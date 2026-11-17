package packetio

import (
	"fmt"
	"math/rand"
	"net/netip"
	"sync"
	"time"
)

// Sim is an in-process link emulator. It implements the same Engine interface
// as the privileged capture backends, which buys two things:
//
//   - the custom TCP stack can be exercised end-to-end (including loss,
//     reordering, duplication and rate limits) without administrator rights;
//   - --impair can reproduce the reported symptoms on a healthy network so the
//     detection logic itself can be validated.
type Sim struct {
	name   string
	ip     netip.Addr
	hub    *SimHub
	in     chan *Packet
	closed chan struct{}
	once   sync.Once
}

// SimHub connects Sim endpoints over per-direction impaired links.
type SimHub struct {
	mu      sync.Mutex
	members map[netip.Addr]*Sim
	rng     *rand.Rand
	links   map[[2]netip.Addr]*linkState
	// Stats exposed for the selftest.
	Offered   uint64
	Delivered uint64
	Dropped   uint64
	Duped     uint64
}

type linkState struct {
	mu       sync.Mutex
	im       *Impairment
	nextFree time.Time
	burst    int
}

// NewSimHub creates an empty virtual LAN.
func NewSimHub(seed int64) *SimHub {
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	return &SimHub{
		members: map[netip.Addr]*Sim{},
		rng:     rand.New(rand.NewSource(seed)),
		links:   map[[2]netip.Addr]*linkState{},
	}
}

// Attach creates one endpoint on the virtual LAN.
func (h *SimHub) Attach(name string, ip netip.Addr) *Sim {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := &Sim{name: name, ip: ip, hub: h, in: make(chan *Packet, 4096), closed: make(chan struct{})}
	h.members[ip] = s
	return s
}

// SetLink installs the impairment profile applied to traffic flowing src->dst.
func (h *SimHub) SetLink(src, dst netip.Addr, im *Impairment) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.links[[2]netip.Addr{src, dst}] = &linkState{im: im}
}

func (h *SimHub) link(src, dst netip.Addr) *linkState {
	h.mu.Lock()
	defer h.mu.Unlock()
	k := [2]netip.Addr{src, dst}
	if ls, ok := h.links[k]; ok {
		return ls
	}
	ls := &linkState{}
	h.links[k] = ls
	return ls
}

func (s *Sim) Name() string         { return "sim:" + s.name }
func (s *Sim) LocalIP() netip.Addr  { return s.ip }
func (s *Sim) Recv() <-chan *Packet { return s.in }
func (s *Sim) Injectable() bool     { return true }

func (s *Sim) Capabilities() []string {
	return []string{"in-process link emulator", "deterministic (seeded)", "impairment: loss/delay/jitter/dup/reorder/rate/burst"}
}

func (s *Sim) Close() error {
	s.once.Do(func() {
		close(s.closed)
		h := s.hub
		h.mu.Lock()
		delete(h.members, s.ip)
		h.mu.Unlock()
	})
	return nil
}

// Send hands the packet to the hub, which impairs it and delivers it to the
// destination endpoint (or drops it).
func (s *Sim) Send(ipPacket []byte) error {
	dst, err := DstAddr(ipPacket)
	if err != nil {
		return err
	}
	s.hub.mu.Lock()
	target, ok := s.hub.members[dst]
	s.hub.mu.Unlock()
	if !ok {
		return fmt.Errorf("sim: no route to %s", dst)
	}
	buf := make([]byte, len(ipPacket))
	copy(buf, ipPacket)
	s.hub.deliver(s.ip, dst, target, buf)
	return nil
}

func (h *SimHub) deliver(src, dst netip.Addr, target *Sim, pkt []byte) {
	ls := h.link(src, dst)
	h.mu.Lock()
	rnd := h.rng
	h.Offered++
	h.mu.Unlock()

	im := ls.im
	if im != nil {
		// Gilbert-Elliott style burst loss: once inside an episode, drop the
		// next BurstLen packets outright.
		if ls.burst > 0 {
			ls.burst--
			h.mu.Lock()
			h.Dropped++
			h.mu.Unlock()
			return
		}
		if im.BurstPct > 0 && im.BurstLen > 0 && rnd.Float64()*100 < im.BurstPct {
			ls.burst = im.BurstLen - 1
			h.mu.Lock()
			h.Dropped++
			h.mu.Unlock()
			return
		}
		if im.LossPct > 0 && rnd.Float64()*100 < im.LossPct {
			h.mu.Lock()
			h.Dropped++
			h.mu.Unlock()
			return
		}
	}

	h.mu.Lock()
	h.Delivered++
	h.mu.Unlock()

	// Serialisation delay from the token bucket / rate limit.
	ls.mu.Lock()
	serial := time.Duration(0)
	if im != nil && im.RateMbps > 0 {
		serial = time.Duration(float64(len(pkt)*8) / (im.RateMbps * 1e6) * float64(time.Second))
		now := time.Now()
		if ls.nextFree.Before(now) {
			ls.nextFree = now
		}
		ls.nextFree = ls.nextFree.Add(serial)
		serial = time.Until(ls.nextFree)
	}
	ls.mu.Unlock()

	base := time.Duration(0)
	if im != nil {
		base = im.Delay
		if im.Jitter > 0 {
			base += time.Duration(rnd.Int63n(int64(2*im.Jitter)+1)) - im.Jitter
			if base < 0 {
				base = 0
			}
		}
		if im.ReorderPct > 0 && rnd.Float64()*100 < im.ReorderPct {
			// Late delivery of this packet lets later packets overtake it.
			spacing := im.Delay / 2
			if spacing <= 0 {
				spacing = 200 * time.Microsecond
			}
			base += time.Duration(1+rnd.Int63n(7)) * spacing
		}
	}
	total := base + serial
	if total <= 0 {
		target.enqueue(pkt)
	} else {
		go func(d time.Duration) {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
				target.enqueue(pkt)
			case <-target.closed:
			}
		}(total)
	}

	if im != nil && im.DupPct > 0 && rnd.Float64()*100 < im.DupPct {
		dup := make([]byte, len(pkt))
		copy(dup, pkt)
		h.mu.Lock()
		h.Duped++
		h.mu.Unlock()
		go func(d time.Duration) {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
				target.enqueue(dup)
			case <-target.closed:
			}
		}(total + time.Duration(rnd.Int63n(int64(time.Millisecond))))
	}
}

func (s *Sim) enqueue(pkt []byte) {
	select {
	case s.in <- &Packet{Buf: pkt, At: time.Now(), NanoAt: time.Now().UnixNano()}:
	case <-s.closed:
	default: // ring overflow is itself a signal: count as drop, never block
		s.hub.mu.Lock()
		s.hub.Dropped++
		s.hub.mu.Unlock()
	}
}

// DstAddr extracts the destination IPv4 address from a raw IP packet.
func DstAddr(ipPacket []byte) (netip.Addr, error) {
	if len(ipPacket) < 20 {
		return netip.Addr{}, fmt.Errorf("packetio: short ip packet (%d bytes)", len(ipPacket))
	}
	if ipPacket[0]>>4 != 4 {
		return netip.Addr{}, fmt.Errorf("packetio: not IPv4")
	}
	a, _ := netip.AddrFromSlice(ipPacket[16:20])
	return a, nil
}

// SrcAddr extracts the source IPv4 address from a raw IP packet.
func SrcAddr(ipPacket []byte) (netip.Addr, error) {
	if len(ipPacket) < 20 {
		return netip.Addr{}, fmt.Errorf("packetio: short ip packet (%d bytes)", len(ipPacket))
	}
	a, _ := netip.AddrFromSlice(ipPacket[12:16])
	return a, nil
}
