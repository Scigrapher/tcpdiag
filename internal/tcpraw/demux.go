package tcpraw

import (
	"fmt"
	"net/netip"
	"sync"
	"time"

	"tcpdiag/internal/packetio"
	"tcpdiag/internal/wire"
)

// Key identifies a TCP conversation, direction-insensitive.
type Key struct {
	A, B         netip.Addr
	APort, BPort uint16
}

func (k Key) String() string {
	return fmt.Sprintf("%s:%d<->%s:%d", k.A, k.APort, k.B, k.BPort)
}

func keyOf(s *Segment) Key {
	return Key{A: s.SrcIP, B: s.DstIP, APort: s.SrcPort, BPort: s.DstPort}
}

func invert(k Key) Key { return Key{A: k.B, B: k.A, APort: k.BPort, BPort: k.APort} }

func (k Key) matches(s *Segment) bool {
	k2 := keyOf(s)
	return k2 == k || invert(k2) == k
}

// Demux owns one packet engine and fans received traffic out to handlers. This
// is what lets a single capture socket simultaneously drive the user-space
// stack and passively observe a kernel-stack connection on the same host.
type Demux struct {
	eng         packetio.Engine
	mu          sync.RWMutex
	handlers    map[Key][]func(*Segment)
	any         []func(*Segment)
	rawh        []func(*packetio.Packet)
	txh         []func(*packetio.Packet)
	ctlPorts    map[uint16]bool
	parsed      uint64
	bad         uint64
	seen        uint64
	controlPkts uint64
	tcpPkts     uint64
	udpPkts     uint64
	diagTCP     uint64
	diagUDP     uint64
	icmpPkts    uint64
	otherPkts   uint64
	bytes       uint64
	injected    uint64
	txBytes     uint64
	bigPkts     uint64
	maxPktLen   int
	closed      chan struct{}
	once        sync.Once
}

func NewDemux(eng packetio.Engine) *Demux {
	d := &Demux{
		eng:      eng,
		handlers: map[Key][]func(*Segment){},
		ctlPorts: map[uint16]bool{},
		closed:   make(chan struct{}),
	}
	go d.loop()
	return d
}

func (d *Demux) Engine() packetio.Engine { return d.eng }

func (d *Demux) loop() {
	for {
		select {
		case <-d.closed:
			return
		case p, ok := <-d.eng.Recv():
			if !ok {
				return
			}
			d.observe(p)
			d.dispatchRaw(p)
			seg, err := Parse(p.Buf)
			if err != nil {
				d.mu.Lock()
				d.bad++
				d.mu.Unlock()
				continue
			}
			seg.ReceivedAt = p.NanoAt
			d.mu.Lock()
			d.parsed++
			d.mu.Unlock()
			k := keyOf(seg)
			d.mu.RLock()
			hs := append([]func(*Segment){}, d.handlers[k]...)
			hs = append(hs, d.handlers[invert(k)]...)
			any := append([]func(*Segment){}, d.any...)
			d.mu.RUnlock()
			for _, h := range hs {
				h(seg)
			}
			for _, h := range any {
				h(seg)
			}
		}
	}
}

// observe tallies the capture: totals, a per-protocol breakdown and evidence of
// oversized (offload-coalesced) packets. This is what lets the report answer
// "is tcpdiag actually seeing my traffic?" without the user opening Wireshark.
func (d *Demux) observe(p *packetio.Packet) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen++
	d.bytes += uint64(len(p.Buf))
	if len(p.Buf) > d.maxPktLen {
		d.maxPktLen = len(p.Buf)
	}
	if len(p.Buf) > 2000 {
		d.bigPkts++
	}
	if len(p.Buf) < 20 {
		d.otherPkts++
		return
	}
	var ports [2]uint16
	havePorts := false
	switch p.Buf[9] {
	case 6:
		d.tcpPkts++
		ports, havePorts = l4Ports(p.Buf), true
	case 17:
		d.udpPkts++
		ports, havePorts = l4Ports(p.Buf), true
	case 1:
		d.icmpPkts++
	default:
		d.otherPkts++
	}
	// Beacons and probe packets from tcpdiag itself land on ports it owns.
	// Counting them as user traffic is what makes a capture look like
	// "everything is UDP" when it is only the control plane.
	if havePorts && (d.ctlPorts[ports[0]] || d.ctlPorts[ports[1]]) {
		d.controlPkts++
		switch p.Buf[9] {
		case 6:
			d.diagTCP++
		case 17:
			d.diagUDP++
		}
	}
}

// l4Ports extracts source and destination ports from a bare IPv4 TCP/UDP packet.
func l4Ports(b []byte) [2]uint16 {
	var out [2]uint16
	if len(b) < 20 {
		return out
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl+4 > len(b) {
		return out
	}
	out[0] = uint16(b[ihl])<<8 | uint16(b[ihl+1])
	out[1] = uint16(b[ihl+2])<<8 | uint16(b[ihl+3])
	return out
}

// SetControlPorts marks the ports tcpdiag uses itself, so its beacons and probe
// packets are reported separately from the traffic under test.
func (d *Demux) SetControlPorts(ports []uint16) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ctlPorts = map[uint16]bool{}
	for _, p := range ports {
		if p != 0 {
			d.ctlPorts[p] = true
		}
	}
}

func (d *Demux) dispatchRaw(p *packetio.Packet) {
	d.mu.RLock()
	rh := append([]func(*packetio.Packet){}, d.rawh...)
	d.mu.RUnlock()
	for _, fn := range rh {
		fn(p)
	}
}

// Register installs a handler for one conversation (either direction).
func (d *Demux) Register(k Key, h func(*Segment)) {
	d.mu.Lock()
	d.handlers[k] = append(d.handlers[k], h)
	d.mu.Unlock()
}

// RegisterAny installs a handler invoked for every TCP segment.
func (d *Demux) RegisterAny(h func(*Segment)) {
	d.mu.Lock()
	d.any = append(d.any, h)
	d.mu.Unlock()
}

// RegisterPackets receives every raw packet, including non-TCP ones such as
// the ICMP time-exceeded replies used by the TTL walk.
func (d *Demux) RegisterPackets(fn func(*packetio.Packet)) {
	d.mu.Lock()
	d.rawh = append(d.rawh, fn)
	d.mu.Unlock()
}

// RegisterInjected receives every packet tcpdiag transmits with this demux.
// Platform capture paths differ in whether they show locally injected raw
// packets; this hook gives the pcap writer a path-independent view.
func (d *Demux) RegisterInjected(fn func(*packetio.Packet)) {
	d.mu.Lock()
	d.txh = append(d.txh, fn)
	d.mu.Unlock()
}

func (d *Demux) Send(seg *Segment) error {
	p := seg.Marshal()
	at := time.Now()
	if err := d.eng.Send(p); err != nil {
		return err
	}
	d.mu.Lock()
	d.injected++
	d.txBytes += uint64(len(p))
	hs := append([]func(*packetio.Packet){}, d.txh...)
	d.mu.Unlock()
	if len(hs) > 0 {
		pk := &packetio.Packet{Buf: p, At: at, NanoAt: at.UnixNano()}
		for _, h := range hs {
			h(pk)
		}
	}
	return nil
}

func (d *Demux) Capture() wire.Capture {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return wire.Capture{
		Packets: d.seen, Bytes: d.bytes, TCP: d.tcpPkts, UDP: d.udpPkts,
		DiagTCP: d.diagTCP, DiagUDP: d.diagUDP,
		ICMP: d.icmpPkts, Other: d.otherPkts, Oversized: d.bigPkts,
		MaxBytes: d.maxPktLen, Injected: d.injected, TxBytes: d.txBytes, Control: d.controlPkts,
		Engine: d.eng.Name(),
	}
}

func (d *Demux) Stats() (parsed, bad uint64) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.parsed, d.bad
}

// Offload reports how many captured packets were far larger than a single
// MTU. That is the signature of NIC receive segment coalescing (RSC/LRO/GRO),
// which is a frequent cause of bogus Dup-ACK and Spurious-Retransmission
// annotations: the offload merges segments and the analyser sees byte ranges it
// believes were already delivered.
// Seen reports how many packets the capture loop has handled, including
// frames that could not be parsed.
func (d *Demux) Seen() uint64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.seen
}

func (d *Demux) Offload() (bigPackets uint64, maxLen int) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.bigPkts, d.maxPktLen
}

func (d *Demux) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}
