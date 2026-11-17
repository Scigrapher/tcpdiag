package probe

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"tcpdiag/internal/packetio"
	"tcpdiag/internal/tcpraw"
)

// Hop is one TTL step of the walk.
type Hop struct {
	TTL     int     `json:"ttl"`
	Router  string  `json:"router,omitempty"`
	Sent    int     `json:"sent"`
	Replied int     `json:"replied"`
	LossPct float64 `json:"loss_pct"`
	MeanMs  float64 `json:"mean_ms"`
	Reached bool    `json:"reached,omitempty"`
	Note    string  `json:"note,omitempty"`
}

// TTLWalk sends TCP SYNs with increasing TTL and records which router answers,
// and - critically - at which hop the loss begins. When a LAN has dup-ACK
// storms, the answer is usually "the access point" or "the first switch", and
// this localises it without a second capture point.
//
// It requires a raw packet engine, because ICMP time-exceeded replies are not
// delivered to ordinary sockets.
func TTLWalk(dmx *tcpraw.Demux, srcIP netip.Addr, dst netip.Addr, dstPort uint16, maxTTL, probes int) ([]Hop, string) {
	if dmx == nil {
		return nil, "TTL walk needs a raw packet engine (--stack=raw)"
	}
	type hit struct {
		at    time.Time
		from  netip.Addr
		rst   bool
		synak bool
	}
	var mu sync.Mutex
	hits := map[int][]hit{}
	targetID := uint16(0xC0DE)

	dmx.RegisterPackets(func(p *packetio.Packet) {
		pkt := p.Buf
		if len(pkt) < 28 || pkt[9] != 1 {
			return
		}
		icmpType := pkt[20]
		if icmpType != 11 {
			return
		}
		// ICMP payload begins at 20+8; the original IP header is at +8.
		if len(pkt) < 20+8+20 {
			return
		}
		inner := pkt[20+8:]
		if inner[9] != 6 {
			return
		}
		innerID := binary.BigEndian.Uint16(inner[4:6])
		if innerID != targetID {
			return
		}
		src, ok := netip.AddrFromSlice(pkt[12:16])
		if !ok {
			return
		}
		ttl := int(inner[8])
		mu.Lock()
		hits[ttl] = append(hits[ttl], hit{at: time.Unix(0, p.NanoAt), from: src})
		mu.Unlock()
	})

	var out []Hop
	for ttl := 1; ttl <= maxTTL; ttl++ {
		h := Hop{TTL: ttl, Sent: probes}
		sport := uint16(40000 + ttl)
		for i := 0; i < probes; i++ {
			seg := &tcpraw.Segment{
				SrcIP: srcIP, DstIP: dst, SrcPort: sport, DstPort: dstPort,
				Seq:    uint32(time.Now().UnixNano() & 0xffffff),
				Flags:  tcpraw.FlagSYN,
				Window: 1460,
				TTL:    uint8(ttl),
				IPID:   targetID,
			}
			if err := dmx.Engine().Send(seg.Marshal()); err != nil {
				h.Note = err.Error()
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		deadline := time.Now().Add(1200 * time.Millisecond)
		for time.Now().Before(deadline) {
			mu.Lock()
			n := len(hits[ttl])
			mu.Unlock()
			if n >= probes {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		mu.Lock()
		hs := hits[ttl]
		mu.Unlock()
		h.Replied = len(hs)
		if len(hs) > 0 {
			h.Router = hs[0].from.String()
			var sum float64
			for _, x := range hs {
				sum += float64(x.at.UnixNano())
			}
			h.MeanMs = float64(sum/float64(len(hs))) / 1e6
		}
		h.LossPct = 100 * float64(probes-len(hs)) / float64(probes)
		out = append(out, h)
		if len(hs) > 0 && hs[0].from == dst {
			h.Reached = true
			break
		}
		// If the destination answered with SYN/ACK or RST we are done.
		mu.Lock()
		var got bool
		for _, x := range hits[ttl] {
			if x.rst || x.synak {
				got = true
			}
		}
		mu.Unlock()
		if got {
			h.Reached = true
			break
		}
		if len(hs) == 0 && ttl > 6 {
			h.Note = "no response at this TTL; stopping the walk"
			break
		}
	}
	note := ""
	for _, h := range out {
		if h.LossPct > 20 {
			note = fmt.Sprintf("first lossy hop: TTL %d (%s) dropped %.0f%% of probes", h.TTL, h.Router, h.LossPct)
			break
		}
	}
	if note == "" && len(out) > 0 {
		note = fmt.Sprintf("walked %d hop(s), no hop lost more than 20%% of probes", len(out))
	}
	return out, note
}
