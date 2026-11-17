package packetio

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Packet is one IPv4 packet, L2 header already stripped by the backend.
type Packet struct {
	Buf    []byte
	At     time.Time
	NanoAt int64
}

// Options configures an Engine.
type Options struct {
	Backend    string // auto | windows | linux | sim | auto-fallback
	LocalIP    netip.Addr
	IfaceName  string
	Sim        *Sim // required for the sim backend
	MatchPorts []uint16
	MatchProto uint8 // 6 == TCP, 0 == any
	RingBuffer int
	AdminHint  bool
}

// Engine is a layer-3 packet engine: it delivers IPv4 packets to the local
// stack and injects locally-built IPv4 packets onto the wire.
type Engine interface {
	Name() string
	Send(ipPacket []byte) error
	Recv() <-chan *Packet
	Close() error
	LocalIP() netip.Addr
	// Injectable reports whether Send can actually put a locally-built IPv4
	// packet on the wire. Capture-only engines return false.
	Injectable() bool
	// Capabilities describes what this backend can actually do, so the UI can
	// tell the user why a raw run degrades to observation only.
	Capabilities() []string
}

// ErrNoRawBackend is returned when no privileged capture/inject path exists.
var ErrNoRawBackend = errors.New("tcpdiag: no raw packet backend available")

// ---------------------------------------------------------------------------
// Impairment: inject synthetic loss/delay/duplication/reordering so a healthy
// lab network can reproduce the symptoms under test.
// ---------------------------------------------------------------------------

type Impairment struct {
	LossPct    float64       // independent drop probability per packet
	DupPct     float64       // duplicate probability
	ReorderPct float64       // probability a packet is delivered out of order
	Delay      time.Duration // baseline one-way delay
	Jitter     time.Duration // +- uniform jitter
	BurstLen   int           // loss occurs in bursts of N (0 == memoryless)
	BurstPct   float64       // probability of entering a burst episode
	RateMbps   float64       // token bucket pacing (0 == unlimited)
	DropSeqs   []uint64      // explicit sequence numbers to always drop
	Note       string
}

func (im *Impairment) Enabled() bool {
	if im == nil {
		return false
	}
	return im.LossPct > 0 || im.DupPct > 0 || im.ReorderPct > 0 ||
		im.Delay > 0 || im.Jitter > 0 || im.RateMbps > 0 || im.BurstPct > 0 || len(im.DropSeqs) > 0
}

func (im *Impairment) String() string {
	if !im.Enabled() {
		return "none"
	}
	parts := []string{}
	if im.LossPct > 0 {
		parts = append(parts, fmt.Sprintf("loss=%.2f%%", im.LossPct))
	}
	if im.DupPct > 0 {
		parts = append(parts, fmt.Sprintf("dup=%.2f%%", im.DupPct))
	}
	if im.ReorderPct > 0 {
		parts = append(parts, fmt.Sprintf("reorder=%.2f%%", im.ReorderPct))
	}
	if im.Delay > 0 {
		parts = append(parts, "delay="+im.Delay.String())
	}
	if im.Jitter > 0 {
		parts = append(parts, "jitter="+im.Jitter.String())
	}
	if im.BurstPct > 0 {
		parts = append(parts, fmt.Sprintf("burst=%.2f%%x%d", im.BurstPct, im.BurstLen))
	}
	if im.RateMbps > 0 {
		parts = append(parts, fmt.Sprintf("rate=%.1fMbps", im.RateMbps))
	}
	return strings.Join(parts, ",")
}

// ParseImpairment parses "loss=1.5,delay=12ms,jitter=4ms,dup=0.5,reorder=1,rate=100,burst=3@20".
func ParseImpairment(spec string) (*Impairment, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, nil
	}
	im := &Impairment{Note: spec}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		k, v, ok := strings.Cut(tok, "=")
		if !ok {
			return nil, fmt.Errorf("impairment: expected key=value, got %q", tok)
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		switch k {
		case "loss", "dup", "reorder":
			f, err := parsePct(v)
			if err != nil {
				return nil, err
			}
			switch k {
			case "loss":
				im.LossPct = f
			case "dup":
				im.DupPct = f
			case "reorder":
				im.ReorderPct = f
			}
		case "delay", "jitter":
			d, err := time.ParseDuration(v)
			if err != nil {
				return nil, fmt.Errorf("impairment %s: %w", k, err)
			}
			if k == "delay" {
				im.Delay = d
			} else {
				im.Jitter = d
			}
		case "rate":
			f, err := strconv.ParseFloat(strings.TrimSuffix(strings.ToLower(v), "mbps"), 64)
			if err != nil {
				return nil, fmt.Errorf("impairment rate: %w", err)
			}
			im.RateMbps = f
		case "burst":
			// "3@20" => bursts of 3 packets entered at 20% of episodes
			n, pct, ok := strings.Cut(v, "@")
			if !ok {
				return nil, fmt.Errorf("impairment burst: want N@PCT, got %q", v)
			}
			nv, err := strconv.Atoi(n)
			if err != nil {
				return nil, fmt.Errorf("impairment burst: %w", err)
			}
			pf, err := parsePct(pct)
			if err != nil {
				return nil, err
			}
			im.BurstLen, im.BurstPct = nv, pf
		default:
			return nil, fmt.Errorf("impairment: unknown key %q", k)
		}
	}
	if im.BurstLen > 0 && im.BurstPct == 0 {
		im.BurstPct = 100
	}
	return im, nil
}

func parsePct(v string) (float64, error) {
	v = strings.TrimSuffix(strings.TrimSpace(v), "%")
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("impairment: bad percentage %q", v)
	}
	if f < 0 || f > 100 {
		return 0, fmt.Errorf("impairment: percentage out of range: %q", v)
	}
	return f, nil
}

// ---------------------------------------------------------------------------
// Link-layer normalisation
// ---------------------------------------------------------------------------
//
// Capture sources disagree about whether the link-layer header is included.
// AF_PACKET hands over the whole frame; SIO_RCVALL normally hands over a bare
// IP packet; some Windows filter and virtual adapters hand over Ethernet
// framed data anyway. Everything downstream assumes pk.Buf is a bare IP packet,
// and the pcap link type (DLT_RAW) is only correct if that is true - when it is
// not, Wireshark reads 0xff as the IP version and the traffic is dissected as
// nonsense. Normalising here makes that class of bug impossible.

// Ethernet header length.
const ethHeaderLen = 14

const (
	etypeIPv4 = 0x0800
	etypeIPv6 = 0x86dd
	etypeARP  = 0x0806
)

// IsIPv4 reports whether b begins with an IPv4 header.
func IsIPv4(b []byte) bool {
	return len(b) >= 20 && b[0]>>4 == 4 && b[0]&0x0f >= 5
}

// IsIPv6 reports whether b begins with an IPv6 header.
func IsIPv6(b []byte) bool {
	return len(b) >= 40 && b[0]>>4 == 6
}

// IsIP reports whether b already begins with an IP header.
func IsIP(b []byte) bool { return IsIPv4(b) || IsIPv6(b) }

// StripL2 removes an Ethernet header when one is present. It returns the
// network-layer payload, whether a link header was removed, and the ethertype.
// Non-IP frames (ARP and friends) are reported with their ethertype so callers
// can drop them.
func StripL2(b []byte) (payload []byte, hadL2 bool, ethertype uint16) {
	if IsIP(b) {
		return b, false, 0
	}
	if len(b) < ethHeaderLen+1 {
		return b, false, 0
	}
	et := uint16(b[12])<<8 | uint16(b[13])
	switch et {
	case etypeIPv4, etypeIPv6, etypeARP:
		return b[ethHeaderLen:], true, et
	}
	return b, false, 0
}
