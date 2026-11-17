package tcpraw

import (
	"net/netip"
	"testing"
	"time"

	"tcpdiag/internal/packetio"
)

// fakeEngine feeds arbitrary bytes straight into the demux, bypassing the link
// simulator's routing so genuinely malformed frames can be tested.
type fakeEngine struct {
	in   chan *packetio.Packet
	done chan struct{}
}

func newFakeEngine() *fakeEngine {
	return &fakeEngine{in: make(chan *packetio.Packet, 64), done: make(chan struct{})}
}

func (f *fakeEngine) push(b []byte) {
	cp := append([]byte{}, b...)
	now := time.Now()
	f.in <- &packetio.Packet{Buf: cp, At: now, NanoAt: now.UnixNano()}
}

func (f *fakeEngine) Name() string                  { return "fake" }
func (f *fakeEngine) Send(ipPacket []byte) error    { return nil }
func (f *fakeEngine) Recv() <-chan *packetio.Packet { return f.in }
func (f *fakeEngine) Close() error                  { return nil }
func (f *fakeEngine) LocalIP() netip.Addr           { return netip.MustParseAddr("10.9.0.2") }
func (f *fakeEngine) Injectable() bool              { return true }
func (f *fakeEngine) Capabilities() []string        { return []string{"test"} }

// The capture loop must survive arbitrary wire traffic. The reported crash came
// from a 14640-byte captured frame with an impossible IP Total Length field -
// the shape produced by NIC receive coalescing - so that exact shape is the
// regression case, and the loop must keep delivering afterwards.
func TestDemuxSurvivesOversizedMalformedFrame(t *testing.T) {
	a := netip.MustParseAddr("10.9.0.1")
	b := netip.MustParseAddr("10.9.0.2")
	eng := newFakeEngine()
	dmx := NewDemux(eng)
	defer dmx.Close()
	dmx.SetControlPorts([]uint16{1000, 2000})
	injected := make(chan *packetio.Packet, 1)
	dmx.RegisterInjected(func(p *packetio.Packet) {
		select {
		case injected <- p:
		default:
		}
	})

	got := make(chan *Segment, 8)
	dmx.Register(Key{A: a, B: b, APort: 1000, BPort: 2000}, func(s *Segment) {
		select {
		case got <- s:
		default:
		}
	})

	// 1. The crasher: 14640 bytes with a zero Total Length field.
	big := make([]byte, 14640)
	big[0] = 4<<4 | 5
	big[2], big[3] = 0, 0
	big[9] = 6
	big[32] = 5 << 4
	copy(big[12:16], a.AsSlice())
	copy(big[16:20], b.AsSlice())
	eng.push(big)

	// 2. Other junk a sniffer really sees.
	eng.push(make([]byte, 64)) // all zeros: version 0
	short := make([]byte, 4)
	eng.push(short)
	frag := make([]byte, 60)
	frag[0] = 4<<4 | 5
	frag[2], frag[3] = 0, 60
	frag[6] = 0x20 // More Fragments
	frag[9] = 6
	copy(frag[12:16], a.AsSlice())
	copy(frag[16:20], b.AsSlice())
	eng.push(frag)

	// 3. A genuine segment must still be delivered afterwards.
	seg := &Segment{
		SrcIP: a, DstIP: b, SrcPort: 1000, DstPort: 2000,
		Seq: 1, Ack: 1, Flags: FlagACK | FlagPSH, Window: 1460, TTL: 64,
		Payload: []byte("still working"),
	}
	eng.push(seg.Marshal())

	select {
	case s := <-got:
		if string(s.Payload) != "still working" {
			t.Fatalf("wrong payload after malformed input: %q", s.Payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("capture loop stopped delivering segments after malformed input")
	}
	parsed, bad := dmx.Stats()
	t.Logf("demux survived: parsed=%d rejected=%d", parsed, bad)
	if bad == 0 {
		t.Error("malformed frames should have been counted as rejected")
	}
	if bigN, maxLen := dmx.Offload(); bigN == 0 || maxLen < 14640 {
		t.Errorf("offload evidence not recorded: big=%d max=%d", bigN, maxLen)
	}

	// The protocol breakdown must count every packet, not just oversized ones:
	// it is how the report answers "is tcpdiag actually seeing my traffic".
	// Sending through the demux must be tallied as well.
	if err := dmx.Send(seg); err != nil {
		t.Fatal(err)
	}
	cap := dmx.Capture()
	if cap.Packets < 5 {
		t.Errorf("packet total too low: %+v", cap)
	}
	if cap.TCP == 0 {
		t.Errorf("no TCP counted although TCP was delivered: %+v", cap)
	}
	if cap.Bytes == 0 {
		t.Errorf("byte total is zero: %+v", cap)
	}
	if cap.Injected == 0 {
		t.Error("injected packet count should be tracked")
	}
	if cap.DiagTCP == 0 {
		t.Error("tcpdiag-flow TCP count should include the segment on our own ports")
	}
	select {
	case p := <-injected:
		if len(p.Buf) == 0 || p.NanoAt == 0 {
			t.Errorf("injected hook got an empty packet: %+v", p)
		}
	case <-time.After(time.Second):
		t.Fatal("injected hook did not receive the transmitted segment")
	}
	t.Logf("capture: %d pkts / %d bytes, tcp=%d diag_tcp=%d udp=%d icmp=%d other=%d",
		cap.Packets, cap.Bytes, cap.TCP, cap.DiagTCP, cap.UDP, cap.ICMP, cap.Other)
}
