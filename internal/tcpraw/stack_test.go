package tcpraw

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"tcpdiag/internal/packetio"
)

func TestHandshakeOverSim(t *testing.T) {
	ipA := netip.MustParseAddr("10.99.0.1")
	ipB := netip.MustParseAddr("10.99.0.2")
	hub := packetio.NewSimHub(1)
	simA, simB := hub.Attach("A", ipA), hub.Attach("B", ipB)
	dmxA, dmxB := NewDemux(simA), NewDemux(simB)

	var sawA, sawB int
	dmxA.RegisterAny(func(s *Segment) { sawA++ })
	dmxB.RegisterAny(func(s *Segment) { sawB++ })

	ca := DefaultConfig()
	ca.LocalIP, ca.RemoteIP = ipA, ipB
	ca.LocalPort, ca.RemotePort = 42426, 42425
	cb := DefaultConfig()
	cb.LocalIP, cb.RemoteIP = ipB, ipA
	cb.LocalPort, cb.RemotePort = 42425, 42426

	done := make(chan error, 1)
	go func() {
		_, err := Listen(dmxB, cb).Accept()
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	connA, err := Dial(dmxA, ca)
	if err != nil {
		pa, ba := dmxA.Stats()
		pb, bb := dmxB.Stats()
		t.Fatalf("dial: %v (A parsed=%d bad=%d, B parsed=%d bad=%d, sawA=%d sawB=%d)", err, pa, ba, pb, bb, sawA, sawB)
	}
	defer connA.Close()
	if err := <-done; err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got := connA.State(); got != StEstablished {
		t.Fatalf("state = %v", got)
	}
}

func TestBulkTransferWithLoss(t *testing.T) {
	ipA := netip.MustParseAddr("10.99.0.1")
	ipB := netip.MustParseAddr("10.99.0.2")
	hub := packetio.NewSimHub(7)
	im, err := packetio.ParseImpairment("loss=2,delay=8ms,jitter=3ms,reorder=1,dup=0.2")
	if err != nil {
		t.Fatal(err)
	}
	simA, simB := hub.Attach("A", ipA), hub.Attach("B", ipB)
	hub.SetLink(ipA, ipB, im)
	hub.SetLink(ipB, ipA, im)
	dmxA, dmxB := NewDemux(simA), NewDemux(simB)

	ca := DefaultConfig()
	ca.LocalIP, ca.RemoteIP = ipA, ipB
	ca.LocalPort, ca.RemotePort = 42426, 42425
	ca.MinRTO = 20 * time.Millisecond
	cb := DefaultConfig()
	cb.LocalIP, cb.RemoteIP = ipB, ipA
	cb.LocalPort, cb.RemotePort = 42425, 42426
	cb.MinRTO = 20 * time.Millisecond

	type res struct {
		c   *Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := Listen(dmxB, cb).Accept()
		ch <- res{c, err}
	}()
	a, err := Dial(dmxA, ca)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	b := r.c

	const total = 256 * 1024
	payload := make([]byte, total)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	go func() {
		_, _ = a.Write(payload)
	}()
	got := make([]byte, 0, total)
	buf := make([]byte, 32*1024)
	deadline := time.Now().Add(20 * time.Second)
	for len(got) < total && time.Now().Before(deadline) {
		n, err := b.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if len(got) != total {
		t.Fatalf("received %d of %d bytes", len(got), total)
	}
	for i := range payload {
		if got[i] != payload[i] {
			t.Fatalf("byte %d: got %d want %d", i, got[i], payload[i])
		}
	}
	sa, sb := a.Snapshot(), b.Snapshot()
	t.Logf("A retrans=%d fast=%d rto=%d spurious=%d dupACKsent=%d", sa.RetransSent, sa.FastRetrans, sa.RtoRetrans, sa.SpuriousRetrans, sa.DupAcksSent)
	t.Logf("B retrans=%d fast=%d rto=%d spurious=%d dupACKsent=%d ooo=%d retransRecv=%d", sb.RetransSent, sb.FastRetrans, sb.RtoRetrans, sb.SpuriousRetrans, sb.DupAcksSent, sb.OooSegs, sb.RetransRecvSegs)
	if sa.RetransSent == 0 {
		t.Errorf("expected some retransmission at 2%% loss")
	}
	if sa.FastRetrans == 0 {
		t.Errorf("expected fast retransmit to fire")
	}
}

// TestHandshakeRecoversLostSynAck guards a real failure mode: if the SYN/ACK is
// lost, the listener must re-send the SYN/ACK. Re-sending a bare SYN (which is
// what an unguarded implementation does) is ignored by a peer in SYN-SENT, and
// the connection can then never come up.
func TestHandshakeRecoversLostSynAck(t *testing.T) {
	ipA := netip.MustParseAddr("10.99.0.1")
	ipB := netip.MustParseAddr("10.99.0.2")
	hub := packetio.NewSimHub(3)
	simA, simB := hub.Attach("A", ipA), hub.Attach("B", ipB)
	hard, err := packetio.ParseImpairment("loss=100")
	if err != nil {
		t.Fatal(err)
	}
	// Silence the B->A direction so the first SYN/ACK is definitely lost.
	hub.SetLink(ipB, ipA, hard)
	dmxA, dmxB := NewDemux(simA), NewDemux(simB)

	ca := DefaultConfig()
	ca.LocalIP, ca.RemoteIP = ipA, ipB
	ca.LocalPort, ca.RemotePort = 42426, 42425
	cb := DefaultConfig()
	cb.LocalIP, cb.RemoteIP = ipB, ipA
	cb.LocalPort, cb.RemotePort = 42425, 42426

	ch := make(chan error, 1)
	go func() {
		_, err := Listen(dmxB, cb).Accept()
		ch <- err
	}()
	time.Sleep(30 * time.Millisecond)
	// Restore the path shortly after the first SYN/ACK would have been dropped.
	go func() {
		time.Sleep(100 * time.Millisecond)
		hub.SetLink(ipB, ipA, nil)
	}()
	connA, err := Dial(dmxA, ca)
	if err != nil {
		t.Fatalf("handshake did not recover from a lost SYN/ACK: %v", err)
	}
	defer connA.Close()
	if err := <-ch; err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got := connA.Snapshot().SynRetrans; got == 0 {
		t.Errorf("expected SYN retransmissions after the dropped SYN/ACK, got %d", got)
	}
}

// The stack must advertise SACK-Permitted in its SYN. If it does not, both ends
// conclude the peer lacks SACK, never send SACK blocks, and recover by
// retransmitting everything from the oldest unacked byte - which shows up as
// spurious retransmissions, the very symptom this tool is meant to diagnose.
func TestHandshakeNegotiatesSACK(t *testing.T) {
	// 1. the option is actually on the wire
	s := &Segment{
		SrcIP: netip.MustParseAddr("10.99.0.1"), DstIP: netip.MustParseAddr("10.99.0.2"),
		SrcPort: 1, DstPort: 2, Seq: 1, Flags: FlagSYN, Window: 1460, TTL: 64,
		Opts: Options{MSS: 1400, HasWinScale: true, WinScale: 7, SACKPermitted: true},
	}
	got, err := Parse(s.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Opts.SACKPermitted {
		t.Fatal("SYN must carry TCP option kind 4 (SACK-Permitted)")
	}

	// 2. two stacks must therefore both believe SACK was negotiated, and the
	//    receiver must actually use SACK blocks under loss.
	ipA := netip.MustParseAddr("10.99.0.1")
	ipB := netip.MustParseAddr("10.99.0.2")
	hub := packetio.NewSimHub(9)
	im, _ := packetio.ParseImpairment("loss=3,delay=6ms,jitter=2ms")
	simA, simB := hub.Attach("A", ipA), hub.Attach("B", ipB)
	hub.SetLink(ipA, ipB, im)
	hub.SetLink(ipB, ipA, im)
	dmxA, dmxB := NewDemux(simA), NewDemux(simB)

	ca := DefaultConfig()
	ca.LocalIP, ca.RemoteIP = ipA, ipB
	ca.LocalPort, ca.RemotePort = 42426, 42425
	ca.MinRTO = 20 * time.Millisecond
	cb := DefaultConfig()
	cb.LocalIP, cb.RemoteIP = ipB, ipA
	cb.LocalPort, cb.RemotePort = 42425, 42426
	cb.MinRTO = 20 * time.Millisecond

	ch := make(chan *Conn, 1)
	go func() { c, _ := Listen(dmxB, cb).Accept(); ch <- c }()
	a, err := Dial(dmxA, ca)
	if err != nil {
		t.Fatal(err)
	}
	b := <-ch

	payload := make([]byte, 128*1024)
	for i := range payload {
		payload[i] = byte(i * 3)
	}
	go func() { _, _ = a.Write(payload) }()
	buf := make([]byte, 32*1024)
	gotBytes := make([]byte, 0, len(payload))
	deadline := time.Now().Add(20 * time.Second)
	for len(gotBytes) < len(payload) && time.Now().Before(deadline) {
		n, err := b.Read(buf)
		if n > 0 {
			gotBytes = append(gotBytes, buf[:n]...)
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if len(gotBytes) != len(payload) {
		t.Fatalf("short transfer: %d/%d", len(gotBytes), len(payload))
	}

	sa, sb := a.Snapshot(), b.Snapshot()
	t.Logf("A: sackBlocksSent=%d notes=%v", sa.SackBlocks, sa.Notes)
	t.Logf("B: sackBlocksSent=%d notes=%v", sb.SackBlocks, sb.Notes)
	// SACK blocks are emitted by the side receiving the data, which is B here.
	if sb.SackBlocks == 0 {
		t.Error("the receiver never sent SACK blocks: SACK negotiation is broken")
	}
	for _, note := range append(sa.Notes, sb.Notes...) {
		if strings.Contains(note, "did NOT negotiate SACK") {
			t.Errorf("SACK negotiation failed: %s", note)
		}
	}
}
