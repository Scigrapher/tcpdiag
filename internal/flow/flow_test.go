package flow

import (
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"

	"tcpdiag/internal/wire"
	"time"
)

// LocalSnapshot starts from an empty snapshot and folds in the transport
// stack's provider. Handshake facts must survive that merge; losing them made
// an established raw connection report that no peer SYN had ever been seen.
func TestLocalSnapshotKeepsProviderHandshakeFields(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	s := New(a, Config{
		LocalID: "local", PeerID: "peer", Stack: "raw",
		Providers: []func(*wire.Snapshot){func(sn *wire.Snapshot) {
			sn.SawPeerSyn = true
			sn.PeerSACK = true
			sn.PeerSynOpts = "MSS=1400, SACK-Permitted"
			sn.State = "ESTABLISHED"
		}},
	})
	snap := s.LocalSnapshot()
	if !snap.SawPeerSyn || !snap.PeerSACK {
		t.Fatalf("handshake flags were dropped: sawSyn=%v sack=%v", snap.SawPeerSyn, snap.PeerSACK)
	}
	if snap.State != "ESTABLISHED" || snap.PeerSynOpts == "" {
		t.Fatalf("handshake metadata was dropped: state=%q opts=%q", snap.State, snap.PeerSynOpts)
	}
}

// memConn is a frame-oriented in-memory pipe: one Write delivers exactly one
// frame, which lets the test drop whole frames the way a lossy link would.
type memConn struct {
	rd     chan []byte
	wr     chan []byte
	buf    []byte
	closed chan struct{}
	once   sync.Once
}

func (m *memConn) Read(p []byte) (int, error) {
	for len(m.buf) == 0 {
		select {
		case b, ok := <-m.rd:
			if !ok {
				return 0, io.EOF
			}
			m.buf = b
		case <-m.closed:
			return 0, io.EOF
		}
	}
	n := copy(p, m.buf)
	m.buf = m.buf[n:]
	return n, nil
}

func (m *memConn) Write(p []byte) (int, error) {
	cp := append([]byte{}, p...)
	select {
	case m.wr <- cp:
		return len(p), nil
	case <-m.closed:
		return 0, io.ErrClosedPipe
	}
}

func (m *memConn) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}

// newPair returns two endpoints with independent per-direction drop rates.
func newPair(dropA, dropB float64) (*memConn, *memConn) {
	a := &memConn{rd: make(chan []byte, 1024), wr: make(chan []byte, 1024), closed: make(chan struct{})}
	b := &memConn{rd: make(chan []byte, 1024), wr: make(chan []byte, 1024), closed: make(chan struct{})}
	// Separate generators per direction: one math/rand.Rand must not be used
	// from two goroutines at once.
	rndA := rand.New(rand.NewSource(11))
	rndB := rand.New(rand.NewSource(12))
	go func() {
		for {
			select {
			case pkt, ok := <-a.wr:
				if !ok {
					return
				}
				if rndA.Float64() < dropA {
					continue
				}
				select {
				case b.rd <- pkt:
				case <-b.closed:
					return
				}
			case <-a.closed:
				return
			}
		}
	}()
	go func() {
		for {
			select {
			case pkt, ok := <-b.wr:
				if !ok {
					return
				}
				if rndB.Float64() < dropB {
					continue
				}
				select {
				case a.rd <- pkt:
				case <-a.closed:
					return
				}
			case <-b.closed:
				return
			}
		}
	}()
	return a, b
}

func cfgFor(local, peer string, dialer bool, seed []byte, total uint64) Config {
	return Config{
		LocalID: local, LocalName: "node-" + local, PeerID: peer, PeerName: "node-" + peer,
		Stack: "test", IsDialer: dialer, BlockSize: 2048, RateMbps: 2,
		TotalBytes: total, Seed: seed, Version: "test",
		Logf: func(string, ...any) {},
	}
}

func TestSessionStreamsBothWays(t *testing.T) {
	seed := []byte("shared-session-seed-0123456789ab")
	ca, cb := newPair(0, 0)
	sa := New(ca, cfgFor("A", "B", true, seed, 32*1024))
	sb := New(cb, cfgFor("B", "A", false, seed, 32*1024))
	errA, errB := make(chan error, 1), make(chan error, 1)
	go func() { errA <- sa.Start() }()
	go func() { errB <- sb.Start() }()
	if err := <-errA; err != nil {
		t.Fatalf("A start: %v", err)
	}
	if err := <-errB; err != nil {
		t.Fatalf("B start: %v", err)
	}
	<-time.After(200 * time.Millisecond)
	sa.Close()
	sb.Close()

	la := sa.LocalSnapshot()
	lb := sb.LocalSnapshot()
	if la.BytesSent < 32*1024 || lb.BytesSent < 32*1024 {
		t.Fatalf("expected both sides to transmit: A=%d B=%d", la.BytesSent, lb.BytesSent)
	}
	if la.ChainMismatch != 0 || lb.ChainMismatch != 0 {
		t.Fatalf("lossless link must not report chain problems: A=%d B=%d", la.ChainMismatch, lb.ChainMismatch)
	}
	if la.BlocksMissing != 0 || lb.BlocksMissing != 0 {
		t.Fatalf("lossless link must not report missing blocks: A=%d B=%d", la.BlocksMissing, lb.BlocksMissing)
	}
}

// TestOneSidedDiagnosis is the core promise of the tool: with only A's view,
// you can see both directions, because B's blocks carry B's telemetry and B's
// payload is cryptographically tied to what B received from A.
func TestOneSidedDiagnosis(t *testing.T) {
	seed := []byte("shared-session-seed-0123456789ab")
	ca, cb := newPair(0.35, 0.35)
	sa := New(ca, cfgFor("A", "B", true, seed, 512*1024))
	sb := New(cb, cfgFor("B", "A", false, seed, 512*1024))
	errA, errB := make(chan error, 1), make(chan error, 1)
	go func() { errA <- sa.Start() }()
	go func() { errB <- sb.Start() }()
	if err := <-errA; err != nil {
		t.Fatalf("A start: %v", err)
	}
	if err := <-errB; err != nil {
		t.Fatalf("B start: %v", err)
	}
	// Poll while both sides are still streaming: B's telemetry rides inside the
	// blocks it sends, so we want one that has matured (B has received from A).
	var peerSnap *wire.Snapshot
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if p, _ := sa.PeerSnapshot(); p != nil && p.BlocksRecv > 0 && p.BlocksSent > 3 {
			peerSnap = p
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	wa, wb := make(chan error, 1), make(chan error, 1)
	go func() { wa <- sa.Wait() }()
	go func() { wb <- sb.Wait() }()
	<-wa
	<-wb
	sa.Close()
	sb.Close()

	la := sa.LocalSnapshot()
	if peerSnap == nil {
		t.Fatal("A must hold the telemetry reported by B")
	}
	if peerSnap.PeerID != "B" {
		t.Fatalf("peer telemetry is not from B: %q", peerSnap.PeerID)
	}
	if peerSnap.BytesSent == 0 {
		t.Fatal("peer telemetry must report what B transmitted")
	}
	if la.BlocksMissing == 0 {
		t.Fatal("with 35% frame loss A must have detected missing blocks")
	}
	// A's view of the return path comes only from B's embedded report.
	if peerSnap.BlocksRecv == 0 {
		t.Fatal("peer must have reported receiving blocks from A")
	}
	if la.ChainMismatch != 0 {
		t.Fatalf("intact frames must still verify: %d mismatches", la.ChainMismatch)
	}
	t.Logf("A saw %d missing blocks; B reported %d blocks sent / %d received",
		la.BlocksMissing, peerSnap.BlocksSent, peerSnap.BlocksRecv)
}
