package flow

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"tcpdiag/internal/stats"
	"tcpdiag/internal/wire"
)

// Pipe is the transport a Session runs on: a kernel TCP connection, a raw
// user-space TCP connection, or anything else with a reliable byte stream.
type Pipe interface {
	io.Reader
	io.Writer
	io.Closer
}

type Config struct {
	SessionID  string
	LocalID    string
	LocalName  string
	PeerID     string
	PeerName   string
	Stack      string
	IsDialer   bool
	BlockSize  int
	RateMbps   float64
	TotalBytes uint64
	Duration   time.Duration
	Seed       []byte
	Version    string
	OSName     string
	Arch       string
	Iface      string
	Features   []string
	PayloadFor func(blockSeq uint64, n int, recvDigest [wire.DigestSize]byte) []byte
	Logf       func(string, ...any)
	// Providers contribute stack-specific counters to the snapshot that rides
	// inside every outbound block.
	Providers []func(*wire.Snapshot)
}

type Session struct {
	cfg  Config
	pipe Pipe
	br   *bufio.Reader

	mu            sync.Mutex
	sentChain     [wire.DigestSize]byte
	recvChain     [wire.DigestSize]byte
	blockSeq      uint64
	streamOffset  uint64
	rxBlocks      uint64
	rxBytes       uint64
	expectNext    uint64
	low           uint64
	high          uint64
	haveLow       bool
	haveHigh      bool
	recv          map[uint64]bool
	chainOf       map[uint64][wire.DigestSize]byte
	lateCount     uint64
	haveExpect    bool
	peerSnap      *wire.Snapshot
	peerSnapAt    time.Time
	peerSnapCount uint64
	lastPeerData  time.Time
	started       time.Time
	err           error
	handshook     bool
	helloRep      []byte
	pending       []*wire.Frame

	Counters *stats.Counters
	AppHist  *stats.Histogram
	Gaps     *stats.GapRing
	TxMeter  *stats.Meter
	RxMeter  *stats.Meter

	sendWake chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	finished chan struct{}
	sendDone chan struct{}

	sentBytes   atomic.Uint64
	recvBytes   atomic.Uint64
	chainBad    atomic.Uint64
	dupBlocks   atomic.Uint64
	lateBlocks  atomic.Uint64
	oooBlocks   atomic.Uint64
	pingSeq     atomic.Uint64
	pingPending atomic.Uint64
	pingBestNS  atomic.Uint64
	pingLastNS  atomic.Uint64
	pingCount   atomic.Uint64
}

var ErrNoSeed = errors.New("flow: no session seed")

func New(pipe Pipe, cfg Config) *Session {
	if cfg.BlockSize <= 0 {
		cfg.BlockSize = 16384
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	s := &Session{
		cfg:      cfg,
		pipe:     pipe,
		br:       bufio.NewReaderSize(pipe, 256*1024),
		Counters: &stats.Counters{},
		AppHist:  stats.NewHistogram(),
		Gaps:     stats.NewGapRing(128, 128),

		TxMeter:  stats.NewMeter(),
		RxMeter:  stats.NewMeter(),
		sendWake: make(chan struct{}, 1),
		done:     make(chan struct{}),
		finished: make(chan struct{}),
		sendDone: make(chan struct{}),
		recv:     map[uint64]bool{},
		chainOf:  map[uint64][wire.DigestSize]byte{},
	}
	s.pingBestNS.Store(1 << 62)
	if len(cfg.Seed) == 0 {
		s.cfg.Seed = make([]byte, 32)
		for i := range s.cfg.Seed {
			s.cfg.Seed[i] = byte(time.Now().UnixNano() >> (i % 8 * 8))
		}
	}
	return s
}

// Start performs the handshake then runs the continuous send and receive loops.
func (s *Session) Start() error {
	if err := s.handshake(); err != nil {
		return err
	}
	go s.recvLoop()
	go s.sendLoop()
	go s.pingLoop()
	return nil
}

func (s *Session) handshake() error {
	hs := wire.Handshake{
		Protocol:  "tcpdiag/1",
		PeerID:    s.cfg.LocalID,
		PeerName:  s.cfg.LocalName,
		Stack:     s.cfg.Stack,
		Role:      "listen",
		SeedHex:   hex.EncodeToString(s.cfg.Seed),
		BlockSize: s.cfg.BlockSize,
		Version:   s.cfg.Version,
		OS:        s.cfg.OSName,
		Arch:      s.cfg.Arch,
		Iface:     s.cfg.Iface,
		Features:  s.cfg.Features,
		StartNS:   time.Now().UnixNano(),
	}
	if s.cfg.IsDialer {
		hs.Role = "dial"
	}
	rep, _ := json.Marshal(hs)
	s.mu.Lock()
	s.helloRep = rep
	s.mu.Unlock()
	ourHello := &wire.Frame{H: wire.Header{Type: wire.MsgHandshake}, Report: rep}
	ourHelloAck := &wire.Frame{H: wire.Header{Type: wire.MsgHandshakeA}, Report: rep}

	var peerSeen, ackSeen atomic.Bool
	stop := make(chan struct{})
	defer close(stop)
	// Both the hello and its ack can be lost on a bad link. Re-send whichever is
	// outstanding until the exchange completes; otherwise one dropped frame
	// strands the peer, which waits for a hello we think we already sent.
	go func() {
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				// Keep the hello in flight until it has actually been
				// acknowledged: hearing *from* the peer is not proof the peer
				// received us, and stopping here deadlocks both ends.
				if !ackSeen.Load() {
					_ = wire.WriteFrame(s.pipe, ourHello)
				}
				if peerSeen.Load() && !ackSeen.Load() {
					_ = wire.WriteFrame(s.pipe, ourHelloAck)
				}
			}
		}
	}()
	_ = wire.WriteFrame(s.pipe, ourHello)

	watchdog := time.AfterFunc(20*time.Second, func() { _ = s.pipe.Close() })
	defer watchdog.Stop()
	deadline := time.Now().Add(20 * time.Second)

	for !(peerSeen.Load() && ackSeen.Load()) {
		if time.Now().After(deadline) {
			return errors.New("flow: handshake timed out")
		}
		f, err := wire.ReadFrame(s.br)
		if err != nil {
			return fmt.Errorf("handshake read: %w", err)
		}
		switch f.H.Type {
		case wire.MsgHandshake:
			var ph wire.Handshake
			if err := json.Unmarshal(f.Report, &ph); err != nil {
				return fmt.Errorf("handshake decode: %w", err)
			}
			if !s.cfg.IsDialer {
				// The dialer owns the session seed so both ends generate
				// identical keystreams; the listener adopts what it is given.
				seed, err := hex.DecodeString(ph.SeedHex)
				if err != nil || len(seed) == 0 {
					return ErrNoSeed
				}
				s.cfg.Seed = seed
			}
			s.cfg.PeerID = ph.PeerID
			s.cfg.PeerName = ph.PeerName
			s.mu.Lock()
			s.handshook = true
			s.started = time.Now()
			s.mu.Unlock()
			if !peerSeen.Load() {
				s.cfg.Logf("handshook with %s (%s, stack=%s)", ph.PeerName, ph.PeerID, ph.Stack)
			}
			peerSeen.Store(true)
			_ = wire.WriteFrame(s.pipe, ourHelloAck)
		case wire.MsgHandshakeA:
			ackSeen.Store(true)
		default:
			// Data that arrived while we were still handshaking must not be
			// thrown away: the peer may have finished its handshake first and
			// started streaming immediately.
			s.mu.Lock()
			if len(s.pending) < 4096 {
				s.pending = append(s.pending, f)
			}
			s.mu.Unlock()
		}
	}
	return nil
}

func (s *Session) recvLoop() {
	defer close(s.finished)
	for {
		select {
		case <-s.done:
			return
		default:
		}
		var f *wire.Frame
		s.mu.Lock()
		if len(s.pending) > 0 {
			f, s.pending = s.pending[0], s.pending[1:]
		}
		s.mu.Unlock()
		if f == nil {
			var err error
			f, err = wire.ReadFrame(s.br)
			if err != nil {
				s.mu.Lock()
				if s.err == nil {
					s.err = err
				}
				s.mu.Unlock()
				return
			}
		}
		switch f.H.Type {
		case wire.MsgData:
			s.absorbData(f)
		case wire.MsgPong:
			rtt := uint64(time.Now().UnixNano() - int64(f.H.BlockSeq))
			s.pingPending.Store(0)
			s.pingCount.Add(1)
			s.pingLastNS.Store(rtt)
			if rtt < s.pingBestNS.Load() {
				s.pingBestNS.Store(rtt)
			}
			s.AppHist.Observe(float64(rtt) / 1e6)
		case wire.MsgPing:
			_ = wire.WriteFrame(s.pipe, &wire.Frame{H: wire.Header{Type: wire.MsgPong, BlockSeq: f.H.BlockSeq}})
		case wire.MsgHandshake:
			// Stateless rule: always answer a hello with our hello-ack, even
			// long after our own handshake finished. Without this, a peer that
			// completed first would never learn that our ack was lost.
			s.mu.Lock()
			rep := s.helloRep
			s.mu.Unlock()
			_ = wire.WriteFrame(s.pipe, &wire.Frame{H: wire.Header{Type: wire.MsgHandshakeA}, Report: rep})
		case wire.MsgHandshakeA:
			// late ack; already complete
		case wire.MsgGoodbye:
			s.cfg.Logf("peer said goodbye")
			return
		}
	}
}

func (s *Session) absorbData(f *wire.Frame) {
	now := time.Now()
	seq := f.H.BlockSeq

	s.mu.Lock()
	s.lastPeerData = now
	// Block numbering always starts at zero, so the low-water mark starts at
	// zero too. Seeding it from the first block received would make the loss of
	// the very first blocks invisible.
	low := s.low
	var dup, late, gapOpen bool
	var gapFrom, gapTo uint64
	switch {
	case seq < low:
		// Already accounted for: the same block reached us twice.
		dup = true
	case seq == low:
		s.recv[seq] = true
	default: // seq > low: it is above the low-water mark
		if s.recv[seq] {
			dup = true
		} else {
			s.recv[seq] = true
			if s.haveHigh && seq <= s.high {
				// An interior hole got filled without the sender having to
				// say anything: the packet was reordered or duplicated on the
				// path, not lost.
				late = true
			}
			if !s.haveHigh {
				s.haveHigh = true
				s.high = seq
				if seq > 0 {
					// The blocks before the first one we ever saw are gone too.
					gapOpen, gapFrom, gapTo = true, 0, seq
				}
			} else if seq > s.high {
				if seq > s.high+1 {
					gapOpen, gapFrom, gapTo = true, s.high+1, seq
				}
				s.high = seq
			}
		}
	}
	newLow := low
	for s.recv[newLow] {
		delete(s.recv, newLow)
		newLow++
	}
	if newLow != low {
		s.low = newLow
		s.expectNext = newLow
	}
	// Chain verification uses the block's predecessor, so it stays valid even
	// when blocks arrive out of order.
	var chainWant [wire.DigestSize]byte
	haveWant := true
	if seq == 0 {
		chainWant = [wire.DigestSize]byte{}
	} else if v, ok := s.chainOf[seq-1]; ok {
		chainWant = v
	} else {
		haveWant = false
	}
	s.mu.Unlock()

	if dup {
		s.dupBlocks.Add(1)
		s.Counters.BlocksDup.Add(1)
		return
	}
	if late {
		s.lateBlocks.Add(1)
		s.Counters.BlocksLate.Add(1)
	}
	if gapOpen {
		s.oooBlocks.Add(1)
		s.Counters.BlocksOOO.Add(1)
		s.Counters.BlocksMissing.Add(gapTo - gapFrom)
		s.Gaps.Open(gapFrom, gapTo)
		s.cfg.Logf("gap: blocks %d..%d missing (peer high-water %d)", gapFrom, gapTo, s.high)
	}
	if newLow != low {
		src := "in_order"
		if late {
			src = "late_arrival"
		}
		s.Gaps.FillBelow(newLow, src)
	}

	// The causal chain can only be checked where we actually hold the
	// predecessor. After a hole we cannot verify continuity (that is the point
	// of the chain), so rather than comparing against a value we never derived
	// - which would report every subsequent block as corrupt - the first block
	// after a hole re-anchors the chain from its own claimed predecessor digest.
	// Verification then resumes and still catches any later skip or replay.
	check := haveWant
	if !haveWant && seq != 0 {
		chainWant = f.H.PrevSentDigest
	}
	if check && f.H.PrevSentDigest != chainWant {
		s.chainBad.Add(1)
		s.Counters.ChainMismatch.Add(1)
		s.cfg.Logf("chain mismatch at block %d: sender skipped or replayed blocks", seq)
	}

	// Payload verification: the keystream is derived from the sender's
	// receive-chain head, so a correct payload is cryptographic proof that what
	// the sender believed it had received really did arrive.
	if !s.payloadMatches(f) {
		s.chainBad.Add(1)
		s.Counters.ChainMismatch.Add(1)
		s.cfg.Logf("payload mismatch at block %d (corruption or replay)", seq)
	}

	s.mu.Lock()
	s.chainOf[seq] = wire.ChainNext(chainWant, seq, f.Payload)
	s.rxBlocks++
	s.rxBytes += uint64(len(f.Payload))
	s.mu.Unlock()

	s.recvBytes.Add(uint64(len(f.Payload)))
	s.RxMeter.Add(len(f.Payload))
	s.Counters.BlocksRecv.Add(1)
	s.Counters.BytesRecv.Add(uint64(len(f.Payload)))

	if len(f.Report) > 0 {
		var snap wire.Snapshot
		if err := json.Unmarshal(f.Report, &snap); err == nil {
			s.mu.Lock()
			s.peerSnap = &snap
			s.peerSnapAt = now
			s.peerSnapCount++
			s.mu.Unlock()
		}
	}
}

func (s *Session) rxBlocksAdd(n uint64) {
	s.mu.Lock()
	s.rxBlocks += n
	s.mu.Unlock()
}

func (s *Session) expectNextAdd(n uint64) {
	s.mu.Lock()
	s.expectNext += n
	s.mu.Unlock()
}

// ---------------------------------------------------------------------------
// Send
// ---------------------------------------------------------------------------

func (s *Session) blockPayload(seq uint64, n int, recvDigest [wire.DigestSize]byte) []byte {
	if s.cfg.PayloadFor != nil {
		return s.cfg.PayloadFor(seq, n, recvDigest)
	}
	out := make([]byte, n)
	wire.Keystream(s.cfg.Seed, seq, recvDigest, out)
	return out
}

func (s *Session) payloadMatches(f *wire.Frame) bool {
	want := s.blockPayload(f.H.BlockSeq, len(f.Payload), f.H.RecvDigest)
	if len(want) != len(f.Payload) {
		return false
	}
	var d byte
	for i := range want {
		d |= want[i] ^ f.Payload[i]
	}
	return d == 0
}

func (s *Session) sendLoop() {
	var sent, bytes uint64
	var next time.Time
	for {
		select {
		case <-s.done:
			return
		default:
		}
		if s.cfg.Duration > 0 && time.Since(s.started) > s.cfg.Duration {
			s.sendFinalTelemetry()
			close(s.sendDone)
			return
		}
		if s.cfg.TotalBytes > 0 && bytes >= s.cfg.TotalBytes {
			s.sendFinalTelemetry()
			close(s.sendDone)
			return
		}
		n := s.cfg.BlockSize
		if s.cfg.TotalBytes > 0 && bytes+uint64(n) > s.cfg.TotalBytes {
			n = int(s.cfg.TotalBytes - bytes)
		}

		s.mu.Lock()
		seq := s.blockSeq
		rd := s.recvChain
		prev := s.sentChain
		s.blockSeq++
		s.mu.Unlock()

		payload := s.blockPayload(seq, n, rd)
		snap := s.LocalSnapshot()
		report, _ := json.Marshal(snap)
		f := &wire.Frame{
			H: wire.Header{
				Type:           wire.MsgData,
				BlockSeq:       seq,
				StreamOffset:   bytes,
				PrevSentDigest: prev,
				RecvDigest:     rd,
			},
			Report:  report,
			Payload: payload,
		}
		if err := wire.WriteFrame(s.pipe, f); err != nil {
			s.mu.Lock()
			if s.err == nil {
				s.err = err
			}
			s.mu.Unlock()
			return
		}
		s.mu.Lock()
		s.sentChain = wire.ChainNext(prev, seq, payload)
		s.streamOffset += uint64(n)
		s.mu.Unlock()

		sent++
		bytes += uint64(n)
		s.sentBytes.Add(uint64(n))
		s.TxMeter.Add(n + len(report) + wire.HeaderSize)
		s.Counters.BlocksSent.Add(1)
		s.Counters.BytesSent.Add(uint64(n))

		if s.cfg.RateMbps > 0 {
			want := float64(bytes*8) / (s.cfg.RateMbps * 1e6)
			if next.IsZero() {
				next = time.Now()
			}
			due := next.Add(time.Duration(want * float64(time.Second)))
			if d := time.Until(due); d > 0 {
				if d > 5*time.Millisecond {
					select {
					case <-time.After(d):
					case <-s.done:
						return
					}
				} else if d > 0 {
					time.Sleep(d)
				}
			}
		}
	}
}

// sendFinalTelemetry sends one last report-only block when our planned
// transmission is done. Telemetry rides inside data blocks, so without this the
// peer is left with whatever the last block before the tail happened to carry -
// and if the closing blocks were dropped, the peer is diagnosing from a stale
// picture. This frame carries the final counters, and continues the block
// sequence and hash chain so it validates like any other block.
func (s *Session) sendFinalTelemetry() {
	s.mu.Lock()
	seq := s.blockSeq
	prev := s.sentChain
	rd := s.recvChain
	s.blockSeq++
	s.mu.Unlock()
	snap := s.LocalSnapshot()
	snap.Notes = append(snap.Notes, "final telemetry block")
	report, _ := json.Marshal(snap)
	f := &wire.Frame{
		H: wire.Header{
			Type:           wire.MsgData,
			Flags:          wire.FlagPriority,
			BlockSeq:       seq,
			StreamOffset:   s.streamOffset,
			PrevSentDigest: prev,
			RecvDigest:     rd,
		},
		Report: report,
	}
	if err := wire.WriteFrame(s.pipe, f); err != nil {
		return
	}
	s.mu.Lock()
	s.sentChain = wire.ChainNext(prev, seq, nil)
	s.mu.Unlock()
}

func (s *Session) pingLoop() {
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			if s.pingPending.Load() != 0 {
				continue
			}
			now := time.Now().UnixNano()
			s.pingPending.Store(uint64(now))
			_ = wire.WriteFrame(s.pipe, &wire.Frame{H: wire.Header{Type: wire.MsgPing, BlockSeq: uint64(now)}})
		}
	}
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

// LocalSnapshot builds our own telemetry, including everything the engines
// report. This is what rides inside every block we transmit.
func (s *Session) LocalSnapshot() *wire.Snapshot {
	s.mu.Lock()
	started := s.started
	s.mu.Unlock()
	if started.IsZero() {
		started = time.Now()
	}
	sbps := s.TxMeter.Rate() / 1e6
	rbps := s.RxMeter.Rate() / 1e6
	elapsed := time.Since(started).Seconds()
	snap := &wire.Snapshot{
		Generated:     time.Now().UnixNano(),
		PeerID:        s.cfg.LocalID,
		PeerName:      s.cfg.LocalName,
		Stack:         s.cfg.Stack,
		BlocksSent:    s.Counters.BlocksSent.Load(),
		BytesSent:     s.Counters.BytesSent.Load(),
		BlocksRecv:    s.Counters.BlocksRecv.Load(),
		BytesRecv:     s.Counters.BytesRecv.Load(),
		MbpsSent:      sbps,
		MbpsRecv:      rbps,
		ElapsedSec:    elapsed,
		AvgMbpsSent:   avgRate(s.Counters.BytesSent.Load(), elapsed),
		AvgMbpsRecv:   avgRate(s.Counters.BytesRecv.Load(), elapsed),
		ChainMismatch: s.chainBad.Load(),
		BlocksDup:     s.Counters.BlocksDup.Load(),
		BlocksOOO:     s.Counters.BlocksOOO.Load(),
		BlocksLate:    s.Counters.BlocksLate.Load(),
		BlocksMissing: s.Counters.BlocksMissing.Load(),
		Iface:         s.cfg.Iface,
	}
	g, open := s.Gaps.Snapshot()
	snap.Gaps = g
	snap.OpenGaps = open
	snap.MaxGapSeen = s.Gaps.MaxGap()
	for _, p := range s.cfg.Providers {
		if p != nil {
			p(snap)
		}
	}
	if s.pingCount.Load() > 0 {
		snap.AckLatencyMs = float64(s.pingLastNS.Load()) / 1e6
	}
	return snap
}

// PeerSnapshot returns the last telemetry block received from the far side.
func avgRate(bytes uint64, elapsed float64) float64 {
	if elapsed <= 0 {
		return 0
	}
	return float64(bytes) * 8 / 1e6 / elapsed
}

// LastActivity reports when a data block was last received, so the engine can
// tell an idle-but-live session from a dead one and resume advertising if the
// stream stalls.
func (s *Session) LastActivity() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lastPeerData.IsZero() {
		return s.started
	}
	return s.lastPeerData
}

func (s *Session) PeerID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.PeerID
}

func (s *Session) PeerName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.PeerName
}

func (s *Session) PeerSnapshot() (*wire.Snapshot, time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.peerSnap == nil {
		return nil, time.Time{}
	}
	cp := *s.peerSnap
	return &cp, s.peerSnapAt
}

// AppRTT returns application-level round-trip statistics.
func (s *Session) AppRTT() (mean, last, best time.Duration, count uint64) {
	last = time.Duration(s.pingLastNS.Load())
	best = time.Duration(s.pingBestNS.Load())
	if best >= 1<<62 {
		best = 0
	}
	return time.Duration(s.AppHist.Mean() * float64(time.Millisecond)), last, best, s.pingCount.Load()
}

func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

func (s *Session) Stats() (sent, recv uint64) {
	return s.sentBytes.Load(), s.recvBytes.Load()
}

func (s *Session) Close() error {
	s.stopOnce.Do(func() {
		close(s.done)
		// Close the transport first: that unblocks any Write/Read waiting on the
		// stack's condition variable, so shutdown cannot wedge behind a stalled
		// send buffer. The goodbye frame is best-effort and off the critical path.
		_ = s.pipe.Close()
		go func() {
			defer func() { recover() }()
			_ = wire.WriteFrame(s.pipe, &wire.Frame{H: wire.Header{Type: wire.MsgGoodbye}})
		}()
	})
	return nil
}

// Wait blocks until the send loop finishes or the session errors.
func (s *Session) Wait() error {
	select {
	case <-s.sendDone:
		// We have transmitted everything we planned to. Let the tail of the
		// peer's stream land before declaring the run over.
		select {
		case <-s.finished:
		case <-time.After(time.Second):
		}
	case <-s.finished:
	case <-s.done:
	}
	return s.Err()
}
