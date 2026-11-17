package tcpraw

import (
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"sync"
	"time"

	"tcpdiag/internal/stats"
	"tcpdiag/internal/wire"
)

type State int

const (
	StClosed State = iota
	StListen
	StSynSent
	StSynRcvd
	StEstablished
	StFinWait1
	StFinWait2
	StCloseWait
	StClosing
	StLastAck
)

func (s State) String() string {
	switch s {
	case StClosed:
		return "CLOSED"
	case StListen:
		return "LISTEN"
	case StSynSent:
		return "SYN-SENT"
	case StSynRcvd:
		return "SYN-RECEIVED"
	case StEstablished:
		return "ESTABLISHED"
	case StFinWait1:
		return "FIN-WAIT-1"
	case StFinWait2:
		return "FIN-WAIT-2"
	case StCloseWait:
		return "CLOSE-WAIT"
	case StClosing:
		return "CLOSING"
	case StLastAck:
		return "LAST-ACK"
	}
	return "?"
}

var (
	ErrClosed   = errors.New("tcpraw: connection closed")
	ErrReset    = errors.New("tcpraw: connection reset by peer")
	ErrTimeout  = errors.New("tcpraw: retransmission timeout exceeded")
	ErrNoEngine = errors.New("tcpraw: no packet engine")
)

type Config struct {
	LocalIP, RemoteIP     netip.Addr
	LocalPort, RemotePort uint16
	MSS                   int
	RcvBuf, SndBuf        int
	MinRTO, MaxRTO        time.Duration
	InitialRTO            time.Duration
	DelayedACK            bool
	DelayedACKTimeout     time.Duration
	Timestamps            bool
	SACK                  bool
	TTL                   uint8
	TOS                   uint8
	MaxRetransmits        int
	FastRetransmitThresh  int
	PersistInterval       time.Duration
	SynRTO                time.Duration
	KeepAlive             time.Duration
	HandshakeTimeout      time.Duration
	Name                  string
	Logf                  func(string, ...any)
}

func DefaultConfig() Config {
	return Config{
		MSS:                  1460,
		RcvBuf:               4 << 20,
		SndBuf:               4 << 20,
		MinRTO:               200 * time.Microsecond,
		MaxRTO:               60 * time.Second,
		InitialRTO:           1 * time.Second,
		DelayedACK:           false,
		DelayedACKTimeout:    40 * time.Millisecond,
		Timestamps:           true,
		SACK:                 true,
		TTL:                  64,
		MaxRetransmits:       12,
		FastRetransmitThresh: 3,
		PersistInterval:      500 * time.Millisecond,
		SynRTO:               200 * time.Millisecond,
		HandshakeTimeout:     20 * time.Second,
	}
}

// segNode is one transmitted segment held for retransmission.
type segNode struct {
	seq     uint32
	data    []byte
	firstAt time.Time
	lastAt  time.Time
	txCount int
	retrans bool // retransmitted at least once -> excluded from RTT sampling (Karn)
	sacked  bool // peer has SACKed this segment
	next    *segNode
}

type segList struct {
	head, tail *segNode
	n          int
}

func (l *segList) Len() int    { return l.n }
func (l *segList) Empty() bool { return l.head == nil }

func (l *segList) Push(n *segNode) {
	n.next = nil
	if l.tail == nil {
		l.head, l.tail = n, n
	} else {
		l.tail.next = n
		l.tail = n
	}
	l.n++
}

func (l *segList) Pop() *segNode {
	n := l.head
	if n == nil {
		return nil
	}
	l.head = n.next
	if l.head == nil {
		l.tail = nil
	}
	n.next = nil
	l.n--
	return n
}

// oooChunk is out-of-order received data awaiting its hole to be filled.
type oooChunk struct {
	seq  uint32
	data []byte
}

// Conn is a user-space TCP connection. It is deliberately instrumented: every
// event that Wireshark would annotate (dup ACK, fast retransmit, spurious
// retransmit, out-of-order, zero window) is counted and timestamped here, at
// the moment it happens, with the sequence-number evidence attached.
type Conn struct {
	cfg Config
	dmx *Demux
	key Key

	mu   sync.Mutex
	cond *sync.Cond
	wake chan struct{}

	state  State
	err    error
	closed bool

	iss, irs       uint32
	sndUna, sndNxt uint32
	rcvNxt         uint32

	cwnd, ssthresh uint32
	peerWin        uint32
	myScale        int
	peerScale      int
	peerSACKOK     bool
	sawPeerSyn     bool
	peerSynOpts    string
	challenge      uint32
	echoChallenge  bool

	unacked  segList
	txQueue  segList
	inFlight uint32

	rxBuf   []byte
	rxStart int
	rxSeq   uint32
	ooo     map[uint32]*oooChunk
	oooByte int
	sacks   []SACKBlock

	dupCount    int
	inRecovery  bool
	recoveryEnd uint32

	pendingAck    bool
	pendingDup    bool
	ackDue        time.Time
	lastAckSentAt time.Time
	lastAckSent   uint32
	haveLastAck   bool

	lastAckAt  time.Time
	lastDataAt time.Time
	ackWatch   map[uint32]int64 // seq -> recv time, to measure our own ack latency

	rto     *RTTEstimator
	nextRTO time.Time
	synRTO  time.Duration

	hand chan struct{}
	done chan struct{}
	once sync.Once

	Counters *stats.Counters
	Hist     *stats.Histogram
	Ring     *stats.EventRing
	Gaps     *stats.GapRing

	lastPeerTS uint32
	nextSynAt  time.Time
	persistDue time.Time
	onceHand   sync.Once
	startAt    time.Time
	ipid       uint16
	rng        *rand.Rand

	// Observation of the peer's behaviour
	peerClosed  bool
	localClosed bool
	windowStall time.Time
}

// newConn builds an unstarted connection.
func newConn(dmx *Demux, cfg Config) *Conn {
	if cfg.MSS <= 0 {
		cfg.MSS = 1460
	}
	if cfg.RcvBuf <= 0 {
		cfg.RcvBuf = 1 << 20
	}
	if cfg.SndBuf <= 0 {
		cfg.SndBuf = 1 << 20
	}
	if cfg.FastRetransmitThresh <= 0 {
		cfg.FastRetransmitThresh = 3
	}
	c := &Conn{
		cfg:       cfg,
		dmx:       dmx,
		key:       Key{A: cfg.LocalIP, B: cfg.RemoteIP, APort: cfg.LocalPort, BPort: cfg.RemotePort},
		wake:      make(chan struct{}, 1),
		ooo:       map[uint32]*oooChunk{},
		rto:       NewRTTEstimator(cfg.MinRTO, cfg.MaxRTO, cfg.InitialRTO),
		hand:      make(chan struct{}),
		done:      make(chan struct{}),
		Counters:  &stats.Counters{},
		Hist:      stats.NewHistogram(),
		Ring:      stats.NewEventRing(256),
		Gaps:      stats.NewGapRing(64, 64),
		startAt:   time.Now(),
		ackWatch:  map[uint32]int64{},
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
		cwnd:      0,
		ssthresh:  1 << 30,
		challenge: rand.Uint32(),
	}
	if c.challenge == 0 {
		c.challenge = 0x9e3779b9
	}
	if cfg.SynRTO <= 0 {
		cfg.SynRTO = 200 * time.Millisecond
	}
	c.synRTO = cfg.SynRTO
	c.cond = sync.NewCond(&c.mu)
	// Window scaling: smallest shift that fits RcvBuf in 16 bits.
	for c.myScale = 0; (cfg.RcvBuf >> c.myScale) > 65535; c.myScale++ {
	}
	return c
}

func (c *Conn) log(format string, v ...any) {
	if c.cfg.Logf != nil {
		c.cfg.Logf(format, v...)
	}
}

func (c *Conn) wakeTx() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// ---------------------------------------------------------------------------
// Active / passive open
// ---------------------------------------------------------------------------

// Dial performs a TCP three-way handshake using only the packet engine.
func Dial(dmx *Demux, cfg Config) (*Conn, error) {
	if dmx == nil {
		return nil, ErrNoEngine
	}
	c := newConn(dmx, cfg)
	c.mu.Lock()
	c.iss = rand.Uint32()
	c.sndUna, c.sndNxt = c.iss, c.iss+1
	c.state = StSynSent
	c.mu.Unlock()
	c.dmx.Register(c.key, c.onSegment)
	c.sendSYN()
	go c.txLoop()

	timeout := cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	select {
	case <-c.hand:
		c.mu.Lock()
		err := c.err
		c.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return c, nil
	case <-time.After(timeout):
		c.Close()
		return nil, fmt.Errorf("tcpraw: handshake timed out to %s:%d", cfg.RemoteIP, cfg.RemotePort)
	}
}

// Listener accepts an inbound raw TCP connection.
type Listener struct {
	c   *Conn
	dmx *Demux
}

// Listen starts a passive open: it waits for a SYN from the configured remote.
func Listen(dmx *Demux, cfg Config) *Listener {
	c := newConn(dmx, cfg)
	c.mu.Lock()
	c.state = StListen
	c.mu.Unlock()
	c.dmx.Register(c.key, c.onSegment)
	go c.txLoop()
	return &Listener{c: c, dmx: dmx}
}

// Accept waits for the handshake to complete.
func (l *Listener) Accept() (*Conn, error) {
	select {
	case <-l.c.hand:
		l.c.mu.Lock()
		err := l.c.err
		l.c.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return l.c, nil
	case <-time.After(5 * time.Minute):
		l.c.Close()
		return nil, errors.New("tcpraw: no SYN received")
	}
}

func (c *Conn) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *Conn) LocalAddr() netip.AddrPort {
	return netip.AddrPortFrom(c.cfg.LocalIP, c.cfg.LocalPort)
}
func (c *Conn) RemoteAddr() netip.AddrPort {
	return netip.AddrPortFrom(c.cfg.RemoteIP, c.cfg.RemotePort)
}

// ---------------------------------------------------------------------------
// Transmit helpers
// ---------------------------------------------------------------------------

func (c *Conn) advertisedWindow() uint32 {
	unread := uint32(len(c.rxBuf)-c.rxStart) + uint32(c.oooByte)
	free := 0
	if c.cfg.RcvBuf > int(unread) {
		free = c.cfg.RcvBuf - int(unread)
	}
	w := uint32(free >> c.myScale)
	if w > 65535 {
		w = 65535
	}
	return w
}

// send builds and transmits one segment. Caller holds c.mu.
func (c *Conn) send(flags uint8, seq, ack uint32, payload []byte, opts Options) {
	if c.challenge != 0 {
		// Every segment carries the private challenge. The OS port shield on
		// the same 4-tuple never sees or echoes this option, so its ACKs,
		// window updates and resets can be ignored cleanly.
		opts.HasChallenge, opts.Challenge = true, c.challenge
	}
	s := &Segment{
		SrcIP:   c.cfg.LocalIP,
		DstIP:   c.cfg.RemoteIP,
		SrcPort: c.cfg.LocalPort,
		DstPort: c.cfg.RemotePort,
		Seq:     seq,
		Ack:     ack,
		Flags:   flags,
		Window:  uint16(c.advertisedWindow()),
		TTL:     c.cfg.TTL,
		TOS:     c.cfg.TOS,
		Opts:    opts,
		Payload: payload,
	}
	c.ipid++
	s.IPID = c.ipid
	if c.cfg.Timestamps && (c.state == StEstablished || c.state == StCloseWait || c.state == StFinWait1 || c.state == StFinWait2) {
		s.Opts.HasTimestamp = true
		s.Opts.Timestamp = uint32(time.Since(c.startAt).Milliseconds())
		s.Opts.TimestampEcho = c.lastPeerTS
	}
	if len(payload) == 0 && flags&FlagACK != 0 {
		// A pure ACK repeating the previous acknowledgement while a hole is
		// open at the peer is what an analyser labels "TCP Dup ACK".
		if c.haveLastAck && ack == c.lastAckSent && len(c.ooo) > 0 {
			c.Counters.DupAcksSent.Add(1)
		}
		c.haveLastAck, c.lastAckSent = true, ack
	}
	pkt := s.Marshal()
	c.Counters.SegsSent.Add(1)
	if err := c.dmx.Send(s); err != nil {
		c.log("send error: %v", err)
	}
	_ = pkt
}

// sendSYN emits the initial SYN with our option set.
func (c *Conn) sendSYN() {
	c.mu.Lock()
	defer c.mu.Unlock()
	o := Options{MSS: uint16(c.cfg.MSS), HasWinScale: true, WinScale: c.myScale}
	if c.cfg.SACK {
		o.SACKPermitted = true
	}
	o.HasChallenge, o.Challenge = true, c.challenge
	if c.cfg.Timestamps {
		o.HasTimestamp = true
		o.Timestamp = uint32(time.Since(c.startAt).Milliseconds())
	}
	c.send(FlagSYN, c.sndNxt-1, 0, nil, o)
	c.nextSynAt = time.Now().Add(c.synRTO)
}

// retransmitHandshake repeats whichever handshake segment is outstanding. A
// listener in SYN-RECEIVED must repeat its SYN/ACK: re-sending a bare SYN there
// is ignored by the peer and the connection can never come up.
func (c *Conn) retransmitHandshake() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == StSynRcvd {
		o := Options{MSS: uint16(c.cfg.MSS), HasWinScale: true, WinScale: c.myScale}
		if c.cfg.SACK {
			o.SACKPermitted = true
		}
		o.HasChallenge, o.Challenge = c.echoChallenge, c.challenge
		c.send(FlagSYN|FlagACK, c.sndNxt-1, c.rcvNxt, nil, o)
	} else {
		o := Options{MSS: uint16(c.cfg.MSS), HasWinScale: true, WinScale: c.myScale}
		if c.cfg.SACK {
			o.SACKPermitted = true
		}
		o.HasChallenge, o.Challenge = true, c.challenge
		if c.cfg.Timestamps {
			o.HasTimestamp = true
			o.Timestamp = uint32(time.Since(c.startAt).Milliseconds())
		}
		c.send(FlagSYN, c.sndNxt-1, 0, nil, o)
	}
	c.Counters.SynRetrans.Add(1)
	c.synRTO *= 2
	if c.synRTO > c.cfg.MaxRTO {
		c.synRTO = c.cfg.MaxRTO
	}
	c.nextSynAt = time.Now().Add(c.synRTO)
}

// emitAckLocked sends a pure acknowledgement (possibly a duplicate ACK, which
// is exactly what triggers the peer's fast retransmit).
func (c *Conn) emitAckLocked(dup bool) {
	o := Options{}
	if len(c.sacks) > 0 && c.cfg.SACK && c.peerSACKOK {
		o.SACK = c.sacks
		c.Counters.SackBlocks.Add(uint64(len(c.sacks)))
	}
	if c.cfg.Timestamps {
		o.HasTimestamp = true
		o.Timestamp = uint32(time.Since(c.startAt).Milliseconds())
		o.TimestampEcho = c.lastPeerTS
	}
	flags := uint8(FlagACK)
	if c.localClosed {
		flags |= FlagFIN
	}
	c.send(flags, c.sndNxt, c.rcvNxt, nil, o)
	c.pendingAck, c.pendingDup = false, false
	c.lastAckSentAt = time.Now()
	_ = dup
	// Ack-generation latency: how long did we sit on data before acking it?
	for seq, at := range c.ackWatch {
		if seqLE(seq, c.rcvNxt) {
			lat := float64(c.lastAckSentAt.UnixNano()-at) / 1e6
			c.Counters.AckLatencyNS.Store(uint64(lat * 1e6))
			delete(c.ackWatch, seq)
		}
	}
}

// ---------------------------------------------------------------------------
// Receive path
// ---------------------------------------------------------------------------

func (c *Conn) onSegment(s *Segment) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	// Ignore anything our own host generated. SIO_RCVALL is a sniffer, not a
	// bypass, so the kernel stack still sees the packets for this user-space
	// connection and answers its own SYN with a SYN/ACK and an RST. Those are
	// sourced from our local address, whereas the peer never is, so dropping
	// them removes the interference cleanly.
	if s.SrcIP == c.cfg.LocalIP {
		return
	}
	c.Counters.SegsRecv.Add(1)
	now := time.Now()
	if s.Opts.HasTimestamp {
		c.lastPeerTS = s.Opts.Timestamp
	}

	switch c.state {
	case StSynSent:
		if s.Flags&FlagRST != 0 {
			c.failLocked(ErrReset)
			return
		}
		if s.Flags&FlagSYN == 0 || s.Flags&FlagACK == 0 {
			return
		}
		if s.Ack != c.sndNxt {
			c.log("SYN/ACK ack %d does not match iss+1 %d", s.Ack, c.sndNxt)
			return
		}
		if !s.Opts.HasChallenge || s.Opts.Challenge != c.challenge {
			// This is almost certainly the OS port shield answering the same
			// SYN. Its SYN-ACK has a different sequence space and would poison
			// the connection if accepted.
			c.log("ignoring SYN/ACK without matching raw challenge")
			return
		}
		c.irs = s.Seq
		c.rcvNxt = c.irs + 1
		c.rxSeq = c.rcvNxt
		c.acceptPeerOpts(s)
		c.send(FlagACK, c.sndNxt-1, c.rcvNxt, nil, Options{})
		c.state = StEstablished
		c.cwnd = uint32(c.cfg.MSS)
		c.lastAckAt = now
		c.log("established (raw) %s", c.key)
		c.signalHandshake()
		return
	case StListen, StSynRcvd:
		if s.Flags&FlagRST != 0 {
			c.failLocked(ErrReset)
			return
		}
		if c.state == StListen {
			if s.Flags&FlagSYN == 0 {
				return
			}
			c.irs = rand.Uint32() - 1
			c.iss = c.irs
			c.sndUna, c.sndNxt = c.iss, c.iss+1
			c.rcvNxt = s.Seq + 1
			c.rxSeq = c.rcvNxt
			c.acceptPeerOpts(s)
			if s.Opts.HasChallenge {
				c.challenge = s.Opts.Challenge
				c.echoChallenge = true
			} else {
				c.challenge = 0
				c.echoChallenge = false
			}
			o := Options{MSS: uint16(c.cfg.MSS), HasWinScale: true, WinScale: c.myScale}
			if c.cfg.SACK {
				o.SACKPermitted = true
			}
			o.HasChallenge, o.Challenge = c.echoChallenge, c.challenge
			c.send(FlagSYN|FlagACK, c.sndNxt-1, c.rcvNxt, nil, o)
			c.state = StSynRcvd
			c.nextSynAt = now.Add(c.rto.RTO)
			c.log("received SYN from %s:%d, sent SYN/ACK", s.SrcIP, s.SrcPort)
			return
		}
		// StSynRcvd: awaiting the final ACK.
		if c.challenge != 0 && (!s.Opts.HasChallenge || s.Opts.Challenge != c.challenge) {
			c.log("ignoring handshake ACK without matching raw challenge")
			return
		}
		if s.Flags&FlagACK != 0 && s.Ack == c.sndNxt {
			c.state = StEstablished
			c.cwnd = uint32(c.cfg.MSS)
			c.lastAckAt = now
			c.acceptPeerOpts(s)
			c.log("handshake completed by peer ACK")
			c.signalHandshake()
		}
		return
	}

	// Established (and closing states).
	if c.challenge != 0 && (!s.Opts.HasChallenge || s.Opts.Challenge != c.challenge) {
		c.log("ignoring segment without matching raw challenge")
		return
	}
	if s.Flags&FlagRST != 0 {
		c.Counters.RstRecv.Add(1)
		c.log("RST received from peer")
		c.failLocked(ErrReset)
		return
	}
	if s.Flags&FlagACK == 0 {
		return
	}
	c.Counters.AckSegsRecv.Add(1)

	if s.Window == 0 && c.peerWin != 0 {
		c.Counters.ZeroWindowRecv.Add(1)
		c.log("peer advertised zero window")
	}
	c.peerWin = uint32(s.Window) << c.peerScale
	if c.peerWin > 0 {
		c.windowStall = time.Time{}
	}

	// --- acknowledgement of our data -------------------------------------
	if seqGT(s.Ack, c.sndUna) && seqLE(s.Ack, c.sndNxt) {
		c.processAckLocked(s, now)
	} else if s.Ack == c.sndUna && c.unacked.Len() > 0 && c.sndNxt > c.sndUna {
		c.processDupAckLocked(s, now)
	}
	if len(s.Opts.SACK) > 0 {
		c.processSACKLocked(s)
	}

	// --- peer FIN ---------------------------------------------------------
	if s.Flags&FlagFIN != 0 && !c.peerClosed {
		if seqGE(s.Seq, c.rcvNxt) || s.Seq == c.rcvNxt {
			c.peerClosed = true
			c.rcvNxt = s.Seq + 1
			if c.state == StEstablished {
				c.state = StCloseWait
			}
			c.pendingAck = true
			c.cond.Broadcast()
			c.log("peer sent FIN")
		}
	}

	// --- payload ----------------------------------------------------------
	if len(s.Payload) > 0 {
		c.processDataLocked(s, now)
	}

	if c.pendingDup {
		c.emitAckLocked(true)
	} else if c.pendingAck {
		if c.cfg.DelayedACK && !c.hasWorkLocked() {
			c.ackDue = now.Add(c.cfg.DelayedACKTimeout)
		} else {
			c.emitAckLocked(false)
		}
	}
	c.flushLocked(now)
	c.cond.Broadcast()
}

// acceptPeerOpts records what the peer announced. The option-derived fields are
// taken from SYN segments only: the final ACK of the handshake carries no
// options, and re-deriving from it would silently clear a negotiated option
// such as SACK (which then degrades recovery and manufactures spurious
// retransmissions).
func (c *Conn) acceptPeerOpts(s *Segment) {
	if s.Flags&FlagSYN != 0 {
		c.sawPeerSyn = true
		c.peerSynOpts = describeOptions(s)
		if s.Opts.HasWinScale {
			c.peerScale = s.Opts.WinScale
			if c.peerScale > 14 {
				c.peerScale = 14
			}
		}
		if s.Opts.MSS > 0 && int(s.Opts.MSS) < c.cfg.MSS {
			c.cfg.MSS = int(s.Opts.MSS)
		}
		if s.Opts.SACKPermitted {
			c.peerSACKOK = c.cfg.SACK
		}
	}
	c.peerWin = uint32(s.Window) << c.peerScale
}

func (c *Conn) signalHandshake() {
	c.onceHand.Do(func() { close(c.hand) })
	c.wakeTx()
}

func (c *Conn) failLocked(err error) {
	if c.err == nil {
		c.err = err
	}
	c.state = StClosed
	c.cond.Broadcast()
	c.onceHand.Do(func() { close(c.hand) })
}

func (c *Conn) processAckLocked(s *Segment, now time.Time) {
	newUna := s.Ack
	var rttSample time.Duration
	sampled := false
	ackedBytes := uint32(0)

	for !c.unacked.Empty() {
		n := c.unacked.head
		end := n.seq + uint32(len(n.data))
		if seqGT(end, newUna) {
			break
		}
		ackedBytes += uint32(len(n.data))
		if !n.retrans && !sampled {
			rttSample = now.Sub(n.firstAt)
			sampled = true
		}
		c.unacked.Pop()
	}
	c.inFlight = c.sndNxt - newUna
	c.sndUna = newUna
	c.lastAckAt = now
	c.dupCount = 0
	c.inFlightBytes()

	if sampled && rttSample > 0 {
		c.rto.Update(rttSample)
		c.Hist.Observe(float64(rttSample) / float64(time.Millisecond))
	}
	if c.inRecovery && seqGE(c.sndUna, c.recoveryEnd) {
		c.inRecovery = false
	}
	// Congestion avoidance / slow start
	mss := uint32(c.cfg.MSS)
	if c.cwnd < c.ssthresh {
		c.cwnd += ackedBytes
		if c.cwnd > c.ssthresh {
			c.cwnd = c.ssthresh
		}
	} else {
		inc := (mss * mss) / c.cwnd
		if inc == 0 {
			inc = 1
		}
		c.cwnd += inc
	}
	c.nextRTO = time.Time{}
	if !c.unacked.Empty() {
		c.nextRTO = now.Add(c.rto.RTO)
	}
	c.log("ack -> %d (in-flight %d, cwnd %d, srtt %v)", newUna, c.inFlight, c.cwnd, c.rto.SRTT)
}

func (c *Conn) processDupAckLocked(s *Segment, now time.Time) {
	c.dupCount++
	c.Counters.DupAcksRecv.Add(1)
	if c.dupCount == c.cfg.FastRetransmitThresh && !c.inRecovery {
		c.fastRetransmitLocked(now)
	}
}

func (c *Conn) processSACKLocked(s *Segment) {
	c.sacks = append([]SACKBlock{}, s.Opts.SACK...)
	for _, b := range c.sacks {
		for n := c.unacked.head; n != nil; n = n.next {
			end := n.seq + uint32(len(n.data))
			if seqLE(b.Start, n.seq) && seqGE(b.End, end) {
				n.sacked = true
			}
		}
	}
}

// rangeAlreadyHeld reports whether the peer has told us (cumulative ACK or a
// SACK block) that it already holds [seq,seq+n). Resending such a range is what
// an analyser labels a spurious retransmission.
func (c *Conn) rangeAlreadyHeld(seq, n uint32) bool {
	end := seq + n
	if seqLE(end, c.sndUna) {
		return true
	}
	for _, b := range c.sacks {
		if seqLE(b.Start, seq) && seqGE(b.End, end) {
			return true
		}
	}
	return false
}

// firstLostSeq uses SACK information to locate the earliest un-SACKed hole.
func (c *Conn) firstLostSeq() uint32 {
	if len(c.sacks) == 0 || c.unacked.Empty() {
		return c.sndUna
	}
	cur := c.sndUna
	for _, b := range c.sacks {
		if b.Start != cur {
			break
		}
		if seqGT(b.End, cur) {
			cur = b.End
		}
	}
	return cur
}

func (c *Conn) fastRetransmitLocked(now time.Time) {
	c.Counters.FastRetrans.Add(1)
	mss := uint32(c.cfg.MSS)
	c.ssthresh = c.cwnd / 2
	if c.ssthresh < 2*mss {
		c.ssthresh = 2 * mss
	}
	c.cwnd = c.ssthresh + 3*mss
	c.inRecovery = true
	c.recoveryEnd = c.sndNxt
	seq := c.firstLostSeq()
	sinceAck := now.Sub(c.lastAckAt)
	ev := wire.RetxEvent{
		Seq: seq, Kind: "fast_retransmit", At: now.UnixNano(),
		SinceLastAckMs:  sinceAck.Milliseconds(),
		SinceLastDataMs: now.Sub(c.lastDataAt).Milliseconds(),
		WithinRTT:       c.rto.TooEarly(sinceAck),
	}
	ev.AlreadyAcked = c.rangeAlreadyHeld(seq, mss)
	if ev.AlreadyAcked {
		// The peer already told us it holds this data.
		c.Counters.SpuriousRetrans.Add(1)
		c.Counters.SpuriousSack.Add(1)
		c.log("FAST RETRANSMIT seq=%d but the peer already ACKed/SACKed it => SPURIOUS", seq)
	} else {
		c.log("FAST RETRANSMIT seq=%d after %d dup acks", seq, c.dupCount)
	}
	c.resendFromLocked(seq, mss, now, &ev)
	c.Ring.Add(ev)
}

// resendFromLocked retransmits segments beginning at seq, up to budget bytes.
func (c *Conn) resendFromLocked(seq uint32, budget uint32, now time.Time, ev *wire.RetxEvent) {
	resent := uint32(0)
	for n := c.unacked.head; n != nil && (budget == 0 || resent < budget); n = n.next {
		nend := n.seq + uint32(len(n.data))
		if seqLE(nend, seq) {
			continue
		}
		off := uint32(0)
		if seqGT(seq, n.seq) {
			off = seq - n.seq
		}
		data := n.data[off:]
		if budget > 0 && uint32(len(data)) > budget-resent {
			data = data[:budget-resent]
		}
		n.lastAt = now
		n.txCount++
		n.retrans = true
		if uint32(n.txCount) > uint32(c.Counters.MaxRetrPerSeq.Load()) {
			c.Counters.MaxRetrPerSeq.Store(uint64(n.txCount))
		}
		o := Options{}
		if len(c.sacks) > 0 && c.peerSACKOK {
			o.SACK = c.sacks
		}
		c.send(FlagACK|FlagPSH, n.seq+off, c.rcvNxt, data, o)
		c.Counters.RetransSent.Add(1)
		c.Counters.OctetsRetrans.Add(uint64(len(data)))
		resent += uint32(len(data))
		if ev != nil {
			ev.Len = uint32(len(data))
			ev.OctetsReSent += uint64(len(data))
			ev.RetransmitCount = uint32(n.txCount)
		}
	}
}

// processDataLocked handles inbound payload, tracking holes, duplicates and
// out-of-order arrival the same way a wire analyzer would.
func (c *Conn) processDataLocked(s *Segment, now time.Time) {
	start, end := s.Seq, s.Seq+uint32(len(s.Payload))
	c.Counters.SegsRecv.Add(0)
	if c.peerClosed {
		return
	}
	// Beyond our receive window: ignore (a real stack would send a challenge ACK).
	if seqGT(end, c.rcvNxt+uint32(c.cfg.RcvBuf)) {
		c.Counters.BufFullStalls.Add(1)
		return
	}
	if seqLE(end, c.rcvNxt) {
		// Entirely old data that we have already delivered: from a wire
		// analyzer's point of view this is a spurious retransmission.
		c.Counters.RetransRecv.Add(1)
		c.Counters.SpuriousRecv.Add(1)
		c.pendingAck = true
		c.log("segment seq=%d..%d is below rcvNxt=%d => SPURIOUS retransmission", start, end, c.rcvNxt)
		return
	}
	if seqLT(s.Seq, c.rcvNxt) {
		// Overlaps the left edge: trim the already-received prefix.
		trim := c.rcvNxt - s.Seq
		s = &Segment{Payload: s.Payload[trim:], Seq: c.rcvNxt, Flags: s.Flags, Opts: s.Opts}
		start = s.Seq
		end = start + uint32(len(s.Payload))
	}

	if start == c.rcvNxt {
		c.rxBuf = append(c.rxBuf, s.Payload...)
		c.rcvNxt = end
		c.Counters.BytesRecv.Add(uint64(len(s.Payload)))
		c.lastDataAt = now
		c.ackWatch[start] = now.UnixNano()
		if len(c.ackWatch) > 64 {
			for k := range c.ackWatch {
				if seqLT(k, start) {
					delete(c.ackWatch, k)
				}
			}
		}
		c.pendingAck = true
		c.mergeOOOLocked()
		c.rebuildSACKsLocked()
		c.cond.Broadcast()
		return
	}

	// Out of order: it lies beyond rcvNxt.
	if _, dup := c.ooo[start]; dup {
		c.Counters.RetransRecv.Add(1)
		c.log("duplicate segment for hole at seq=%d", start)
		return
	}
	c.Counters.OooSegs.Add(1)
	// Does this fill an existing hole (=> a retransmission from the peer), or
	// does it open a new one?
	fillsHole := false
	for _, b := range c.sacks {
		if seqLE(b.Start, start) && seqGE(b.End, end) {
			fillsHole = true
			break
		}
	}
	if fillsHole {
		c.Counters.RetransRecv.Add(1)
		c.log("retransmission fills hole at seq=%d", start)
	} else {
		c.Gaps.Open(uint64(c.rcvNxt), uint64(start))
		c.log("out-of-order segment seq=%d (expected %d) => gap of %d bytes", start, c.rcvNxt, start-c.rcvNxt)
	}
	// Keep the ooo set bounded.
	if len(c.ooo) > 4096 {
		return
	}
	cp := append([]byte{}, s.Payload...)
	c.ooo[start] = &oooChunk{seq: start, data: cp}
	c.oooByte += len(cp)
	// A hole means we owe the sender a duplicate ACK straight away; that is the
	// signal it needs to run fast retransmit instead of waiting for an RTO.
	c.pendingAck = true
	c.pendingDup = true
}

func (c *Conn) mergeOOOLocked() {
	for {
		ch, ok := c.ooo[c.rcvNxt]
		if !ok {
			return
		}
		from := c.rcvNxt
		c.rxBuf = append(c.rxBuf, ch.data...)
		c.rcvNxt += uint32(len(ch.data))
		c.oooByte -= len(ch.data)
		delete(c.ooo, from)
		c.Counters.BytesRecv.Add(uint64(len(ch.data)))
		c.Gaps.Fill(uint64(from), "retransmit")
	}
}

// rebuildSACKsLocked collapses the out-of-order set into SACK blocks.
func (c *Conn) rebuildSACKsLocked() {
	blocks := make([]SACKBlock, 0, 4)
	for seq, ch := range c.ooo {
		blocks = append(blocks, SACKBlock{Start: seq, End: seq + uint32(len(ch.data))})
	}
	// sort + merge
	for i := 1; i < len(blocks); i++ {
		for j := i; j > 0 && seqLT(blocks[j].Start, blocks[j-1].Start); j-- {
			blocks[j], blocks[j-1] = blocks[j-1], blocks[j]
		}
	}
	merged := make([]SACKBlock, 0, len(blocks))
	for _, b := range blocks {
		if len(merged) > 0 && seqGE(b.Start, merged[len(merged)-1].End) && seqLE(b.Start, merged[len(merged)-1].End) {
			if seqGT(b.End, merged[len(merged)-1].End) {
				merged[len(merged)-1].End = b.End
			}
			continue
		}
		merged = append(merged, b)
		// Four blocks plus timestamps would need 44 of the 40 available option
		// bytes, so generate at most three and leave room for the rest.
		if len(merged) == 3 {
			break
		}
	}
	c.sacks = merged
}

// ---------------------------------------------------------------------------
// Flush + timers
// ---------------------------------------------------------------------------

func (c *Conn) hasWorkLocked() bool {
	return !c.txQueue.Empty() || c.pendingAck || c.pendingDup
}

func (c *Conn) inFlightBytes() uint32 {
	var n uint32
	for x := c.unacked.head; x != nil; x = x.next {
		n += uint32(len(x.data))
	}
	c.inFlight = n
	return n
}

func (c *Conn) flushLocked(now time.Time) {
	mss := uint32(c.cfg.MSS)
	for !c.txQueue.Empty() {
		limit := c.cwnd
		if c.peerWin < limit {
			limit = c.peerWin
		}
		if limit == 0 {
			if c.unacked.Empty() {
				c.windowStall = now
			}
			return
		}
		flight := c.inFlightBytes()
		if flight >= limit {
			return
		}
		space := limit - flight
		n := c.txQueue.head
		take := uint32(len(n.data))
		if take > space && flight > 0 {
			return
		}
		if take > space {
			take = space
		}
		data := n.data[:take]
		cp := append([]byte{}, data...)
		n.data = n.data[take:]
		sn := &segNode{seq: c.sndNxt, data: cp, firstAt: now, lastAt: now}
		if len(n.data) == 0 {
			c.txQueue.Pop()
		} else {
			// Partial transmission: keep the head in place so stream order is preserved.
		}
		flags := uint8(FlagACK | FlagPSH)
		o := Options{}
		if len(c.sacks) > 0 && c.peerSACKOK {
			o.SACK = c.sacks
		}
		c.pendingAck = false
		c.send(flags, c.sndNxt, c.rcvNxt, cp, o)
		c.sndNxt += uint32(len(cp))
		sn.seq = c.sndNxt - uint32(len(cp))
		sn.txCount = 1
		c.unacked.Push(sn)
		c.lastDataAt = now
		if c.nextRTO.IsZero() {
			c.nextRTO = now.Add(c.rto.RTO)
		}
		_ = mss
	}
}

func (c *Conn) checkTimersLocked(now time.Time) {
	if c.state < StEstablished {
		if !c.nextSynAt.IsZero() && now.After(c.nextSynAt) {
			c.mu.Unlock()
			c.retransmitHandshake()
			c.mu.Lock()
			c.log("handshake retransmit (state %s)", c.state)
		}
		return
	}
	if !c.ackDue.IsZero() && now.After(c.ackDue) {
		c.ackDue = time.Time{}
		c.emitAckLocked(false)
	}
	if !c.unacked.Empty() {
		if !c.nextRTO.IsZero() && now.After(c.nextRTO) {
			c.rtoRetransmitLocked(now)
		}
		return
	}
	// Zero-window persistence: nothing in flight, data queued, no window.
	if c.txQueue.Len() > 0 && c.peerWin == 0 {
		if c.persistDue.IsZero() || now.After(c.persistDue) {
			c.Counters.WindowProbes.Add(1)
			n := c.txQueue.head
			probe := append([]byte{}, n.data[:1]...)
			c.send(FlagACK|FlagPSH, c.sndNxt, c.rcvNxt, probe, Options{})
			c.persistDue = now.Add(c.cfg.PersistInterval)
			c.log("zero-window probe sent (stalled %v)", time.Since(c.windowStall))
		}
	} else {
		c.persistDue = time.Time{}
	}
}

func (c *Conn) rtoRetransmitLocked(now time.Time) {
	n := c.unacked.head
	if n == nil {
		c.nextRTO = time.Time{}
		return
	}
	sinceAck := now.Sub(c.lastAckAt)
	tooEarly := c.rto.TooEarly(sinceAck)
	ev := wire.RetxEvent{
		Seq:             n.seq,
		Len:             uint32(len(n.data)),
		Kind:            "rto",
		At:              now.UnixNano(),
		SinceLastAckMs:  sinceAck.Milliseconds(),
		SinceLastDataMs: now.Sub(c.lastDataAt).Milliseconds(),
		WithinRTT:       tooEarly,
	}
	if tooEarly {
		// Resending inside the plausible RTT window: the peer almost certainly
		// already has this data. This is the spurious-retransmission signature.
		c.Counters.SpuriousRetrans.Add(1)
	}
	if n.txCount >= c.cfg.MaxRetransmits {
		c.failLocked(ErrTimeout)
		return
	}
	c.Counters.RtoRetrans.Add(1)
	c.rto.Backoff()
	mss := uint32(c.cfg.MSS)
	c.ssthresh = c.cwnd / 2
	if c.ssthresh < 2*mss {
		c.ssthresh = 2 * mss
	}
	c.cwnd = mss
	c.inRecovery = false
	c.dupCount = 0
	n.lastAt = now
	n.txCount++
	n.retrans = true
	if uint32(n.txCount) > uint32(c.Counters.MaxRetrPerSeq.Load()) {
		c.Counters.MaxRetrPerSeq.Store(uint64(n.txCount))
	}
	c.send(FlagACK|FlagPSH, n.seq, c.rcvNxt, n.data, Options{})
	c.Counters.RetransSent.Add(1)
	c.Counters.OctetsRetrans.Add(uint64(len(n.data)))
	ev.RetransmitCount = uint32(n.txCount)
	ev.OctetsReSent = uint64(len(n.data))
	c.Ring.Add(ev)
	c.nextRTO = now.Add(c.rto.RTO)
	c.log("RTO retransmit seq=%d len=%d after %v (rto now %v%s)", n.seq, len(n.data), sinceAck, c.rto.RTO, spuriousTag(tooEarly))
}

func spuriousTag(b bool) string {
	if b {
		return ", SPURIOUS"
	}
	return ""
}

func (c *Conn) txLoop() {
	t := time.NewTicker(250 * time.Microsecond)
	defer t.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-c.wake:
		case <-t.C:
		}
		c.mu.Lock()
		now := time.Now()
		c.flushLocked(now)
		c.checkTimersLocked(now)
		c.mu.Unlock()
	}
}

// ---------------------------------------------------------------------------
// net.Conn-ish API
// ---------------------------------------------------------------------------

func (c *Conn) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	total := 0
	mss := c.cfg.MSS
	for total < len(b) {
		// Bound the amount of queued work so Write() applies back-pressure.
		for c.queuedLocked() >= uint32(c.cfg.SndBuf) && c.err == nil && !c.closed {
			c.cond.Wait()
		}
		if c.err != nil {
			return total, c.err
		}
		if c.closed {
			return total, ErrClosed
		}
		n := len(b) - total
		if n > mss {
			n = mss
		}
		cp := append([]byte{}, b[total:total+n]...)
		c.txQueue.Push(&segNode{data: cp})
		total += n
	}
	c.wakeTx()
	c.cond.Broadcast()
	return total, nil
}

func (c *Conn) queuedLocked() uint32 {
	var n uint32
	for x := c.txQueue.head; x != nil; x = x.next {
		n += uint32(len(x.data))
	}
	for x := c.unacked.head; x != nil; x = x.next {
		n += uint32(len(x.data))
	}
	return n
}

func (c *Conn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if len(c.rxBuf) > c.rxStart {
			n := copy(b, c.rxBuf[c.rxStart:])
			c.rxStart += n
			c.rxSeq += uint32(n)
			if c.rxStart == len(c.rxBuf) {
				c.rxBuf, c.rxStart = c.rxBuf[:0], 0
			}
			c.wakeTx()
			return n, nil
		}
		if c.err != nil {
			return 0, c.err
		}
		if c.peerClosed {
			return 0, nil
		}
		if c.closed {
			return 0, ErrClosed
		}
		c.cond.Wait()
	}
}

func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.localClosed = true
	if c.state == StEstablished {
		c.state = StFinWait1
		c.send(FlagFIN|FlagACK, c.sndNxt, c.rcvNxt, nil, Options{})
	}
	c.cond.Broadcast()
	c.mu.Unlock()
	c.once.Do(func() {
		close(c.done)
		if c.dmx != nil {
			_ = c.dmx.Close()
		}
	})
	return nil
}

// describeOptions renders the TCP options a segment carried, for the report.
func describeOptions(s *Segment) string {
	var parts []string
	if s.Opts.MSS > 0 {
		parts = append(parts, fmt.Sprintf("MSS=%d", s.Opts.MSS))
	}
	if s.Opts.HasWinScale {
		parts = append(parts, fmt.Sprintf("WindowScale=%d", s.Opts.WinScale))
	}
	if s.Opts.SACKPermitted {
		parts = append(parts, "SACK-Permitted")
	}
	if s.Opts.HasTimestamp {
		parts = append(parts, "Timestamps")
	}
	if s.Opts.UnknownOptions > 0 {
		parts = append(parts, fmt.Sprintf("unknown=%d", s.Opts.UnknownOptions))
	}
	if len(parts) == 0 {
		return "no options"
	}
	return strings.Join(parts, ", ")
}
