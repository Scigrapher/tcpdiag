package engine

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"tcpdiag/internal/discovery"
	"tcpdiag/internal/flow"
	"tcpdiag/internal/kernelstat"
	"tcpdiag/internal/packetio"
	"tcpdiag/internal/probe"
	"tcpdiag/internal/report"
	"tcpdiag/internal/tcpraw"
	"tcpdiag/internal/wire"
)

// Options is the fully resolved configuration.
type Options struct {
	Name                string
	Peer                string
	PeerStack           string
	PeerRawPort         int
	Discover            bool
	DiscoveryPort       int
	Multicast           string
	DataPort            int
	RawPort             int
	ProbePort           int
	Stack               string
	Backend             string
	LocalIP             string
	Bind                string
	Iface               string
	BlockSize           int
	RateMbps            float64
	Duration            time.Duration
	TotalBytes          uint64
	ConnectTimeout      time.Duration
	ConnectAttempts     int
	Feed                string
	RcvBuf              int
	SndBuf              int
	MSS                 int
	MinRTO              time.Duration
	MaxRTO              time.Duration
	DelayedACK          bool
	Timestamps          bool
	SACK                bool
	TOS                 int
	TTL                 int
	Impair              string
	HTTP                string
	PCAP                string
	PCAPDLT             string
	PCAPAll             bool
	JSONL               string
	CSV                 string
	ReportFile          string
	DoProbe             bool
	ExitAfterProbes     bool
	ProbeCount          int
	ProbeSweep          bool
	ProbeMTU            bool
	ProbeTTL            bool
	ProbeTCP            bool
	TCPProbePort        int
	PeerTCPProbePort    int
	ProbeTCPConnections int
	ProbeTCPBytes       int
	ProbeTCPSmall       int
	ProbeTCPNoDelay     bool
	ProbeTCPTimeout     time.Duration
	NoDelay             bool
	KeepAdvertising     bool
	Verbose             bool
	Version             string
}

type sessionSet struct {
	peerID   string
	peerName string
	kernel   *flow.Session
	raw      *flow.Session
	rawConn  *tcpraw.Conn
	obs      *tcpraw.Observer
	peerIP   netip.Addr
	started  time.Time
}

// Engine orchestrates discovery, sessions, capture, probes and reporting.
type Engine struct {
	opts      Options
	id        string
	host      string
	ip        netip.Addr
	dm        *discovery.Manager
	dmx       *tcpraw.Demux
	eng       packetio.Engine
	ln        net.Listener
	shields   []net.Listener
	pcap      *PCAPWriter
	pcapFlt   *PCAPFilter
	kd        *kernelstat.Differ
	kbase     map[string]uint64
	probeS    *probe.Server
	tcpProbeS *probe.TCPServer

	mu         sync.Mutex
	sets       map[string]*sessionSet
	stop       chan struct{}
	logf       func(string, ...any)
	out        io.Writer
	start      time.Time
	probeNotes []string

	rawErr      map[string]string
	rawAttempts map[string]int
}

// New builds an Engine.
func New(o Options) *Engine {
	if o.Name == "" {
		o.Name, _ = os.Hostname()
	}
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = 5 * time.Second
	}
	if o.ConnectAttempts <= 0 {
		o.ConnectAttempts = 10
	}
	if o.ProbeTCPConnections <= 0 {
		o.ProbeTCPConnections = 10
	}
	if o.ProbeTCPBytes <= 0 {
		o.ProbeTCPBytes = 4 << 20
	}
	if o.ProbeTCPTimeout <= 0 {
		o.ProbeTCPTimeout = 10 * time.Second
	}
	h := sha256.Sum256([]byte(o.Name + "|" + o.LocalIP + "|" + strconv.Itoa(o.DataPort)))
	e := &Engine{
		opts:  o,
		id:    hex.EncodeToString(h[:6]),
		host:  o.Name,
		sets:  map[string]*sessionSet{},
		stop:  make(chan struct{}),
		out:   os.Stdout,
		start: time.Now(),

		rawErr:      map[string]string{},
		rawAttempts: map[string]int{},
	}
	e.logf = func(f string, v ...any) {
		if o.Verbose {
			fmt.Fprintf(e.out, "[%s] "+f+"\n", append([]any{time.Since(e.start).Round(time.Millisecond)}, v...)...)
		}
	}
	return e
}

// PeerID is this instance's stable identity.
func (e *Engine) PeerID() string { return e.id }

// primaryIPv4 picks the address used for raw packets and discovery.
func primaryIPv4(preferred string) (netip.Addr, error) {
	if preferred != "" {
		a, err := netip.ParseAddr(preferred)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("--local-ip: %w", err)
		}
		return a, nil
	}
	caddrs, err := localIPv4s()
	if err != nil {
		return netip.Addr{}, err
	}
	if len(caddrs) == 0 {
		return netip.Addr{}, fmt.Errorf("no IPv4 address found; pass --local-ip")
	}
	// The address the kernel would use for the default route is the one that
	// actually reaches the LAN. Picking "the first non-link-local address"
	// instead makes Tailscale, ZeroTier, Hyper-V, WSL and VPN adapters win, and
	// then every session dials an address that is unreachable from peers.
	if dr, ok := defaultRouteSource(); ok {
		for _, c := range caddrs {
			if c.addr == dr {
				return c.addr, nil
			}
		}
	}
	// Fall back to a scored preference.
	var best *localAddr
	for i := range caddrs {
		c := caddrs[i]
		if best == nil || c.score() > best.score() {
			best = &c
		}
	}
	return best.addr, nil
}

// localAddr is one candidate source address with its adapter.
type localAddr struct {
	addr     netip.Addr
	iface    string
	nameRank int // tiebreak: physical-looking adapter names first
}

// score ranks candidates: real LAN adapters over VPN/CGNAT/virtual ones.
func (c localAddr) score() int {
	s := 100 + c.nameRank
	lower := strings.ToLower(c.iface)
	switch {
	case strings.Contains(lower, "tailscale"), strings.Contains(lower, "zerotier"),
		strings.Contains(lower, "warp"), strings.Contains(lower, "tap"),
		strings.Contains(lower, "tun"), strings.Contains(lower, "vpn"):
		s -= 60
	case strings.Contains(lower, "vEthernet") || strings.Contains(lower, "hyper-v") ||
		strings.Contains(lower, "wsl") || strings.Contains(lower, "docker") ||
		strings.Contains(lower, "loopback") || strings.Contains(lower, "loopback adapter"):
		s -= 50
	}
	// Carrier-grade NAT and APIPA ranges are almost never the right answer.
	if isCGNAT(c.addr) || c.addr.IsLinkLocalUnicast() {
		s -= 40
	}
	return s
}

func isCGNAT(a netip.Addr) bool {
	if !a.Is4() {
		return false
	}
	b := a.As4()
	return b[0] == 100 && b[1] >= 64 && b[1] <= 127
}

func localIPv4s() ([]localAddr, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []localAddr
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, ad := range addrs {
			n, ok := ad.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := n.IP.To4()
			if v4 == nil {
				continue
			}
			a, ok := netip.AddrFromSlice(v4)
			if !ok {
				continue
			}
			out = append(out, localAddr{addr: a, iface: ifi.Name})
		}
	}
	return out, nil
}

// defaultRouteSource asks the kernel which source address it would use for the
// default route. A UDP "dial" performs a routing lookup without transmitting a
// single packet.
func defaultRouteSource() (netip.Addr, bool) {
	for _, probe := range []string{"8.8.8.8:53", "1.1.1.1:53", "239.255.42.99:1"} {
		conn, err := net.Dial("udp4", probe)
		if err != nil {
			continue
		}
		ua, ok := conn.LocalAddr().(*net.UDPAddr)
		_ = conn.Close()
		if !ok {
			continue
		}
		if a, ok := netip.AddrFromSlice(ua.IP.To4()); ok && a.Is4() && !a.IsUnspecified() {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// Start brings everything up and blocks until the run completes.
func (e *Engine) Start() error {
	o := e.opts
	if o.ProbeTCP || o.ExitAfterProbes {
		o.DoProbe = true
	}
	ip, err := primaryIPv4(o.LocalIP)
	if err != nil {
		return err
	}
	e.ip = ip
	e.printLocalBinding()
	e.kd = kernelstat.NewDiffer(kernelstat.New())
	e.kbase = e.kd.Delta()

	wantRaw := o.Stack == "raw" || o.Stack == "both" || o.Stack == "observe"
	// A capture requested on the kernel stack is still useful: open the packet
	// backend in capture-only mode and attach the passive analyser, rather than
	// silently accepting --pcap and writing no file at all.
	wantCapture := wantRaw || o.PCAP != ""
	if wantCapture {
		im, err := packetio.ParseImpairment(o.Impair)
		if err != nil {
			return err
		}
		eng, err := packetio.Open(packetio.Options{Backend: o.Backend, LocalIP: ip, IfaceName: o.Iface})
		if err != nil {
			if o.Stack == "raw" {
				return fmt.Errorf("raw stack requested but the packet engine failed: %w", err)
			}
			if o.PCAP != "" {
				fmt.Fprintf(e.out, "note: no capture file will be written: the packet backend is unavailable (%v)\n", err)
			}
			if wantRaw {
				fmt.Fprintf(e.out, "note: raw engine unavailable (%v); continuing with the kernel stack only\n", err)
			}
		} else {
			if im.Enabled() && wantRaw {
				eng = packetio.WithImpairment(eng, im)
				fmt.Fprintf(e.out, "impairment active: %s\n", im)
			}
			if (o.Stack == "raw" || o.Stack == "both") && !eng.Injectable() {
				detail := strings.Join(eng.Capabilities(), "; ")
				if o.Stack == "raw" {
					_ = eng.Close()
					return fmt.Errorf("raw stack requires packet injection, but %s is capture-only: %s", eng.Name(), detail)
				}
				fmt.Fprintf(e.out, "note: raw stack disabled because %s cannot inject packets; continuing with the kernel stack only (%s)\n", eng.Name(), detail)
			}
			e.eng = eng
			e.dmx = tcpraw.NewDemux(eng)
			// Mark the ports tcpdiag uses itself, so its beacons and probe
			// packets are reported separately from the traffic under test.
			e.dmx.SetControlPorts([]uint16{
				uint16(o.DiscoveryPort), uint16(o.ProbePort), uint16(o.DataPort),
				uint16(o.RawPort), uint16(o.RawPort + 1), uint16(o.TCPProbePort),
			})
			if wantRaw {
				e.shieldRawPorts()
			}
			for _, c := range eng.Capabilities() {
				e.logf("engine %s: %s", eng.Name(), c)
			}
			if o.PCAP != "" {
				dlt := DLTRaw
				if strings.EqualFold(o.PCAPDLT, "ethernet") || strings.EqualFold(o.PCAPDLT, "eth") {
					dlt = DLTEther
				}
				p, err := OpenPCAP(o.PCAP, dlt)
				if err != nil {
					return fmt.Errorf("pcap: %w", err)
				}
				if !o.PCAPAll {
					f := NewPCAPFilter([]uint16{
						uint16(o.DataPort), uint16(o.RawPort), uint16(o.RawPort + 1),
						uint16(o.ProbePort), uint16(o.DiscoveryPort), uint16(o.PeerRawPort),
						uint16(o.TCPProbePort), uint16(o.PeerTCPProbePort),
					})
					e.mu.Lock()
					e.pcapFlt = f
					e.mu.Unlock()
					p.SetFilter(f)
				}
				e.pcap = p
				e.dmx.RegisterPackets(func(pk *packetio.Packet) {
					_ = p.WriteCaptured(pk.Buf, time.Unix(0, pk.NanoAt))
				})
				// SIO_RCVALL does not reliably hand locally injected raw-socket
				// packets back to the capture loop. Write what we built so the
				// file still contains tcpdiag's own TCP, not just UDP control
				// traffic.
				e.dmx.RegisterInjected(func(pk *packetio.Packet) {
					_ = p.WriteInjected(pk.Buf, time.Unix(0, pk.NanoAt))
				})
				if o.PCAPAll {
					fmt.Fprintf(e.out, "writing capture to %s (link type %s, ALL host traffic)\n", o.PCAP, o.PCAPDLT)
				} else {
					fmt.Fprintf(e.out, "writing capture to %s (link type %s, tcpdiag flows only; --pcap-all for everything)\n", o.PCAP, o.PCAPDLT)
				}
			}
		}
	}

	if o.Stack != "raw" {
		bind := o.Bind
		if bind == "" {
			bind = "0.0.0.0"
		}
		ln, err := net.Listen("tcp4", net.JoinHostPort(bind, strconv.Itoa(o.DataPort)))
		if err != nil {
			// Not fatal: a pure dialer never needs to accept; it simply cannot be
			// dialled by another node, so discovery-driven sessions may be one-sided.
			fmt.Fprintf(e.out, "note: cannot listen on tcp/%d (%v); this instance can only dial out\n", o.DataPort, err)
		} else {
			e.ln = ln
			go e.acceptLoop()
		}
	}

	if ps, err := probe.StartServerOn(o.Bind, o.ProbePort); err != nil {
		fmt.Fprintf(e.out, "note: probe server not started: %v\n", err)
	} else {
		e.probeS = ps
	}
	if o.TCPProbePort > 0 {
		if ts, err := probe.StartTCPServerOn(o.Bind, o.TCPProbePort); err != nil {
			fmt.Fprintf(e.out, "note: TCP probe server not started: %v\n", err)
		} else {
			e.tcpProbeS = ts
		}
	}

	if o.HTTP != "" {
		go e.serveHTTP()
	}

	if o.Discover && o.Peer == "" {
		dm, err := discovery.Start(discovery.Options{
			Port:    o.DiscoveryPort,
			Group:   o.Multicast,
			ID:      e.id,
			Name:    o.Name,
			Version: o.Version,
			Self:    e.selfAnnounce,
			Logf:    e.timestamped,
			OnAdd:   e.HandlePeer,
		})
		if err != nil {
			return fmt.Errorf("discovery: %w", err)
		}
		e.dm = dm
	}

	if o.DoProbe {
		go e.probeWhenReady(ip)
	}

	if o.Peer != "" {
		if err := e.addExplicitPeer(o.Peer); err != nil {
			return err
		}
	}

	if o.Duration > 0 {
		go func() {
			time.Sleep(o.Duration)
			e.Stop()
		}()
	}

	e.statusLoop()
	return nil
}

func (e *Engine) timestamped(f string, v ...any) {
	fmt.Fprintf(e.out, "[%s] "+f+"\n", append([]any{time.Since(e.start).Round(time.Millisecond)}, v...)...)
}

func (e *Engine) selfAnnounce() discovery.Announce {
	tcpProbePort := 0
	if e.tcpProbeS != nil {
		tcpProbePort = e.opts.TCPProbePort
	}
	return discovery.Announce{
		ID:           e.id,
		Name:         e.opts.Name,
		Version:      e.opts.Version,
		Stack:        e.opts.Stack,
		TCPAddr:      net.JoinHostPort(e.ip.String(), strconv.Itoa(e.opts.DataPort)),
		RawIP:        e.ip.String(),
		RawPort:      e.opts.RawPort,
		IPs:          allIPv4(),
		ProbePort:    e.opts.ProbePort,
		TCPProbePort: tcpProbePort,
		Boot:         e.start.Unix(),
		Hostname:     e.host,
	}
}

// ---------------------------------------------------------------------------
// Kernel data plane
// ---------------------------------------------------------------------------

func (e *Engine) acceptLoop() {
	for {
		c, err := e.ln.Accept()
		if err != nil {
			select {
			case <-e.stop:
				return
			default:
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go e.adoptKernelConn(c, false)
	}
}

func (e *Engine) kernelPipe(c net.Conn) flow.Pipe {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return c
	}
	_ = tc.SetNoDelay(e.opts.NoDelay)
	if e.opts.RcvBuf > 0 {
		_ = tc.SetReadBuffer(e.opts.RcvBuf)
	}
	if e.opts.SndBuf > 0 {
		_ = tc.SetWriteBuffer(e.opts.SndBuf)
	}
	return tc
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

func (e *Engine) newFlowConfig(peerID, peerName, stack string, dialer bool) flow.Config {
	o := e.opts
	seed := sha256.Sum256([]byte("tcpdiag-session|" + sortedPair(e.id, peerID) + "|" + strconv.Itoa(o.DataPort)))
	cfg := flow.Config{
		SessionID:  hex.EncodeToString(seed[:8]),
		LocalID:    e.id,
		LocalName:  o.Name,
		PeerID:     peerID,
		PeerName:   peerName,
		Stack:      stack,
		IsDialer:   dialer,
		BlockSize:  o.BlockSize,
		RateMbps:   o.RateMbps,
		TotalBytes: o.TotalBytes,
		Duration:   o.Duration,
		Seed:       seed[:],
		Version:    o.Version,
		OSName:     runtime.GOOS,
		Arch:       runtime.GOARCH,
		Iface:      o.Iface,
		Features:   []string{"causal-chain", "embedded-telemetry", "app-rtt"},
		Logf:       e.logf,
	}
	if o.Feed != "" {
		data, err := loadFeed(o.Feed)
		if err != nil || len(data) == 0 {
			fmt.Fprintf(e.out, "note: --feed %s unusable (%v); using synthetic data\n", o.Feed, err)
		} else {
			seedCopy := append([]byte{}, seed[:]...)
			// Real data on the wire, still bound to the causal chain: each block
			// is a file slice XORed with the receive-history keystream, so a
			// payload that verifies still proves what the sender had received.
			// Both sides must be given the same --feed input.
			cfg.PayloadFor = func(blockSeq uint64, n int, rd [wire.DigestSize]byte) []byte {
				out := make([]byte, n)
				ks := make([]byte, n)
				wire.Keystream(seedCopy, blockSeq, rd, ks)
				dl := uint64(len(data))
				base := (blockSeq * uint64(n)) % dl
				for i := 0; i < n; i++ {
					out[i] = data[(base+uint64(i))%dl] ^ ks[i]
				}
				return out
			}
			cfg.Features = append(cfg.Features, "feed="+o.Feed)
		}
	}
	return cfg
}

// loadFeed reads a file, or every file in a directory, into one byte slice.
func loadFeed(path string) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return os.ReadFile(path)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, en := range entries {
		if !en.IsDir() {
			names = append(names, en.Name())
		}
	}
	sort.Strings(names)
	var acc []byte
	for _, nm := range names {
		b, err := os.ReadFile(filepath.Join(path, nm))
		if err != nil {
			continue
		}
		acc = append(acc, b...)
		if len(acc) > 128<<20 {
			break
		}
	}
	if len(acc) == 0 {
		return nil, fmt.Errorf("directory %s has no readable files", path)
	}
	return acc, nil
}

func sortedPair(a, b string) string {
	if a < b {
		return a + "+" + b
	}
	return b + "+" + a
}

func (e *Engine) adoptKernelConn(c net.Conn, dialer bool) {
	pipe := e.kernelPipe(c)
	cfg := e.newFlowConfig("unknown", "unknown", "kernel", dialer)
	// If a raw engine is available, attach a passive analyser to this kernel
	// connection. It reconstructs dup-ACK / fast-retransmit / spurious-
	// retransmission events from sequence numbers on the wire, so the kernel's
	// behaviour can be judged without a second capture point and without
	// WinPcap/Npcap.
	var obs *tcpraw.Observer
	if e.dmx != nil {
		if la, ok := c.LocalAddr().(*net.TCPAddr); ok {
			if ra, ok2 := c.RemoteAddr().(*net.TCPAddr); ok2 {
				la4, okA := netip.AddrFromSlice(la.IP.To4())
				ra4, okB := netip.AddrFromSlice(ra.IP.To4())
				if okA && okB {
					obs = tcpraw.NewObserver(e.dmx, tcpraw.Key{
						A: la4, B: ra4, APort: uint16(la.Port), BPort: uint16(ra.Port),
					}, "kernel-wire")
					e.logf("observing kernel connection %s:%d <-> %s:%d", la4, la.Port, ra4, ra.Port)
				}
			}
		}
	}
	cfg.Providers = []func(*wire.Snapshot){e.kernelProvider(nil, obs)}
	if e.opts.Stack == "observe" {
		cfg.RateMbps = 0.05 // keepalive-level traffic; the point is analysis, not throughput
	}
	s := flow.New(pipe, cfg)
	if err := s.Start(); err != nil {
		fmt.Fprintf(e.out, "kernel session failed: %v\n", err)
		_ = c.Close()
		return
	}
	// The handshake told us who the peer is; adopt that identity and attach the
	// counter providers now that both ends agree.
	// The handshake replaced the placeholder identity with the real one, so key
	// the session on what the peer actually told us.
	pid, pname := s.PeerID(), s.PeerName()
	e.mu.Lock()
	set := e.sets[pid]
	if set == nil {
		set = &sessionSet{peerID: pid, peerName: pname, started: time.Now()}
		e.sets[pid] = set
	}
	if set.peerIP == (netip.Addr{}) {
		if ra, ok := c.RemoteAddr().(*net.TCPAddr); ok {
			if a, ok2 := netip.AddrFromSlice(ra.IP.To4()); ok2 {
				set.peerIP = a
			}
		}
	}
	set.kernel, set.obs = s, obs
	e.mu.Unlock()
	e.logf("kernel session started with %s (%s)", pname, pid)
}

// kernelProvider fills stack-specific counters into the snapshot that rides
// inside every block, so the far side can diagnose without local access.
func (e *Engine) kernelProvider(raw *tcpraw.Conn, obs *tcpraw.Observer) func(*wire.Snapshot) {
	return func(s *wire.Snapshot) {
		if raw != nil {
			s.Add(raw.Snapshot())
		}
		if obs != nil {
			s.Add(obs.Snapshot())
		}
		// Oversized captured packets are evidence of NIC receive offload, which
		// corrupts exactly the annotations this tool is asked about.
		if e.dmx != nil {
			if big, maxLen := e.dmx.Offload(); big > 0 {
				if s.Kernel == nil {
					s.Kernel = map[string]uint64{}
				}
				s.Kernel["offload_coalesced_segments"] = big
				s.Kernel["offload_max_segment_bytes"] = uint64(maxLen)
			}
		}
		d := e.kd.Delta()
		if len(d) == 0 {
			return
		}
		if s.Kernel == nil {
			s.Kernel = map[string]uint64{}
		}
		for k, v := range d {
			s.Kernel[k] = v
		}
		// When we are not running our own stack, the OS is the only witness:
		// attribute its retransmits to this side so direction can still be
		// reasoned about.
		if raw == nil && s.RetransSent == 0 {
			for _, k := range []string{"win_tcp_retrans_segs", "tcp_retranssegs", "tcp_retrans_segs"} {
				if v, ok := d[k]; ok && v >= e.kbase[k] {
					s.RetransSent += v - e.kbase[k]
					break
				}
			}
		}
	}
}

func (e *Engine) rawConfig(dialer bool, peerIP netip.Addr, peerRawPort int) tcpraw.Config {
	o := e.opts
	cfg := tcpraw.DefaultConfig()
	cfg.RcvBuf, cfg.SndBuf = o.RcvBuf, o.SndBuf
	cfg.MSS = o.MSS
	cfg.MinRTO, cfg.MaxRTO = o.MinRTO, o.MaxRTO
	cfg.DelayedACK = o.DelayedACK
	cfg.Timestamps = o.Timestamps
	cfg.SACK = o.SACK
	cfg.HandshakeTimeout = o.ConnectTimeout
	cfg.TTL = uint8(o.TTL)
	cfg.TOS = uint8(o.TOS)
	cfg.Logf = e.logf
	cfg.LocalIP = e.ip
	cfg.RemoteIP = peerIP
	if peerRawPort <= 0 {
		peerRawPort = o.RawPort
	}
	if dialer {
		cfg.LocalPort, cfg.RemotePort = uint16(o.RawPort+1), uint16(peerRawPort)
	} else {
		cfg.LocalPort, cfg.RemotePort = uint16(o.RawPort), uint16(peerRawPort+1)
	}
	return cfg
}

func (e *Engine) startRawSession(peerID, peerName string, peerIP netip.Addr, peerRawPort int, dialer bool) error {
	if e.dmx == nil {
		return fmt.Errorf("raw engine not available")
	}
	if e.eng == nil || !e.eng.Injectable() {
		return fmt.Errorf("raw TCP injection is unavailable on this host")
	}
	e.mu.Lock()
	e.rawAttempts[peerID]++
	e.mu.Unlock()
	cfg := e.rawConfig(dialer, peerIP, peerRawPort)
	var conn *tcpraw.Conn
	var err error
	if dialer {
		conn, err = tcpraw.Dial(e.dmx, cfg)
	} else {
		conn, err = tcpraw.Listen(e.dmx, cfg).Accept()
	}
	if err != nil {
		err = fmt.Errorf("raw connect: %w", err)
		e.mu.Lock()
		e.rawErr[peerID] = err.Error()
		e.mu.Unlock()
		return err
	}
	fcfg := e.newFlowConfig(peerID, peerName, "raw", dialer)
	fcfg.Providers = []func(*wire.Snapshot){e.kernelProvider(conn, nil)}
	s := flow.New(conn, fcfg)
	if err := s.Start(); err != nil {
		_ = conn.Close()
		err = fmt.Errorf("raw flow: %w", err)
		e.mu.Lock()
		e.rawErr[peerID] = err.Error()
		e.mu.Unlock()
		return err
	}
	e.mu.Lock()
	set := e.sets[peerID]
	if set == nil {
		set = &sessionSet{peerID: peerID, peerName: peerName, started: time.Now(), peerIP: peerIP}
	}
	set.raw, set.rawConn = s, conn
	set.peerIP = peerIP
	e.sets[peerID] = set
	delete(e.rawErr, peerID)
	e.mu.Unlock()
	fmt.Fprintf(e.out, "raw session established with %s (%s) over %s\n", peerName, peerIP, e.eng.Name())
	return nil
}

// ---------------------------------------------------------------------------
// Peers
// ---------------------------------------------------------------------------

func (e *Engine) addExplicitPeer(target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("--peer expects host:port: %w", err)
	}
	port, _ := strconv.Atoi(portStr)
	ip, err := netip.ParseAddr(host)
	if err != nil {
		addrs, err2 := net.LookupHost(host)
		if err2 != nil || len(addrs) == 0 {
			return fmt.Errorf("cannot resolve %q", host)
		}
		ip, _ = netip.ParseAddr(addrs[0])
	}
	pid := "static-" + host
	pname := "peer@" + host
	e.mu.Lock()
	e.sets[pid] = &sessionSet{peerID: pid, peerName: pname, peerIP: ip, started: time.Now()}
	e.mu.Unlock()
	e.addCapturePorts(port, e.opts.PeerRawPort, e.opts.PeerRawPort+1, e.opts.ProbePort,
		e.opts.PeerTCPProbePort, e.opts.TCPProbePort)

	peerKernel := e.opts.PeerStack == "" || discovery.StackHasKernel(e.opts.PeerStack)
	peerRaw := e.opts.PeerStack == "" || discovery.StackHasRaw(e.opts.PeerStack)
	if !discovery.StacksCompatible(e.opts.Stack, e.opts.PeerStack) {
		fmt.Fprintf(e.out, "stack mismatch: local=%s peer=%s (%s); these modes share no data plane. Pass --peer-stack or run matching modes.\n",
			e.opts.Stack, target, e.opts.PeerStack)
	}
	if e.opts.Stack != "raw" && peerKernel {
		go func() {
			c, err := net.DialTimeout("tcp4", net.JoinHostPort(host, strconv.Itoa(port)), e.opts.ConnectTimeout)
			if err != nil {
				fmt.Fprintf(e.out, "dial %s failed: %v\n", target, err)
				return
			}
			e.adoptKernelConn(c, true)
		}()
	}
	if (e.opts.Stack == "raw" || e.opts.Stack == "both") && peerRaw && e.eng != nil && e.eng.Injectable() {
		go func() {
			rawPort := e.opts.PeerRawPort
			if rawPort <= 0 {
				rawPort = e.opts.RawPort
			}
			rawTarget := net.JoinHostPort(ip.String(), strconv.Itoa(rawPort))
			var lastErr error
			for attempt := 0; attempt < e.opts.ConnectAttempts; attempt++ {
				if err := e.startRawSession(pid, pname, ip, e.opts.PeerRawPort, true); err == nil {
					return
				} else {
					lastErr = err
					e.logf("raw dial attempt %d: %v", attempt, err)
				}
				time.Sleep(time.Second)
			}
			fmt.Fprintf(e.out, "raw session to %s never came up after %d attempt(s): %v\n", rawTarget, e.opts.ConnectAttempts, lastErr)
		}()
	}
	return nil
}

// addCapturePorts extends the pcap filter with a discovered peer's advertised
// ports. Without this, a peer using non-default ports would be filtered out of
// the very capture meant to document the session.
func (e *Engine) addCapturePorts(ports ...int) {
	e.mu.Lock()
	f := e.pcapFlt
	e.mu.Unlock()
	if f == nil {
		return
	}
	var ps []uint16
	for _, p := range ports {
		if p > 0 {
			ps = append(ps, uint16(p))
		}
	}
	f.AddPorts(ps...)
}

// HandlePeer starts sessions for a discovered peer.
func (e *Engine) HandlePeer(p *discovery.Peer) {
	e.mu.Lock()
	if _, ok := e.sets[p.ID]; ok {
		e.mu.Unlock()
		return
	}
	e.sets[p.ID] = &sessionSet{peerID: p.ID, peerName: p.Name, started: time.Now()}
	e.mu.Unlock()

	dialer := p.ShouldDial(e.id)
	peerKernel := p.Stack == "" || discovery.StackHasKernel(p.Stack)
	peerRaw := p.Stack == "" || discovery.StackHasRaw(p.Stack)
	if !discovery.StacksCompatible(e.opts.Stack, p.Stack) {
		fmt.Fprintf(e.out, "stack mismatch: local=%s peer=%s (%s, tcp=%s raw=%s:%d); these modes share no data plane. Run raw on both ends, or use kernel/both consistently.\n",
			e.opts.Stack, p.Name, p.Stack, p.TCPAddr, p.RawIP, p.RawPort)
	}
	// Dial the address discovery proved reachable, not whichever address the
	// peer happened to advertise first: on a host with Hyper-V, WSL or VPN
	// adapters the advertised one is frequently unreachable from the LAN.
	ip, err := netip.ParseAddr(p.DataIP)
	if err != nil || !ip.Is4() {
		ip = p.Via
	}
	if !ip.Is4() {
		fmt.Fprintf(e.out, "peer %s has no usable IPv4 address (advertised %v)\n", p.Name, p.IPs)
		return
	}
	target := net.JoinHostPort(ip.String(), strconv.Itoa(p.DataPort))
	e.mu.Lock()
	e.sets[p.ID].peerIP = ip
	e.mu.Unlock()
	e.addCapturePorts(p.DataPort, p.RawPort, p.RawPort+1, p.ProbePort, p.TCPProbePort)

	if e.opts.Stack != "raw" && dialer && peerKernel {
		go func() {
			var lastErr error
			for attempt := 0; attempt < e.opts.ConnectAttempts; attempt++ {
				c, err := net.DialTimeout("tcp4", target, e.opts.ConnectTimeout)
				if err == nil {
					e.adoptKernelConn(c, true)
					return
				}
				lastErr = err
				if attempt == 0 || attempt%5 == 4 {
					fmt.Fprintf(e.out, "cannot reach %s (%v); retrying\n", target, err)
				}
				time.Sleep(time.Second)
			}
			fmt.Fprintf(e.out, "could not connect to %s after %d attempt(s): %v\n", target, e.opts.ConnectAttempts, lastErr)
		}()
	}
	if (e.opts.Stack == "raw" || e.opts.Stack == "both") && peerRaw && e.eng != nil && e.eng.Injectable() {
		go func() {
			rawPort := p.RawPort
			if rawPort <= 0 {
				rawPort = e.opts.RawPort
			}
			rawTarget := net.JoinHostPort(ip.String(), strconv.Itoa(rawPort))
			var lastErr error
			for attempt := 0; attempt < e.opts.ConnectAttempts; attempt++ {
				if err := e.startRawSession(p.ID, p.Name, ip, p.RawPort, dialer); err == nil {
					return
				} else {
					lastErr = err
					e.logf("raw session attempt %d: %v", attempt, err)
				}
				time.Sleep(time.Second)
			}
			fmt.Fprintf(e.out, "raw session to %s never came up after %d attempt(s): %v\n", rawTarget, e.opts.ConnectAttempts, lastErr)
		}()
	}
}

// ---------------------------------------------------------------------------
// Status, probes, HTTP
// ---------------------------------------------------------------------------

func (e *Engine) statusLoop() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			e.shutdown()
			return
		case <-t.C:
			e.printStatus()
			e.updateBeacon()
		}
	}
}

// updateBeacon stops advertising once the peers it needs are connected. The
// beacons are LAN-wide background noise and clutter every capture, so they
// continue only until sessions exist, or forever with --keep-advertising.
func (e *Engine) updateBeacon() {
	if e.dm == nil {
		return
	}
	e.dm.SetAlwaysAdvertise(e.opts.KeepAdvertising)
	e.dm.SetQuiet(!e.opts.KeepAdvertising && e.hasSessions())
}

// hasSessions reports whether at least one direction is actually established.
func (e *Engine) hasSessions() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	// A session only counts while it is actually exchanging data: if the stream
	// stalls we must start beaconing again so a restarting peer can find us.
	fresh := time.Now().Add(-15 * time.Second)
	for _, s := range e.sets {
		for _, x := range []*flow.Session{s.kernel, s.raw} {
			if x != nil && x.LastActivity().After(fresh) {
				return true
			}
		}
	}
	return false
}

func (e *Engine) printStatus() {
	e.mu.Lock()
	sets := make([]*sessionSet, 0, len(e.sets))
	for _, s := range e.sets {
		sets = append(sets, s)
	}
	e.mu.Unlock()

	if len(sets) == 0 {
		peers := 0
		if e.dm != nil {
			peers = len(e.dm.Peers())
		}
		fmt.Fprintf(e.out, "[%4ds] waiting for a peer (discovered=%d) stack=%s\n",
			int(time.Since(e.start).Seconds()), peers, e.opts.Stack)
		return
	}
	for _, s := range sets {
		parts := make([]string, 0, 2)
		if s.kernel != nil {
			parts = append(parts, describe("kern", s.kernel))
		}
		if s.raw != nil {
			parts = append(parts, describe("raw ", s.raw))
		}
		if len(parts) == 0 {
			continue
		}
		fmt.Fprintf(e.out, "[%4ds] %s -> %s\n", int(time.Since(e.start).Seconds()), s.peerName, strings.Join(parts, " | "))
	}
}

func describe(tag string, x *flow.Session) string {
	ls := x.LocalSnapshot()
	// Fixed field widths and right-aligned numbers so successive status lines
	// line up in columns instead of shifting as the values grow.
	return fmt.Sprintf("%s %6s/%6s Mb/s  %8s %8s  rtx %6s  fast %5s  rto %5s  spur %5s  dupack %6s  missing %6s  ooo %5s  late %5s  rtt %7.2f ms",
		tag, padNum(ls.MbpsSent, 6), padNum(ls.MbpsRecv, 6),
		"tx "+padU(ls.BytesSent, 10), "rx "+padU(ls.BytesRecv, 10),
		num(ls.RetransSent), num(ls.FastRetrans), num(ls.RtoRetrans), num(ls.SpuriousRetrans),
		num(ls.DupAcksRecv), num(ls.BlocksMissing), num(ls.OooSegs), num(ls.BlocksLate), ls.AckLatencyMs)
}

// probeWhenReady waits for a peer to exist before measuring. Probes need a
// responder on the far side, and at startup the peer may not have been
// discovered yet (or, with --peer, registered yet), so measuring immediately
// would only report "no peer known".
func (e *Engine) probeWhenReady(ip netip.Addr) {
	defer func() {
		if e.opts.ExitAfterProbes {
			e.Stop()
		}
	}()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if e.peerAddr() != (netip.Addr{}) {
			// Let the session settle so the probes describe a steady-state path
			// rather than a half-open connection.
			time.Sleep(500 * time.Millisecond)
			e.runProbes(ip)
			return
		}
		select {
		case <-e.stop:
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
	fmt.Fprintln(e.out, "probes skipped: no peer appeared")
}

// probePortFor returns the UDP echo port the peer advertised, falling back to
// the locally configured one for peers given with --peer.
func (e *Engine) probePortFor(addr netip.Addr) int {
	if e.dm != nil {
		for _, p := range e.dm.Peers() {
			if (p.RawIP == addr.String() || p.DataIP == addr.String() || p.Via.String() == addr.String()) && p.ProbePort > 0 {
				return p.ProbePort
			}
		}
	}
	return e.opts.ProbePort
}

func num(v uint64) string { return strconv.FormatUint(v, 10) }

// padU right-aligns an integer within w columns, so a growing counter cannot
// shift every field that follows it on the status line.
func padU(v uint64, w int) string {
	s := strconv.FormatUint(v, 10)
	for dwidth(s) < w {
		s = " " + s
	}
	return s
}

// padNum right-aligns a float so numeric columns stay aligned as magnitudes
// change.
func padNum(v float64, w int) string {
	s := strconv.FormatFloat(v, 'f', 1, 64)
	for dwidth(s) < w {
		s = " " + s
	}
	return s
}

func dwidth(s string) int { return utf8.RuneCountInString(s) }

func (e *Engine) runProbes(ip netip.Addr) {
	target := e.peerAddr()
	if target == (netip.Addr{}) {
		fmt.Fprintf(e.out, "probes skipped: no peer known yet\n")
		return
	}
	c, err := probe.NewClient(0)
	if err != nil {
		fmt.Fprintf(e.out, "probe client: %v\n", err)
		return
	}
	defer c.Close()
	fmt.Fprintf(e.out, "\n=== active probes against %s ===\n", target)
	pp := e.probePortFor(target)
	base := c.RTT(target, pp,
		probe.Count(e.opts.ProbeCount), probe.Size(64), probe.Interval(20*time.Millisecond))
	e.emitProbe(base)
	if e.opts.ProbeTCP {
		tcpPort := e.tcpProbePortFor(target)
		if tcpPort <= 0 {
			e.noteProbe("tcp probes SKIPPED: no TCP probe port configured")
		} else {
			addr := net.JoinHostPort(target.String(), strconv.Itoa(tcpPort))
			fmt.Fprintf(e.out, "--- TCP transmission probes against %s ---\n", addr)
			e.emitProbe(probe.TCPHandshake(addr, e.opts.ProbeTCPConnections, 50*time.Millisecond, e.opts.ProbeTCPTimeout))
			e.emitProbe(probe.TCPEcho(addr, "tcp-echo", e.opts.ProbeCount, 64, 20*time.Millisecond, e.opts.ProbeTCPTimeout, e.opts.ProbeTCPNoDelay))
			if e.opts.ProbeTCPSmall > 0 {
				e.emitProbe(probe.TCPEcho(addr, "tcp-small", e.opts.ProbeTCPSmall, 1, 0, e.opts.ProbeTCPTimeout, e.opts.ProbeTCPNoDelay))
			}
			if e.opts.ProbeTCPBytes > 0 {
				e.emitProbe(probe.TCPTransfer(addr, "tcp-upload", e.opts.ProbeTCPBytes, true, e.opts.ProbeTCPTimeout, e.opts.ProbeTCPNoDelay))
				e.emitProbe(probe.TCPTransfer(addr, "tcp-download", e.opts.ProbeTCPBytes, false, e.opts.ProbeTCPTimeout, e.opts.ProbeTCPNoDelay))
				e.emitProbe(probe.TCPDuplex(addr, e.opts.ProbeTCPBytes, e.opts.ProbeTCPTimeout, e.opts.ProbeTCPNoDelay))
			}
		}
	}
	if e.opts.ProbeSweep {
		for _, res := range c.LossSweep(target, pp, []float64{1, 5, 20, 50, 100, 200, 500}, 200, 1024) {
			if !res.OK && base.Received > 0 {
				// The idle path already answered, so this is a dropped burst,
				// not an unreachable host.
				res.OK = true
				res.Note = "no replies at this offered rate, although the idle udp-echo baseline worked: the burst was dropped on the path or by the receiver"
			}
			e.emitProbe(res)
		}
	}
	if ep := e.peerEndpoint(); ep != "" {
		e.emitProbe(probe.Handshake(ep, 20, 50*time.Millisecond))
	} else {
		e.noteProbe("%-16s %-22s SKIPPED: peer advertises no kernel TCP listener (raw-only); the raw session status above is the handshake measurement",
			"tcp-connect", target)
	}
	if e.opts.ProbeMTU {
		r := probe.PathMTU(target, pp)
		e.emitProbe(r)
		for _, d := range r.Details {
			e.noteProbe("  %s", d)
		}
	}
	if e.opts.ProbeTTL && e.dmx != nil {
		hops, note := probe.TTLWalk(e.dmx, ip, target, uint16(e.opts.RawPort), 12, 5)
		for _, h := range hops {
			e.noteProbe("ttl=%2d %-15s sent=%d replied=%d loss=%5.1f%% %s", h.TTL, h.Router, h.Sent, h.Replied, h.LossPct, h.Note)
		}
		e.noteProbe("ttl-walk: %s", note)
	}
	fmt.Fprintln(e.out, "=== end probes ===")
}

func (e *Engine) noteProbe(format string, args ...any) string {
	line := fmt.Sprintf(format, args...)
	fmt.Fprintln(e.out, line)
	e.mu.Lock()
	e.probeNotes = append(e.probeNotes, line)
	e.mu.Unlock()
	return line
}

func (e *Engine) emitProbe(r probe.Result) { e.noteProbe("%s", r.String()) }

// tcpProbePortFor returns the peer's always-on OS TCP probe port.
func (e *Engine) tcpProbePortFor(addr netip.Addr) int {
	if e.dm != nil {
		for _, p := range e.dm.Peers() {
			if (p.RawIP == addr.String() || p.DataIP == addr.String() || p.Via.String() == addr.String()) && p.TCPProbePort > 0 {
				return p.TCPProbePort
			}
		}
	}
	if e.opts.PeerTCPProbePort > 0 {
		return e.opts.PeerTCPProbePort
	}
	return e.opts.TCPProbePort
}

func (e *Engine) peerAddr() netip.Addr {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, s := range e.sets {
		if s.peerIP.Is4() {
			return s.peerIP
		}
	}
	if e.dm != nil {
		if ps := e.dm.Peers(); len(ps) > 0 {
			if a, err := netip.ParseAddr(ps[0].RawIP); err == nil {
				return a
			}
		}
	}
	return netip.Addr{}
}

func (e *Engine) peerEndpoint() string {
	if e.opts.Peer != "" {
		if e.opts.PeerStack != "" && !discovery.StackHasKernel(e.opts.PeerStack) {
			return ""
		}
		return e.opts.Peer
	}
	if e.dm != nil {
		if ps := e.dm.Peers(); len(ps) > 0 {
			if ep, ok := ps[0].KernelEndpoint(); ok {
				return ep
			}
		}
	}
	return ""
}

func (e *Engine) serveHTTP() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(dashboard))
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(e.Dump())
	})
	mux.HandleFunc("/report.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		in := e.ReportInput()
		fs := report.Diagnose(in)
		_ = json.NewEncoder(w).Encode(map[string]any{"input": in, "findings": fs, "verdict": report.Verdict(fs)})
	})
	mux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		in := e.ReportInput()
		fs := report.Diagnose(in)
		_, _ = w.Write([]byte(report.Markdown(in, fs)))
	})
	mux.HandleFunc("/report.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		in := e.ReportInput()
		_, _ = w.Write([]byte(report.Text(in, report.Diagnose(in))))
	})
	mux.HandleFunc("/peers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		out := map[string]any{"self": e.selfAnnounce()}
		if e.dm != nil {
			out["peers"] = e.dm.Peers()
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	fmt.Fprintf(e.out, "telemetry on http://%s/stats (also /report, /report.json, /peers)\n", e.opts.HTTP)
	_ = http.ListenAndServe(e.opts.HTTP, mux)
}

// Dump returns everything the tool currently knows.
func (e *Engine) Dump() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	sess := map[string]any{}
	for id, s := range e.sets {
		m := map[string]any{"peer_name": s.peerName, "peer_ip": s.peerIP.String()}
		if s.kernel != nil {
			m["kernel_local"] = s.kernel.LocalSnapshot()
			if p, at := s.kernel.PeerSnapshot(); p != nil {
				m["kernel_peer"] = p
				m["kernel_peer_age"] = time.Since(at).String()
			}
		}
		if s.raw != nil {
			m["raw_local"] = s.raw.LocalSnapshot()
			if p, at := s.raw.PeerSnapshot(); p != nil {
				m["raw_peer"] = p
				m["raw_peer_age"] = time.Since(at).String()
			}
		}
		if s.obs != nil {
			m["observed"] = s.obs.Snapshot()
		}
		sess[id] = m
	}
	disc := map[string]any{}
	if e.dm != nil {
		disc["beacons_sent"] = e.dm.BeaconsSent()
		disc["quiet"] = e.dm.Quiet()
		disc["peers"] = len(e.dm.Peers())
	}
	return map[string]any{
		"self":      e.selfAnnounce(),
		"elapsed":   time.Since(e.start).String(),
		"sessions":  sess,
		"discovery": disc,
	}
}

// ReportInput assembles the two-sided view used by the diagnosis engine.
func (e *Engine) ReportInput() report.Input {
	e.mu.Lock()
	defer e.mu.Unlock()
	in := report.Input{StackMode: e.opts.Stack, Impair: e.opts.Impair, Duration: time.Since(e.start)}
	if e.dm != nil {
		if ps := e.dm.Peers(); len(ps) > 0 {
			in.PeerStack = ps[0].Stack
		}
	}
	if in.PeerStack == "" && e.opts.PeerStack != "" {
		in.PeerStack = e.opts.PeerStack
	}
	ids := make([]string, 0, len(e.sets))
	for id := range e.sets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		s := e.sets[id]
		if s.raw != nil {
			in.Local = s.raw.LocalSnapshot()
			if p, _ := s.raw.PeerSnapshot(); p != nil {
				in.Peer = p
			}
			break
		}
		if s.kernel != nil {
			in.Local = s.kernel.LocalSnapshot()
			if p, _ := s.kernel.PeerSnapshot(); p != nil {
				in.Peer = p
			}
			break
		}
	}
	// Hand the report the full picture: both stacks' views and what the capture
	// engine actually saw. The report compares them itself instead of telling
	// the user to run more commands.
	if e.dmx != nil {
		c := e.dmx.Capture()
		c.PCAP = e.opts.PCAP
		if e.pcap != nil {
			c.PCAPFiltered = e.pcap.Filtered()
			c.PCAPSynthetic = e.pcap.Injected()
			c.PCAPDuplicate = e.pcap.Duplicates()
			c.PCAPAll = e.opts.PCAPAll
		}
		in.Capture = &c
	}
	for _, id := range ids {
		s := e.sets[id]
		if s.kernel != nil && in.Kernel == nil {
			in.Kernel = &report.StackPair{Stack: "kernel", Local: s.kernel.LocalSnapshot()}
			if p, _ := s.kernel.PeerSnapshot(); p != nil {
				in.Kernel.Peer = p
			}
		}
		if s.raw != nil && in.Raw == nil {
			in.Raw = &report.StackPair{Stack: "raw", Local: s.raw.LocalSnapshot()}
			if p, _ := s.raw.PeerSnapshot(); p != nil {
				in.Raw.Peer = p
			}
		}
	}
	if in.Local == nil {
		in.Local = &wire.Snapshot{Stack: e.opts.Stack}
	}
	if in.Peer == nil {
		in.Peer = &wire.Snapshot{Stack: "unknown"}
	}
	// If raw mode was requested but the handshake never completed there is no
	// raw session snapshot to carry the reason. Fold the last connect error in
	// so the report says *why* it is unestablished instead of only that no SYN
	// was seen.
	if in.Raw == nil && (e.opts.Stack == "raw" || e.opts.Stack == "both" || e.opts.Stack == "observe") {
		var lastErr string
		tries := 0
		for _, id := range ids {
			tries += e.rawAttempts[id]
			if lastErr == "" && e.rawErr[id] != "" {
				lastErr = e.rawErr[id]
			}
		}
		if in.Local.Stack == "raw" && in.Local.State == "" {
			in.Local.State = "not established"
		}
		if lastErr != "" {
			in.Local.Notes = append(in.Local.Notes,
				fmt.Sprintf("raw session not established after %d attempt(s): %s", tries, lastErr))
		}
	}
	if mean, _, _, n := lastRTT(e); n > 0 {
		in.AppRTTMs = float64(mean) / float64(time.Millisecond)
	}
	in.ProbeNotes = append([]string{}, e.probeNotes...)
	in.KernelLocal = e.kd.Delta()
	return in
}

// lastRTT reads the application RTT. Callers must already hold e.mu: the
// engine mutex is not reentrant, and ReportInput holds it for the whole
// assembly, so locking again here would deadlock shutdown.
func lastRTT(e *Engine) (time.Duration, time.Duration, time.Duration, uint64) {
	for _, s := range e.sets {
		if s.raw != nil {
			return s.raw.AppRTT()
		}
		if s.kernel != nil {
			return s.kernel.AppRTT()
		}
	}
	return 0, 0, 0, 0
}

func (e *Engine) writeExports(in report.Input, fs []report.Finding) {
	o := e.opts
	if o.JSONL != "" {
		if f, err := os.Create(o.JSONL); err == nil {
			enc := json.NewEncoder(f)
			_ = enc.Encode(in)
			_ = enc.Encode(map[string]any{"findings": fs, "verdict": report.Verdict(fs)})
			_ = f.Close()
			fmt.Fprintf(e.out, "wrote %s\n", o.JSONL)
		}
	}
	if o.CSV != "" {
		if f, err := os.Create(o.CSV); err == nil {
			w := bufio.NewWriter(f)
			fmt.Fprintln(w, "side,metric,value")
			dumpCSV(w, "local", in.Local)
			dumpCSV(w, "peer", in.Peer)
			_ = w.Flush()
			_ = f.Close()
			fmt.Fprintf(e.out, "wrote %s\n", o.CSV)
		}
	}
	if o.ReportFile != "" {
		body := report.Markdown(in, fs)
		if strings.HasSuffix(strings.ToLower(o.ReportFile), ".txt") {
			body = report.Text(in, fs)
		}
		if err := os.WriteFile(o.ReportFile, []byte(body), 0o644); err == nil {
			fmt.Fprintf(e.out, "wrote %s\n", o.ReportFile)
		}
	}
}

func dumpCSV(w io.Writer, side string, s *wire.Snapshot) {
	if s == nil {
		return
	}
	rows := [][2]string{
		{"mbps_sent", fmt.Sprintf("%.3f", s.MbpsSent)},
		{"mbps_recv", fmt.Sprintf("%.3f", s.MbpsRecv)},
		{"retrans_sent", strconv.FormatUint(s.RetransSent, 10)},
		{"fast_retrans", strconv.FormatUint(s.FastRetrans, 10)},
		{"rto_retrans", strconv.FormatUint(s.RtoRetrans, 10)},
		{"spurious_retrans", strconv.FormatUint(s.SpuriousRetrans, 10)},
		{"spurious_recv", strconv.FormatUint(s.SpuriousRecv, 10)},
		{"dup_acks_recv", strconv.FormatUint(s.DupAcksRecv, 10)},
		{"missing_blocks", strconv.FormatUint(s.BlocksMissing, 10)},
		{"ooo_segs", strconv.FormatUint(s.OooSegs, 10)},
		{"late_blocks", strconv.FormatUint(s.BlocksLate, 10)},
		{"chain_mismatch", strconv.FormatUint(s.ChainMismatch, 10)},
		{"rtt_ewms", fmt.Sprintf("%.3f", s.RTTEwms)},
		{"rto_ms", fmt.Sprintf("%.1f", s.RTOms)},
		{"cwnd", strconv.FormatUint(uint64(s.Cwnd), 10)},
	}
	for _, r := range rows {
		fmt.Fprintf(w, "%s,%s,%s\n", side, r[0], r[1])
	}
}

func (e *Engine) shutdown() {
	e.mu.Lock()
	sets := make([]*sessionSet, 0, len(e.sets))
	for _, s := range e.sets {
		sets = append(sets, s)
	}
	e.mu.Unlock()
	for _, s := range sets {
		if s.kernel != nil {
			s.kernel.Close()
		}
		if s.raw != nil {
			s.raw.Close()
		}
	}
	if e.dm != nil {
		e.dm.Stop()
	}
	if e.ln != nil {
		_ = e.ln.Close()
	}
	for _, ln := range e.shields {
		_ = ln.Close()
	}
	if e.dmx != nil {
		_ = e.dmx.Close()
	}
	if e.eng != nil {
		_ = e.eng.Close()
	}
	if e.probeS != nil {
		_ = e.probeS.Close()
	}
	if e.tcpProbeS != nil {
		_ = e.tcpProbeS.Close()
	}
	if e.pcap != nil {
		fmt.Fprintf(e.out, "capture: %d packets -> %s (link type %s)\n", e.pcap.Count(), e.opts.PCAP, e.opts.PCAPDLT)
		if n, inj := e.pcap.Filtered(), e.pcap.Injected(); n > 0 || inj > 0 {
			fmt.Fprintf(e.out, "         %d unrelated packet(s) filtered out, %d locally injected packet(s) added\n", n, inj)
		}
		if s := e.pcap.Suspect(); s > 0 {
			fmt.Fprintf(e.out, "WARNING: %d packets in %s did not start with an IP header; the link type is wrong for this capture source.\n", s, e.opts.PCAP)
			fmt.Fprintln(e.out, "         Re-run with --pcap-dlt ethernet, or upgrade: the capture layer now strips link-layer headers.")
		}
		_ = e.pcap.Close()
	}

	in := e.ReportInput()
	fs := report.Diagnose(in)
	// The console gets the fixed-width renderer; markdown only makes sense in
	// a file, where a viewer renders it.
	fmt.Fprintf(e.out, "\n%s\n", report.Text(in, fs))
	e.writeExports(in, fs)
}

// Peers lists discovered peers.
func (e *Engine) Peers() []discovery.Peer {
	if e.dm == nil {
		return nil
	}
	ps := e.dm.Peers()
	sort.Slice(ps, func(i, j int) bool { return ps[i].Name < ps[j].Name })
	return ps
}

// Stop requests shutdown.
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	select {
	case <-e.stop:
	default:
		close(e.stop)
	}
}

// allIPv4 lists every non-loopback IPv4 address, so a peer can choose one that
// is actually reachable from its own subnet.
func allIPv4() []string {
	var out []string
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifi.Addrs()
		for _, ad := range addrs {
			n, ok := ad.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := n.IP.To4(); v4 != nil {
				if a, ok := netip.AddrFromSlice(v4); ok && !a.IsLinkLocalUnicast() {
					out = append(out, a.String())
				}
			}
		}
	}
	return out
}

// ifaceNameFor maps a local address back to the adapter that owns it.
func ifaceNameFor(ip netip.Addr) string {
	ifs, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}
	for _, ifi := range ifs {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, ad := range addrs {
			if n, ok := ad.(*net.IPNet); ok {
				if v4 := n.IP.To4(); v4 != nil {
					if a, ok := netip.AddrFromSlice(v4); ok && a == ip {
						return ifi.Name
					}
				}
			}
		}
	}
	return "unknown"
}

// egressIPFor returns the local address the kernel would use to reach dst. On a
// host with Hyper-V, WSL or VPN adapters, assuming a single "primary" address
// makes raw-mode packets get sourced from an adapter that cannot reach the peer.
func (e *Engine) egressIPFor(dst netip.Addr) netip.Addr {
	if !dst.Is4() {
		return e.ip
	}
	conn, err := net.Dial("udp4", net.JoinHostPort(dst.String(), "9"))
	if err != nil {
		return e.ip
	}
	defer conn.Close()
	if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		if a, ok := netip.AddrFromSlice(ua.IP.To4()); ok && a.Is4() {
			return a
		}
	}
	return e.ip
}

// printLocalBinding states exactly which adapter, address and ports this
// instance is using, so a mis-routed multi-homed host is obvious at a glance
// instead of being inferred from later failures.
// printLocalBinding states exactly which adapter, address and ports this
// instance is using. On a host with virtual adapters this is the first thing
// worth checking, so it is printed up front rather than being inferred from
// later connection failures.
// shieldRawPorts keeps a kernel listener on the raw-plane ports.
//
// SIO_RCVALL sniffs but does not bypass the kernel stack, so the host still
// sees SYNs for its own user-space connection. A SYN to a port with nothing
// bound to it makes the kernel answer with an RST onto the wire, which tears
// down the peer-side user-space connection. Binding a listener stops that; the
// accepted sockets are held open rather than closed so the kernel never emits a
// FIN or RST of its own afterwards.
func (e *Engine) shieldRawPorts() {
	for _, port := range []int{e.opts.RawPort, e.opts.RawPort + 1} {
		ln, err := net.Listen("tcp4", net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
		if err != nil {
			e.logf("raw port shield for %d: %v", port, err)
			continue
		}
		e.shields = append(e.shields, ln)
		go func(p int, l net.Listener) {
			var held []net.Conn
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				// Hold it open: closing would make the kernel send a RST that the
				// peer would accept as coming from the real connection.
				held = append(held, c)
				e.logf("raw port shield absorbed a kernel handshake on tcp/%d", p)
			}
		}(port, ln)
	}
}

func (e *Engine) printLocalBinding() {
	t := report.NewTable([]string{"", ""}, []bool{false, false})
	t.OmitHeader()
	t.Add("adapter", ifaceNameFor(e.ip))
	t.Add("address", e.ip.String())
	if e.opts.Stack != "raw" {
		t.Add("data plane", "tcp/"+strconv.Itoa(e.opts.DataPort)+" (listen + dial)")
	}
	if e.opts.Stack == "raw" || e.opts.Stack == "both" || e.opts.Stack == "observe" {
		t.Add("raw plane", "tcp/"+strconv.Itoa(e.opts.RawPort)+" listen, tcp/"+strconv.Itoa(e.opts.RawPort+1)+" dial")
	}
	t.Add("probe echo", "udp/"+strconv.Itoa(e.opts.ProbePort))
	if e.opts.TCPProbePort > 0 {
		t.Add("TCP probe", "tcp/"+strconv.Itoa(e.opts.TCPProbePort)+" (always on, any stack mode)")
	}
	if e.opts.Discover {
		t.Add("discovery", "udp/"+strconv.Itoa(e.opts.DiscoveryPort)+" broadcast + multicast "+e.opts.Multicast)
	} else {
		t.Add("discovery", "off")
	}
	if e.opts.HTTP != "" {
		t.Add("dashboard", "http://"+e.opts.HTTP+"/")
	}
	fmt.Print("local\n" + t.Render("  "))

	// Show the other adapters so a mis-picked one is visible immediately.
	if others := e.otherAddresses(); others != "" {
		fmt.Fprintf(e.out, "  other addresses\n")
		for _, line := range strings.Split(others, "\n") {
			if line != "" {
				fmt.Fprintf(e.out, "    %s\n", line)
			}
		}
		fmt.Fprintf(e.out, "  (override with --local-ip or --iface if this is the wrong adapter)\n")
	}
}

// otherAddresses lists the local addresses that were not chosen.
func (e *Engine) otherAddresses() string {
	caddrs, err := localIPv4s()
	if err != nil {
		return ""
	}
	var lines []string
	for _, c := range caddrs {
		if c.addr == e.ip {
			continue
		}
		lines = append(lines, c.addr.String()+" on "+c.iface)
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n")
}
