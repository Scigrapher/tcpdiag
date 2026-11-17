// Command tcpdiag diagnoses TCP retransmission problems (dup ACKs, fast
// retransmission, spurious retransmission) between two machines.
//
// Quick start - run this on both machines:
//
//	tcpdiag
//
// They find each other on the LAN automatically and start streaming data in
// both directions while measuring everything. Press Ctrl-C for a report.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"tcpdiag/internal/engine"
	"tcpdiag/internal/flow"
	"tcpdiag/internal/packetio"
	"tcpdiag/internal/report"
	"tcpdiag/internal/tcpraw"
	"tcpdiag/internal/wire"
)

const version = "1.7.0"

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "selftest", "peers", "probe":
			cmd, args = args[0], args[1:]
		}
	}
	if len(args) > 0 && (args[0] == "-version" || args[0] == "--version") {
		fmt.Printf("tcpdiag %s\n", version)
		return
	}
	var err error
	switch cmd {
	case "run":
		err = cmdRun(args)
	case "selftest":
		err = cmdSelftest(args)
	case "peers":
		err = cmdPeers(args)
	case "probe":
		err = cmdRun(append(args, "-probe"))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func bindRunFlags(fs *flag.FlagSet, o *engine.Options) {
	fs.StringVar(&o.Name, "name", defaultName(), "identity announced to peers")
	fs.StringVar(&o.Peer, "peer", "", "talk to host:port directly, skipping discovery")
	fs.StringVar(&o.PeerStack, "peer-stack", "", "stack mode of an explicit --peer: kernel | raw | both | observe")
	fs.IntVar(&o.PeerRawPort, "peer-raw-port", 0, "raw-stack port of an explicit --peer (0 = use --raw-port)")
	fs.BoolVar(&o.Discover, "discover", true, "auto-discover peers with UDP broadcast + multicast")
	fs.IntVar(&o.DiscoveryPort, "discovery-port", 42077, "UDP discovery port")
	fs.StringVar(&o.Multicast, "multicast", "239.255.42.99", "IPv4 multicast group for discovery")
	fs.IntVar(&o.DataPort, "data-port", 42424, "kernel-stack data plane TCP port")
	fs.IntVar(&o.RawPort, "raw-port", 42425, "raw-stack data plane TCP port")
	fs.IntVar(&o.ProbePort, "probe-port", 42426, "UDP port for active probe echo")
	fs.StringVar(&o.Stack, "stack", "kernel", "kernel | raw | both | observe (raw = our own TCP implementation)")
	fs.StringVar(&o.Backend, "backend", "auto", "packet backend: auto | windows | npcap | linux | sim")
	fs.StringVar(&o.LocalIP, "local-ip", "", "local IPv4 to use (default: auto)")
	fs.StringVar(&o.Bind, "bind", "0.0.0.0", "address to bind listeners to; use 127.0.0.1 for single-host testing")
	fs.StringVar(&o.Iface, "iface", "", "interface name for raw mode")
	fs.IntVar(&o.BlockSize, "block-size", 16384, "bytes per transmitted block")
	fs.Float64Var(&o.RateMbps, "rate", 0, "target send rate in Mbit/s (0 = as fast as possible)")
	fs.DurationVar(&o.Duration, "duration", 0, "stop after this long (0 = run until Ctrl-C)")
	fs.Uint64Var(&o.TotalBytes, "total", 0, "stop after this many bytes per direction")
	fs.DurationVar(&o.ConnectTimeout, "connect-timeout", 5*time.Second, "timeout per data-plane connection attempt")
	fs.IntVar(&o.ConnectAttempts, "connect-attempts", 10, "data-plane connection attempts before giving up")
	fs.StringVar(&o.Feed, "feed", "", "stream the contents of a file or directory instead of synthetic data")
	fs.IntVar(&o.RcvBuf, "rcv-buf", 4<<20, "socket/stack receive buffer bytes")
	fs.IntVar(&o.SndBuf, "snd-buf", 4<<20, "socket/stack send buffer bytes")
	fs.IntVar(&o.MSS, "mss", 1460, "MSS to advertise in raw mode")
	fs.DurationVar(&o.MinRTO, "min-rto", 200*time.Microsecond, "minimum retransmission timeout (raw mode)")
	fs.DurationVar(&o.MaxRTO, "max-rto", 60*time.Second, "maximum retransmission timeout (raw mode)")
	fs.BoolVar(&o.DelayedACK, "delayed-ack", false, "use RFC-style delayed ACKs instead of acking immediately")
	fs.BoolVar(&o.Timestamps, "timestamps", true, "use TCP timestamps for RTT estimation (raw mode)")
	fs.BoolVar(&o.SACK, "sack", true, "negotiate selective acknowledgements (raw mode)")
	fs.IntVar(&o.TOS, "tos", 0, "IPv4 TOS/DSCP byte for raw-mode packets")
	fs.IntVar(&o.TTL, "ttl", 64, "IPv4 TTL for raw-mode packets")
	fs.StringVar(&o.Impair, "impair", "", "inject defects, e.g. \"loss=1,delay=15ms,jitter=5ms,dup=0.2,reorder=1,rate=100,burst=3@20\"")
	fs.StringVar(&o.HTTP, "http", "", "serve a live dashboard and /stats at this address, e.g. :8083")
	fs.StringVar(&o.PCAP, "pcap", "", "write this .pcap file (default: only tcpdiag flows)")
	fs.StringVar(&o.PCAPDLT, "pcap-dlt", "raw", "pcap link type: raw (bare IP) | ethernet (adds an Ethernet header; use if Wireshark mislabels the packets)")
	fs.BoolVar(&o.PCAPAll, "pcap-all", false, "capture every packet on the host, not just tcpdiag's flows")
	fs.StringVar(&o.JSONL, "jsonl", "", "write the report as JSON lines to this file")
	fs.StringVar(&o.CSV, "csv", "", "write summary metrics to this CSV file")
	fs.StringVar(&o.ReportFile, "report", "", "write the markdown diagnosis to this file")
	fs.BoolVar(&o.DoProbe, "probe", false, "run active probes (RTT, loss, handshake, MTU, TTL) against the peer")
	fs.BoolVar(&o.ExitAfterProbes, "exit-after-probes", false, "stop and write the report once all active probes finish")
	fs.IntVar(&o.ProbeCount, "probe-count", 50, "probe packets per measurement")
	fs.BoolVar(&o.ProbeSweep, "probe-sweep", false, "sweep loss vs offered rate (finds a loaded-link cliff)")
	fs.BoolVar(&o.ProbeMTU, "probe-mtu", false, "discover the path MTU with the DF bit")
	fs.BoolVar(&o.ProbeTTL, "probe-ttl", false, "walk TTLs to find which hop drops packets (needs raw)")
	fs.BoolVar(&o.ProbeTCP, "probe-tcp", false, "run TCP handshake, echo, small-write and bulk-transfer probes")
	fs.IntVar(&o.TCPProbePort, "probe-tcp-port", 42427, "TCP port for the always-on TCP probe server")
	fs.IntVar(&o.PeerTCPProbePort, "peer-tcp-probe-port", 0, "TCP probe port of an explicit --peer (0 = use --probe-tcp-port)")
	fs.IntVar(&o.ProbeTCPConnections, "probe-tcp-connections", 10, "TCP handshake probe connections")
	fs.IntVar(&o.ProbeTCPBytes, "probe-tcp-bytes", 4<<20, "bytes per TCP bulk-transfer direction")
	fs.IntVar(&o.ProbeTCPSmall, "probe-tcp-small", 500, "small TCP echo writes (0 disables)")
	fs.BoolVar(&o.ProbeTCPNoDelay, "probe-tcp-nodelay", true, "set TCP_NODELAY on TCP probe connections")
	fs.DurationVar(&o.ProbeTCPTimeout, "probe-tcp-timeout", 10*time.Second, "timeout per TCP probe operation")
	fs.BoolVar(&o.NoDelay, "nodelay", true, "set TCP_NODELAY on kernel sockets")
	fs.BoolVar(&o.KeepAdvertising, "keep-advertising", false, "keep sending discovery beacons after peers connect (default: go quiet once connected)")
	fs.BoolVar(&o.Verbose, "v", false, "verbose logging")
	fs.BoolVar(&o.Verbose, "verbose", false, "verbose logging")
}

func defaultName() string {
	n, err := os.Hostname()
	if err != nil || n == "" {
		return "tcpdiag"
	}
	return n
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("tcpdiag", flag.ContinueOnError)
	var o engine.Options
	bindRunFlags(fs, &o)
	if err := fs.Parse(args); err != nil {
		return err
	}
	o.Version = version
	if o.ProbeTCP || o.ExitAfterProbes {
		o.DoProbe = true
	}
	if o.Bind != "" && net.ParseIP(o.Bind) == nil {
		return fmt.Errorf("--bind must be a valid IP address, got %q", o.Bind)
	}
	switch o.Stack {
	case "kernel", "raw", "both", "observe":
	default:
		return fmt.Errorf("--stack must be kernel, raw, both or observe")
	}
	switch o.PeerStack {
	case "", "kernel", "raw", "both", "observe":
	default:
		return fmt.Errorf("--peer-stack must be kernel, raw, both or observe")
	}
	e := engine.New(o)

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Fprintln(os.Stderr, "\nshutting down and writing the report...")
		e.Stop()
		<-time.After(3 * time.Second)
		os.Exit(0)
	}()

	fmt.Printf("tcpdiag %s  name=%s id=%s stack=%s\n", version, o.Name, e.PeerID(), o.Stack)
	switch {
	case o.Peer != "":
		fmt.Printf("targeting %s (discovery disabled)\n", o.Peer)
	case o.Discover:
		fmt.Printf("discovering peers via udp/%d broadcast + %s multicast\n", o.DiscoveryPort, o.Multicast)
	default:
		fmt.Printf("discovery off: waiting to be dialled on tcp/%d\n", o.DataPort)
	}
	return e.Start()
}

func cmdPeers(args []string) error {
	fs := flag.NewFlagSet("tcpdiag peers", flag.ContinueOnError)
	port := fs.Int("discovery-port", 42077, "UDP discovery port")
	group := fs.String("multicast", "239.255.42.99", "multicast group")
	wait := fs.Duration("wait", 4*time.Second, "how long to listen")
	if err := fs.Parse(args); err != nil {
		return err
	}
	e := engine.New(engine.Options{
		Name: "listener-" + randSuffix(), Stack: "kernel", Discover: true,
		DiscoveryPort: *port, Multicast: *group, Duration: *wait, Version: version,
	})
	fmt.Printf("listening for tcpdiag peers for %v...\n", *wait)
	if err := e.Start(); err != nil {
		return err
	}
	for _, p := range e.Peers() {
		fmt.Printf("%-22s %-16s %-8s tcp=%-22s raw=%s:%d probe=%d tcp-probe=%d stack=%s\n",
			p.Name, p.ID, p.Version, p.TCPAddr, p.RawIP, p.RawPort, p.ProbePort, p.TCPProbePort, p.Stack)
	}
	if len(e.Peers()) == 0 {
		fmt.Println("no peers seen. Check that both hosts allow UDP broadcasts and multicast on the LAN.")
	}
	return nil
}

func randSuffix() string {
	var b [3]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%x", b)
}

// ---------------------------------------------------------------------------
// selftest: two user-space TCP stacks over an impaired in-process link
// ---------------------------------------------------------------------------

func cmdSelftest(args []string) error {
	fs := flag.NewFlagSet("tcpdiag selftest", flag.ContinueOnError)
	impair := fs.String("impair", "loss=2,delay=12ms,jitter=6ms,dup=0.3,reorder=1", "impairment profile for the virtual link")
	dur := fs.Duration("duration", 6*time.Second, "how long to run")
	blockSize := fs.Int("block-size", 8192, "block size")
	rate := fs.Float64("rate", 20, "target Mbit/s per direction")
	mss := fs.Int("mss", 1400, "MSS")
	seedVal := fs.Int64("seed", 0, "deterministic RNG seed (0 = random)")
	verbose := fs.Bool("v", false, "verbose")
	if err := fs.Parse(args); err != nil {
		return err
	}
	im, err := packetio.ParseImpairment(*impair)
	if err != nil {
		return err
	}
	ipA := netip.MustParseAddr("10.99.0.1")
	ipB := netip.MustParseAddr("10.99.0.2")
	hub := packetio.NewSimHub(*seedVal)
	simA, simB := hub.Attach("A", ipA), hub.Attach("B", ipB)
	hub.SetLink(ipA, ipB, im)
	hub.SetLink(ipB, ipA, im)

	logf := func(string, ...any) {}
	if *verbose {
		logf = func(f string, v ...any) { fmt.Printf("   "+f+"\n", v...) }
	}

	// B listens, A dials. Both use our own TCP implementation.
	cfgB := tcpraw.DefaultConfig()
	cfgB.LocalIP, cfgB.RemoteIP = ipB, ipA
	cfgB.LocalPort, cfgB.RemotePort = 42425, 42426
	cfgB.MSS, cfgB.Logf = *mss, logf
	cfgB.MinRTO = 2 * time.Millisecond

	cfgA := tcpraw.DefaultConfig()
	cfgA.LocalIP, cfgA.RemoteIP = ipA, ipB
	cfgA.LocalPort, cfgA.RemotePort = 42426, 42425
	cfgA.MSS, cfgA.Logf = *mss, logf
	cfgA.MinRTO = 2 * time.Millisecond

	dmxA, dmxB := tcpraw.NewDemux(simA), tcpraw.NewDemux(simB)
	type res struct {
		c   *tcpraw.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := tcpraw.Listen(dmxB, cfgB).Accept()
		ch <- res{c, err}
	}()
	connA, err := tcpraw.Dial(dmxA, cfgA)
	if err != nil {
		return fmt.Errorf("A dial: %w", err)
	}
	r := <-ch
	if r.err != nil {
		return fmt.Errorf("B accept: %w", r.err)
	}
	connB := r.c
	fmt.Printf("selftest: two raw TCP stacks over a simulated link  [%s]\n", im)

	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	mkSess := func(local, peer string, dialer bool, conn *tcpraw.Conn) *flow.Session {
		cfg := flow.Config{
			LocalID: local, LocalName: "node-" + local, PeerID: peer, PeerName: "node-" + peer,
			Stack: "raw", IsDialer: dialer, BlockSize: *blockSize, RateMbps: *rate,
			Duration: *dur, Seed: seed, Version: version, Logf: logf,
			Providers: []func(*wireSnap){func(s *wireSnap) { s.Add(conn.Snapshot()) }},
		}
		return flow.New(conn, cfg)
	}
	sessA := mkSess("A", "B", true, connA)
	sessB := mkSess("B", "A", false, connB)
	// Start both concurrently: each session writes its handshake and then waits
	// for the other's, so a serial start would deadlock.
	errA, errB := make(chan error, 1), make(chan error, 1)
	go func() { errA <- sessA.Start() }()
	go func() { errB <- sessB.Start() }()
	if err := <-errA; err != nil {
		return fmt.Errorf("A start: %w", err)
	}
	if err := <-errB; err != nil {
		return fmt.Errorf("B start: %w", err)
	}

	t0 := time.Now()
	doneA := make(chan error, 1)
	doneB := make(chan error, 1)
	go func() { doneA <- sessA.Wait() }()
	go func() { doneB <- sessB.Wait() }()
	select {
	case <-doneA:
	case <-time.After(*dur + 10*time.Second):
	}
	sessA.Close()
	sessB.Close()
	<-doneB

	la := sessA.LocalSnapshot()

	capture := dmxA.Capture()
	capture.Engine = "sim (link offered=" + strconv.FormatUint(hub.Offered, 10) +
		" delivered=" + strconv.FormatUint(hub.Delivered, 10) +
		" dropped=" + strconv.FormatUint(hub.Dropped, 10) +
		" duped=" + strconv.FormatUint(hub.Duped, 10) + ")"
	in := report.Input{
		Local:     la,
		Peer:      peerOf(sessA, sessB),
		Duration:  time.Since(t0),
		Impair:    im.String(),
		StackMode: "raw(sim)",
		Capture:   &capture,
		Raw:       &report.StackPair{Stack: "raw", Local: la, Peer: peerOf(sessA, sessB)},
	}
	fs2 := report.Diagnose(in)
	fmt.Println()
	sum := report.NewTable(
		[]string{"node", "tx blocks", "tx bytes", "rx blocks", "rx bytes",
			"retrans", "fast", "rto", "spur", "dupack", "missing", "ooo", "late", "chain", "srtt ms", "rto ms"},
		[]bool{false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true})
	sum.Add(append([]string{"A"}, summaryRow(la)...)...)
	sum.Add(append([]string{"B"}, summaryRow(peerOf(sessA, sessB))...)...)
	fmt.Println(sum.Render(""))
	fmt.Printf("\nlink: offered=%d delivered=%d dropped=%d duped=%d\n", hub.Offered, hub.Delivered, hub.Dropped, hub.Duped)
	fmt.Println(report.Text(in, fs2))
	return nil
}

type wireSnap = wire.Snapshot

func peerOf(a, b *flow.Session) *wire.Snapshot {
	if p, _ := b.PeerSnapshot(); p != nil {
		return p
	}
	if p, _ := a.PeerSnapshot(); p != nil {
		return p
	}
	return &wire.Snapshot{}
}

// summaryRow renders one node's counters for the aligned selftest summary.
func summaryRow(s *wire.Snapshot) []string {
	if s == nil {
		return []string{"-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-"}
	}
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	return []string{
		u(s.BlocksSent), u(s.BytesSent), u(s.BlocksRecv), u(s.BytesRecv),
		u(s.RetransSent), u(s.FastRetrans), u(s.RtoRetrans), u(s.SpuriousRetrans),
		u(s.DupAcksRecv), u(s.BlocksMissing), u(s.OooSegs), u(s.BlocksLate),
		u(s.ChainMismatch), fmt.Sprintf("%.2f", s.RTTEwms), fmt.Sprintf("%.0f", s.RTOms),
	}
}
