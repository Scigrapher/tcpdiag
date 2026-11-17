package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Announce is the discovery beacon exchanged on the local network.
type Announce struct {
	Type         string   `json:"t"` // announce | probe | bye
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Version      string   `json:"ver"`
	Stack        string   `json:"stack"`
	TCPAddr      string   `json:"tcp"` // host:port the data plane listens on
	RawIP        string   `json:"raw"` // preferred IPv4 for raw-mode packets
	IPs          []string `json:"ips,omitempty"`
	RawPort      int      `json:"rawp"`
	ProbePort    int      `json:"probeport"`    // UDP echo port
	TCPProbePort int      `json:"tcpprobeport"` // always-on OS TCP probe service
	Boot         int64    `json:"boot"`
	Nonce        string   `json:"nonce"`
	Hostname     string   `json:"host"`
}

// Peer is a discovered instance.
type Peer struct {
	Announce
	LastSeen time.Time
	// Via is the source address the peer's beacon actually arrived from. That
	// is the only address proven to be reachable from here, which matters on a
	// multi-homed host: a peer with Hyper-V, WSL or VPN adapters advertises
	// plenty of addresses, most of which are unreachable from the LAN.
	Via netip.Addr
	// DataIP is the address to dial. Resolved from the announced address list
	// against Via rather than trusting the peer's own preference.
	DataIP string
	// DataPort / RawPort are the ports to dial.
	DataPort int
	// EgressIface names the local interface the peer was seen on.
	EgressIface string
}

// ID ordering breaks the dial/listen tie deterministically: the smaller ID
// dials, the larger one listens. Both sides reach the same conclusion without
// a negotiation round, so there is no connect race.
func (p *Peer) ShouldDial(myID string) bool { return myID < p.ID }

// StackHasKernel reports whether a stack mode starts an ordinary OS TCP
// listener. observe uses the kernel data plane, so it counts as kernel here.
func StackHasKernel(stack string) bool {
	switch stack {
	case "", "kernel", "observe", "both":
		return true
	}
	return false
}

// StackHasRaw reports whether a stack mode runs tcpdiag's user-space TCP stack.
func StackHasRaw(stack string) bool {
	switch stack {
	case "", "raw", "both":
		return true
	}
	return false
}

// StacksCompatible reports whether the two modes have at least one data plane
// in common. An empty stack is an older peer that did not advertise one, so it
// is treated as compatible rather than guessed wrong.
func StacksCompatible(local, peer string) bool {
	if local == "" || peer == "" {
		return true
	}
	return (StackHasKernel(local) && StackHasKernel(peer)) ||
		(StackHasRaw(local) && StackHasRaw(peer))
}

// KernelEndpoint is the ordinary TCP listener to probe, when this peer has one.
func (p *Peer) KernelEndpoint() (string, bool) {
	if p.Stack != "" && !StackHasKernel(p.Stack) {
		return "", false
	}
	host := p.DataIP
	if host == "" {
		host = p.Via.String()
	}
	if host == "" {
		return "", false
	}
	port := p.DataPort
	if port == 0 {
		port = 42424
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), true
}

// RawEndpoint is the peer's user-space TCP listener, when it has one.
func (p *Peer) RawEndpoint() (string, bool) {
	if p.Stack != "" && !StackHasRaw(p.Stack) {
		return "", false
	}
	host := p.DataIP
	if host == "" {
		host = p.RawIP
	}
	if host == "" {
		host = p.Via.String()
	}
	if host == "" {
		return "", false
	}
	port := p.RawPort
	if port == 0 {
		port = 42425
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), true
}

// Manager runs the discovery protocol.
type Manager struct {
	port     int
	group    netip.Addr
	id       string
	self     func() Announce
	mu       sync.Mutex
	peers    map[string]*Peer
	onAdd    func(*Peer)
	onRemove func(*Peer)
	conn4    *net.UDPConn
	mcast    []*net.UDPConn
	done     chan struct{}
	once     sync.Once
	interval time.Duration
	timeout  time.Duration
	quiet    atomic.Bool
	always   atomic.Bool
	beacons  atomic.Uint64
	logf     func(string, ...any)
}

// Options configures Manager.
type Options struct {
	Port     int
	Group    string
	ID       string
	Name     string
	Version  string
	Self     func() Announce
	OnAdd    func(*Peer)
	OnRemove func(*Peer)
	Logf     func(string, ...any)
}

// Start binds the discovery sockets and begins beaconing.
func Start(o Options) (*Manager, error) {
	if o.Port == 0 {
		o.Port = 42077
	}
	if o.Group == "" {
		o.Group = "239.255.42.99"
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	group, err := netip.ParseAddr(o.Group)
	if err != nil {
		return nil, fmt.Errorf("discovery group %q: %w", o.Group, err)
	}
	m := &Manager{
		port:     o.Port,
		group:    group,
		id:       o.ID,
		self:     o.Self,
		onAdd:    o.OnAdd,
		onRemove: o.OnRemove,
		peers:    map[string]*Peer{},
		done:     make(chan struct{}),
		interval: time.Second,
		timeout:  6 * time.Second,
		logf:     o.Logf,
	}
	// Primary socket: unicast + broadcast on 0.0.0.0:port, with SO_REUSEADDR so
	// several instances can coexist on one machine while testing.
	lc := net.ListenConfig{Control: control(nil, nil, true)}
	c4, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf("0.0.0.0:%d", o.Port))
	if err != nil {
		return nil, fmt.Errorf("bind udp/%d: %w", o.Port, err)
	}
	m.conn4 = c4.(*net.UDPConn)

	// One multicast listener per IPv4 interface, joined on that interface.
	if group.IsMulticast() {
		ctx := context.Background()
		for _, ifi := range multicastInterfaces() {
			lcm := net.ListenConfig{Control: control(net.IP(group.AsSlice()), ifi.ip, true)}
			pc, err := lcm.ListenPacket(ctx, "udp4", fmt.Sprintf("%s:%d", group.String(), o.Port))
			if err != nil {
				m.logf("multicast join on %s failed: %v", ifi.name, err)
				continue
			}
			m.mcast = append(m.mcast, pc.(*net.UDPConn))
			m.logf("joined %s on %s", group, ifi.name)
		}
	}
	for _, pc := range []*net.UDPConn{m.conn4} {
		go m.readLoop(pc)
	}
	for _, pc := range m.mcast {
		go m.readLoop(pc)
	}
	go m.beaconLoop()
	return m, nil
}

func (m *Manager) readLoop(pc *net.UDPConn) {
	buf := make([]byte, 4096)
	for {
		select {
		case <-m.done:
			return
		default:
		}
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-m.done:
				return
			default:
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		var a Announce
		if err := json.Unmarshal(buf[:n], &a); err != nil || a.ID == "" {
			continue
		}
		if a.ID == m.id {
			continue // our own beacon reflected back
		}
		var from netip.Addr
		if ua, ok := addr.(*net.UDPAddr); ok {
			from, _ = netip.AddrFromSlice(ua.IP.To4())
		}
		switch a.Type {
		case "bye":
			m.mu.Lock()
			p := m.peers[a.ID]
			delete(m.peers, a.ID)
			m.mu.Unlock()
			if p != nil && m.onRemove != nil {
				m.onRemove(p)
			}
			continue
		case "probe", "announce":
			// Decide novelty before absorbing, otherwise the peer is already
			// recorded and we can no longer tell whether we have met it.
			fresh := !m.known(a.ID)
			m.absorb(a, from)
			// Answer directly so a new node learns us immediately. This is what
			// keeps a quiet node discoverable: broadcasting stops once sessions
			// are up, but we still answer probes and first-time announces.
			// Replying to every announce would make two nodes answer each
			// other forever.
			if a.Type == "probe" || fresh {
				m.unicast(from, "announce")
			}
		}
	}
}

// known reports whether this peer id is already in the table.
func (m *Manager) known(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.peers[id]
	return ok
}

func (m *Manager) absorb(a Announce, from netip.Addr) {
	m.mu.Lock()
	p, existed := m.peers[a.ID]
	if !existed {
		p = &Peer{}
		m.peers[a.ID] = p
	}
	p.Announce = a
	p.LastSeen = time.Now()
	p.Via = from
	p.DataIP, p.EgressIface = resolveReachable(a, from)
	p.DataPort = dataPortOf(a)
	m.mu.Unlock()
	if !existed {
		m.logf("discovered peer %s (%s): reachable at %s:%d via %s (beacon from %s, advertised %v)",
			a.Name, a.ID, p.DataIP, p.DataPort, orDefault(p.EgressIface, "local"), from, a.IPs)
		if m.onAdd != nil {
			m.onAdd(p)
		}
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// dataPortOf extracts the data-plane port the peer announced.
func dataPortOf(a Announce) int {
	if a.TCPAddr != "" {
		if h, portStr, err := net.SplitHostPort(a.TCPAddr); err == nil {
			if _, err := netip.ParseAddr(h); err == nil {
				if n, err := strconv.Atoi(portStr); err == nil && n > 0 {
					return n
				}
			}
		}
	}
	return 42424
}

// resolveReachable chooses which announced address to dial. The peer's own
// preference is unreliable on a multi-homed host - a virtual switch, WSL or
// VPN adapter can easily win the "primary address" contest and then be
// unreachable from the LAN - so the address the beacon actually arrived from
// wins, then any announced address on the same /24 as it.
func resolveReachable(a Announce, from netip.Addr) (ip, iface string) {
	var cands []string
	seenC := map[string]bool{}
	add := func(s string) {
		if s == "" || seenC[s] {
			return
		}
		if addr, err := netip.ParseAddr(s); err == nil && addr.Is4() {
			seenC[s] = true
			cands = append(cands, s)
		}
	}
	for _, s := range a.IPs {
		add(s)
	}
	add(a.RawIP)
	if h, _, err := net.SplitHostPort(a.TCPAddr); err == nil {
		add(h)
	}
	if len(cands) == 0 {
		return from.String(), localIfaceFor(from)
	}
	// Proven reachable: the source of the beacon itself.
	if _, ok := seenC[from.String()]; ok {
		return from.String(), localIfaceFor(from)
	}
	// Otherwise prefer an announced address on the same /24 as the beacon.
	fb := from.As4()
	for _, c := range cands {
		ca, _ := netip.ParseAddr(c)
		cb := ca.As4()
		if cb[0] == fb[0] && cb[1] == fb[1] && cb[2] == fb[2] {
			return c, localIfaceFor(from)
		}
	}
	// Nothing announced is on this subnet: use the address that demonstrably
	// carried the beacon.
	return from.String(), localIfaceFor(from)
}

// localIfaceFor names the local interface owning the given address.
func localIfaceFor(ip netip.Addr) string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
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
	return ""
}

func (m *Manager) beaconLoop() {
	t := time.NewTicker(m.interval)
	defer t.Stop()
	m.broadcast("probe") // fast bootstrap when we are the first one up
	for {
		select {
		case <-m.done:
			return
		case <-t.C:
			// Once sessions are up there is no reason to keep shouting: the
			// beacons are pure background noise on the LAN and in captures.
			// New peers still find us because we answer their probes and
			// announces directly (see readLoop), and --keep-advertising
			// restores the constant beacon.
			if !m.Quiet() {
				m.broadcast("announce")
			}
			m.reap()
		}
	}
}

func (m *Manager) reap() {
	cut := time.Now().Add(-m.timeout)
	m.mu.Lock()
	var dead []*Peer
	for id, p := range m.peers {
		if p.LastSeen.Before(cut) {
			dead = append(dead, p)
			delete(m.peers, id)
		}
	}
	m.mu.Unlock()
	for _, p := range dead {
		m.logf("peer %s (%s) lost", p.Name, p.ID)
		if m.onRemove != nil {
			m.onRemove(p)
		}
	}
}

func (m *Manager) payload(t string) []byte {
	a := m.self()
	a.Type = t
	a.ID = m.id
	b, _ := json.Marshal(a)
	return b
}

func (m *Manager) broadcast(t string) {
	m.beacons.Add(1)
	b := m.payload(t)
	dst := net.UDPAddr{IP: net.IP(m.group.AsSlice()), Port: m.port}
	_, _ = m.conn4.WriteToUDP(b, &dst)
	_ = m.conn4.SetWriteBuffer(1 << 20)
	// Also hit the subnet broadcast so nodes that failed to join multicast still
	// see us, and let the user run two instances on one host.
	for _, bc := range localBroadcastAddrs() {
		_, _ = m.conn4.WriteToUDP(b, &net.UDPAddr{IP: bc, Port: m.port})
	}
}

func (m *Manager) unicast(to netip.Addr, t string) {
	if !to.Is4() {
		return
	}
	b := m.payload(t)
	_, _ = m.conn4.WriteToUDP(b, &net.UDPAddr{IP: net.IP(to.AsSlice()), Port: m.port})
}

// SetQuiet stops or starts the periodic beacon. Discovery stays functional in
// quiet mode because unknown peers are answered directly.
func (m *Manager) SetQuiet(q bool) { m.quiet.Store(q) }

// BeaconsSent counts broadcast beacons sent since start.
func (m *Manager) BeaconsSent() uint64 { return m.beacons.Load() }

// Quiet reports whether beacons are currently suppressed.
func (m *Manager) Quiet() bool { return m.quiet.Load() && !m.always.Load() }

// SetAlwaysAdvertise overrides quiet mode: beacons continue regardless of
// whether sessions are established.
func (m *Manager) SetAlwaysAdvertise(v bool) { m.always.Store(v) }

// Peers returns a stable, sorted view of the current peer table.
func (m *Manager) Peers() []Peer {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Peer, 0, len(m.peers))
	for _, p := range m.peers {
		cp := *p
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns one peer by ID.
func (m *Manager) Get(id string) (Peer, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.peers[id]; ok {
		return *p, true
	}
	return Peer{}, false
}

// WaitForPeer blocks until at least one peer is present or the deadline passes.
func (m *Manager) WaitForPeer(d time.Duration) (Peer, bool) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		ps := m.Peers()
		if len(ps) > 0 {
			return ps[0], true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return Peer{}, false
}

// Stop announces our departure and closes the sockets.
func (m *Manager) Stop() {
	m.once.Do(func() {
		m.broadcast("bye")
		close(m.done)
		if m.conn4 != nil {
			_ = m.conn4.Close()
		}
	})
}

func localBroadcastAddrs() []net.IP {
	var out []net.IP
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := n.IP.To4()
			if v4 == nil {
				continue
			}
			m := net.IP(n.Mask).To4()
			if m == nil {
				continue
			}
			bc := make(net.IP, 4)
			for i := 0; i < 4; i++ {
				bc[i] = v4[i] | ^m[i]
			}
			out = append(out, bc)
		}
	}
	return out
}

type ifaceIP struct {
	name  string
	ip    net.IP
	index int
}

func multicastInterfaces() []ifaceIP {
	var out []ifaceIP
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := n.IP.To4(); v4 != nil {
				out = append(out, ifaceIP{name: ifi.Name, ip: v4, index: ifi.Index})
			}
		}
	}
	return out
}
