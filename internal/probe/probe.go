package probe

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// magic prefixes every probe datagram so unrelated traffic is ignored.
var magic = [8]byte{'T', 'D', 'P', 'R', 'O', 'B', '1', '\x00'}

// Probe bursts are deliberately fast. The default OS UDP buffers are smaller
// than a 200-packet sweep at high rates, so a self-inflicted receive overflow
// would look exactly like network loss.
const socketBufferBytes = 4 << 20

// Result is one measurement.
type Result struct {
	Name       string   `json:"name"`
	Target     string   `json:"target"`
	Sent       uint64   `json:"sent"`
	Received   uint64   `json:"received"`
	LossPct    float64  `json:"loss_pct"`
	OutOfOrder uint64   `json:"out_of_order"`
	Duplicates uint64   `json:"duplicates"`
	MinMs      float64  `json:"min_ms"`
	MeanMs     float64  `json:"mean_ms"`
	P50Ms      float64  `json:"p50_ms"`
	P99Ms      float64  `json:"p99_ms"`
	MaxMs      float64  `json:"max_ms"`
	JitterMs   float64  `json:"jitter_ms"`
	Bytes      uint64   `json:"bytes,omitempty"`
	Mbps       float64  `json:"mbps,omitempty"`
	DurationMs float64  `json:"duration_ms,omitempty"`
	Verified   bool     `json:"verified,omitempty"`
	Note       string   `json:"note,omitempty"`
	Details    []string `json:"details,omitempty"`
	OK         bool     `json:"ok"`
}

func (r Result) String() string {
	if !r.OK {
		return fmt.Sprintf("%-16s %-22s FAILED: %s", r.Name, r.Target, r.Note)
	}
	if r.Bytes > 0 {
		status := "verified"
		if !r.Verified {
			status = "NOT verified"
		}
		note := r.Note
		if note != "" {
			note = "  " + note
		}
		return fmt.Sprintf("%-16s %-22s %-10s in %8.1f ms  %8.2f Mbps  %s%s",
			r.Name, r.Target, humanBytes(r.Bytes), r.DurationMs, r.Mbps, status, note)
	}
	// Three decimals: on a LAN or loopback the numbers that matter are tens of
	// microseconds, and two decimals would render every one of them as 0.00.
	return fmt.Sprintf("%-16s %-22s sent=%-6d recv=%-6d loss=%6.2f%%  ooo=%-5d dup=%-5d  rtt ms min/avg/p50/p99/max=%7.3f/%7.3f/%7.3f/%8.3f/%9.3f  jitter=%7.3f  %s",
		r.Name, r.Target, r.Sent, r.Received, r.LossPct, r.OutOfOrder, r.Duplicates,
		r.MinMs, r.MeanMs, r.P50Ms, r.P99Ms, r.MaxMs, r.JitterMs, r.Note)
}

func humanBytes(n uint64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.2f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// ---------------------------------------------------------------------------
// Echo server
// ---------------------------------------------------------------------------

// Server answers probe datagrams on both peers. It is always on so that either
// side can measure the other at any time.
type Server struct {
	conn    *net.UDPConn
	closed  chan struct{}
	once    sync.Once
	handled uint64
}

// StartServer binds the UDP echo port on every interface, as the tool needs.
// Prefer StartServerOn in tests and automation: a wildcard listening socket for
// an unsigned binary is what makes Windows raise a firewall/elevation dialog.
func StartServer(port int) (*Server, error) { return StartServerOn("0.0.0.0", port) }

// StartServerOn binds the UDP echo port on one address. Binding 127.0.0.1 needs
// no privileges and produces no firewall prompt, which keeps the test suite
// usable unattended. Pass port 0 to let the OS choose.
func StartServerOn(bind string, port int) (*Server, error) {
	if bind == "" {
		bind = "0.0.0.0"
	}
	a, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", bind, port))
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp4", a)
	if err != nil {
		return nil, fmt.Errorf("probe server bind udp/%s:%d: %w", bind, port, err)
	}
	_ = c.SetReadBuffer(socketBufferBytes)
	_ = c.SetWriteBuffer(socketBufferBytes)
	s := &Server{conn: c, closed: make(chan struct{})}
	go s.loop()
	return s, nil
}

// Addr reports the bound local address, useful when port 0 was requested.
func (s *Server) Addr() string {
	if s == nil || s.conn == nil {
		return ""
	}
	return s.conn.LocalAddr().String()
}

func (s *Server) loop() {
	buf := make([]byte, 2048)
	for {
		select {
		case <-s.closed:
			return
		default:
		}
		n, from, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
			}
			continue
		}
		if n < 16 || !prefixMatch(buf[:n]) {
			continue
		}
		// Echo verbatim: the client computes everything from the sequence
		// numbers it put in.
		_, _ = s.conn.WriteToUDP(buf[:n], from)
		s.handled++
	}
}

func prefixMatch(b []byte) bool {
	for i := range magic {
		if b[i] != magic[i] {
			return false
		}
	}
	return true
}

func (s *Server) Close() error {
	s.once.Do(func() {
		close(s.closed)
		_ = s.conn.Close()
	})
	return nil
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

type Client struct {
	conn *net.UDPConn
	rnd  *rand.Rand
}

// NewClient creates a probe client bound to any free interface.
func NewClient(localPort int) (*Client, error) { return NewClientOn("0.0.0.0", localPort) }

// NewClientOn creates a probe client bound to one local address. Tests bind to
// 127.0.0.1 so no wildcard listening socket is created and no elevation or
// firewall prompt is raised.
func NewClientOn(bind string, localPort int) (*Client, error) {
	if bind == "" {
		bind = "0.0.0.0"
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(bind), Port: localPort})
	if err != nil {
		return nil, fmt.Errorf("probe client bind %s:%d: %w", bind, localPort, err)
	}
	_ = c.SetReadBuffer(socketBufferBytes)
	_ = c.SetWriteBuffer(socketBufferBytes)
	return &Client{conn: c, rnd: rand.New(rand.NewSource(time.Now().UnixNano()))}, nil
}

func (c *Client) Close() error { return c.conn.Close() }

type opts struct {
	count     int
	size      int
	interval  time.Duration
	rateMbps  float64
	timeout   time.Duration
	burst     int
	payloadHi bool
}

// Option mutates a probe run.
type Option func(*opts)

func Count(n int) Option { return func(o *opts) { o.count = n } }
func Size(n int) Option  { return func(o *opts) { o.size = n } }
func Interval(d time.Duration) Option {
	return func(o *opts) { o.interval = d }
}
func Rate(mbps float64) Option { return func(o *opts) { o.rateMbps = mbps } }
func Timeout(d time.Duration) Option {
	return func(o *opts) { o.timeout = d }
}
func Burst(n int) Option { return func(o *opts) { o.burst = n } }

// paceUntil waits for an absolute deadline. time.Sleep alone is unsuitable for
// the sweep: on Windows a 0.4ms sleep can round up to the ~15.6ms scheduler
// tick, so a nominal 20 Mbps burst is actually paced below 1 Mbps. Sleep the
// coarse part and spin only the final millisecond or two.
func paceUntil(t time.Time) {
	for {
		d := time.Until(t)
		if d <= 0 {
			return
		}
		if d > 2*time.Millisecond {
			time.Sleep(d - time.Millisecond)
			continue
		}
		for time.Now().Before(t) {
		}
		return
	}
}

// RTT measures one-way-plus-reply latency and loss with an echo probe.
func (c *Client) RTT(target netip.Addr, port int, os ...Option) Result {
	o := opts{count: 50, size: 64, interval: 20 * time.Millisecond, timeout: 2 * time.Second}
	for _, f := range os {
		f(&o)
	}
	res := Result{Name: "udp-echo", Target: fmt.Sprintf("%s:%d", target, port), OK: true}
	dst := &net.UDPAddr{IP: net.IP(target.AsSlice()), Port: port}
	var mu sync.Mutex
	// The client keeps its own send times rather than trusting an echoed
	// timestamp: nothing about the reply's clock or content can then corrupt a
	// measurement, and a foreign responder on the port is rejected outright.
	sentAt := map[uint32]time.Time{}
	seen := map[uint32]struct{}{}
	// arrival records sequence numbers in the order they were actually
	// received; reordering must be judged by arrival order, and ranging over a
	// map yields an arbitrary order that would invent inversions.
	var arrival []uint32
	var samples []float64
	var unknown, rejected int
	stopRead := make(chan struct{})
	readerDone := make(chan struct{})
	progressCap := o.count
	if progressCap < 1 {
		progressCap = 1
	}
	// Capacity equals the packet count so a fast reader cannot drop the final
	// progress token and force the caller to wait for the whole timeout.
	progress := make(chan struct{}, progressCap)
	nonce := uint32(c.rnd.Uint64())

	go func() {
		defer close(readerDone)
		buf := make([]byte, 2048)
		for {
			select {
			case <-stopRead:
				return
			default:
			}
			// Short deadlines let this loop notice stopRead even when no reply
			// is arriving. The caller also forces a deadline to unblock the
			// current read, so shutdown does not wait for a full period.
			_ = c.conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			n, _, err := c.conn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-stopRead:
					return
				default:
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
			if n < 24 || !prefixMatch(buf[:n]) {
				continue
			}
			if binary.BigEndian.Uint32(buf[20:24]) != nonce {
				continue // someone else's traffic, or a stale reply
			}
			seq := binary.BigEndian.Uint32(buf[8:12])
			fresh := false
			mu.Lock()
			sent, mine := sentAt[seq]
			if !mine {
				unknown++
				mu.Unlock()
				continue
			}
			if _, dup := seen[seq]; dup {
				res.Duplicates++
			} else {
				seen[seq] = struct{}{}
				arrival = append(arrival, seq)
				fresh = true
				rtt := float64(time.Since(sent)) / float64(time.Millisecond)
				// Accept zero: on Windows the monotonic clock can resolve a fast
				// loopback round trip to zero ticks, and discarding those would
				// throw away every valid sample on a good path.
				if rtt >= 0 && rtt < 60000 {
					samples = append(samples, rtt)
				} else {
					rejected++
				}
			}
			mu.Unlock()
			if fresh {
				select {
				case progress <- struct{}{}:
				default:
				}
			}
		}
	}()

	if o.size < 24 {
		o.size = 24
	}
	start := time.Now()
	for i := 0; i < o.count; i++ {
		if o.rateMbps > 0 {
			due := start.Add(time.Duration(float64(i) * float64(o.size*8) / (o.rateMbps * 1e6) * float64(time.Second)))
			paceUntil(due)
		}
		pkt := make([]byte, o.size)
		copy(pkt, magic[:])
		binary.BigEndian.PutUint32(pkt[8:12], uint32(i))
		binary.BigEndian.PutUint32(pkt[20:24], nonce)
		// Pad only the payload area: filling from byte 8 would scribble over the
		// sequence number and the nonce.
		for j := 24; j < len(pkt); j++ {
			pkt[j] = byte(c.rnd.Intn(256))
		}
		mu.Lock()
		sentAt[uint32(i)] = time.Now()
		mu.Unlock()
		if _, err := c.conn.WriteToUDP(pkt, dst); err != nil {
			res.Note = "send: " + err.Error()
		}
		res.Sent++
		if o.rateMbps == 0 && o.interval > 0 {
			time.Sleep(o.interval)
		}
		if o.burst > 0 && i%o.burst == o.burst-1 {
			time.Sleep(o.interval)
		}
	}
	if o.count > 0 {
		timer := time.NewTimer(o.timeout)
	wait:
		for {
			select {
			case <-readerDone:
				break wait
			case <-progress:
				mu.Lock()
				got := len(seen)
				mu.Unlock()
				if got >= o.count {
					break wait
				}
			case <-timer.C:
				break wait
			}
		}
		timer.Stop()
	}
	// Stop the reader before returning. Leaving it alive made the next sweep
	// rate race this one for the same UDP socket, and the loser discarded the
	// winner's replies as "stale".
	close(stopRead)
	_ = c.conn.SetReadDeadline(time.Now())
	<-readerDone
	_ = c.conn.SetReadDeadline(time.Time{})
	mu.Lock()
	res.Received = uint64(len(seen))
	if res.Received == 0 && res.Sent > 0 && res.Note == "" {
		res.Note = "no authenticated replies - is tcpdiag running on the peer, and is udp/" + fmt.Sprint(port) + " reachable?"
	}
	if len(samples) > 0 && res.MaxMs == 0 {
		// Every round trip fell inside one clock tick. Reporting bare zeros
		// invites the wrong conclusion, so say what was actually measured.
		res.Note = "round trip is below the clock resolution of this host (a fast local path); loss and reordering figures remain valid"
	}
	if res.Received > 0 && len(samples) == 0 {
		// Say why, instead of printing a row of meaningless zeros.
		res.Note = fmt.Sprintf("no usable RTT sample: %d reply/replies had an unrecognised sequence number, %d were outside a plausible range", unknown, rejected)
	}
	if res.Sent > 0 {
		res.LossPct = 100 * float64(res.Sent-res.Received) / float64(res.Sent)
	}
	var highest uint32
	haveHighest := false
	for _, sq := range arrival {
		if haveHighest && sq < highest {
			res.OutOfOrder++
		}
		if !haveHighest || sq > highest {
			highest = sq
			haveHighest = true
		}
	}
	if len(samples) > 0 {
		sort.Float64s(samples)
		res.MinMs = samples[0]
		res.MaxMs = samples[len(samples)-1]
		var sum float64
		for _, s := range samples {
			sum += s
		}
		res.MeanMs = sum / float64(len(samples))
		res.P50Ms = samples[int(0.50*float64(len(samples)-1))]
		res.P99Ms = samples[int(math.Min(float64(len(samples)-1), math.Floor(0.99*float64(len(samples)-1))))]
		var dsum float64
		var last float64
		for i, s := range samples {
			if i > 0 {
				d := s - last
				if d < 0 {
					d = -d
				}
				dsum += d
			}
			last = s
		}
		if len(samples) > 1 {
			res.JitterMs = dsum / float64(len(samples)-1)
		}
	}
	mu.Unlock()
	if res.Received == 0 {
		res.OK = false
		if res.Note == "" {
			res.Note = "no replies - host unreachable, port filtered, or the peer is not running"
		}
	}
	return res
}

// LossSweep sends bursts at increasing rates and reports where loss appears.
// This is the test that separates "the link is fine" from "the link is fine
// until it is loaded", which is the usual root cause of dup-ACK storms.
func (c *Client) LossSweep(target netip.Addr, port int, rates []float64, perBurst int, size int) []Result {
	var out []Result
	for i, r := range rates {
		res := c.RTT(target, port, Count(perBurst), Size(size), Rate(r), Interval(0), Timeout(3*time.Second))
		res.Name = fmt.Sprintf("sweep-%.0fMbps", r)
		if res.Received == 0 && len(out) > 0 && out[len(out)-1].Received > 0 {
			// A perfectly reachable peer that answered the previous rate did
			// not become "unreachable" between bursts. This is a valid loss
			// measurement, not a failed probe.
			res.OK = true
			res.Note = fmt.Sprintf("no replies at this offered rate, although %.0f Mbps worked: the burst was dropped on the path or by the receiver", rates[i-1])
		}
		out = append(out, res)
		time.Sleep(300 * time.Millisecond)
	}
	return out
}

// Handshake measures TCP connection setup cost, which catches SYN loss and
// firewall/NAT interference that never shows up in bulk-transfer statistics.
func Handshake(target string, count int, interval time.Duration) Result {
	res := Result{Name: "tcp-connect", Target: target, OK: true}
	var samples []float64
	for i := 0; i < count; i++ {
		start := time.Now()
		d := net.Dialer{Timeout: 3 * time.Second}
		conn, err := d.Dial("tcp4", target)
		if err != nil {
			res.Note = err.Error()
			continue
		}
		samples = append(samples, float64(time.Since(start).Microseconds())/1000.0)
		res.Received++
		_ = conn.Close()
		res.Sent++
		if interval > 0 {
			time.Sleep(interval)
		}
	}
	if len(samples) > 0 {
		sort.Float64s(samples)
		res.MinMs, res.MaxMs = samples[0], samples[len(samples)-1]
		var sum float64
		for _, s := range samples {
			sum += s
		}
		res.MeanMs = sum / float64(len(samples))
		res.P50Ms = samples[len(samples)/2]
		res.P99Ms = samples[len(samples)-1]
	}
	if res.Sent == 0 {
		res.OK = false
	} else {
		res.LossPct = 100 * float64(res.Sent-res.Received) / float64(res.Sent)
	}
	return res
}
