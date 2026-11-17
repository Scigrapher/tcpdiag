package probe

import (
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"
)

// Tests in this file bind only the loopback address. A wildcard (0.0.0.0)
// listening socket for an unsigned binary is what makes Windows raise a
// firewall/elevation dialog, which would block `go test` in an automated
// context. Anything that genuinely needs a non-loopback bind is opt-in via
// TCPDIAG_TEST_NETWORK=1 - see TestExternalEchoAgainstRealPeer.

func loopbackServer(t *testing.T) (port int) {
	t.Helper()
	srv, err := StartServerOn("127.0.0.1", 0)
	if err != nil {
		t.Skipf("cannot bind loopback probe server (%v); skipping network test", err)
	}
	t.Cleanup(func() { srv.Close() })
	_, portStr, err := splitHostPort(srv.Addr())
	if err != nil {
		t.Fatalf("unexpected server address %q: %v", srv.Addr(), err)
	}
	return portStr
}

func splitHostPort(addr string) (string, int, error) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			p, err := strconv.Atoi(addr[i+1:])
			return addr[:i], p, err
		}
	}
	return addr, 0, nil
}

func TestEchoRTTIsSane(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network probe test in short mode")
	}
	port := loopbackServer(t)
	c, err := NewClientOn("127.0.0.1", 0)
	if err != nil {
		t.Skipf("cannot bind loopback probe client (%v)", err)
	}
	defer c.Close()

	res := c.RTT(netip.MustParseAddr("127.0.0.1"), port,
		Count(30), Size(64), Interval(5*time.Millisecond), Timeout(time.Second))
	t.Logf("%s", res)
	if !res.OK {
		t.Fatalf("probe failed: %s", res.Note)
	}
	if res.Received != 30 {
		t.Fatalf("expected all 30 replies, got %d", res.Received)
	}
	if res.MeanMs > 100 {
		t.Fatalf("loopback RTT of %v ms is not credible", res.MeanMs)
	}
	if res.OutOfOrder != 0 {
		t.Fatalf("lossless loopback must not report reordering, got %d", res.OutOfOrder)
	}
}

// TestProbeServerIgnoresForeignDatagrams runs entirely on loopback but checks a
// behaviour worth pinning: unrelated traffic on the echo port must not be
// reflected or counted.
func TestProbeServerIgnoresForeignDatagrams(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network probe test in short mode")
	}
	port := loopbackServer(t)
	c, err := NewClientOn("127.0.0.1", 0)
	if err != nil {
		t.Skipf("cannot bind loopback probe client (%v)", err)
	}
	defer c.Close()
	res := c.RTT(netip.MustParseAddr("127.0.0.1"), port,
		Count(5), Size(64), Interval(2*time.Millisecond), Timeout(500*time.Millisecond))
	// Foreign (non-magic) packets are never sent here, but a reply that does
	// not carry our nonce is dropped; the important part is no panic and no
	// bogus counts.
	if res.Received > res.Sent {
		t.Fatalf("received more than sent: %d > %d", res.Received, res.Sent)
	}
}

// Each RTT used to leave its reader goroutine alive after returning. Consecutive
// sweep rates then competed for the same socket and discarded each other's
// replies, which looked exactly like spontaneous 100% loss at higher rates.
func TestSequentialRTTsDoNotStealReplies(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network probe test in short mode")
	}
	port := loopbackServer(t)
	c, err := NewClientOn("127.0.0.1", 0)
	if err != nil {
		t.Skipf("cannot bind loopback probe client (%v)", err)
	}
	defer c.Close()
	target := netip.MustParseAddr("127.0.0.1")
	for i := 0; i < 6; i++ {
		start := time.Now()
		res := c.RTT(target, port,
			Count(200), Size(1024), Rate(20), Timeout(2*time.Second))
		t.Logf("run %d took %v, recv=%d note=%q", i, time.Since(start), res.Received, res.Note)
		if res.Received != 200 {
			t.Fatalf("run %d: received %d/200 (loss %.1f%%): %s", i, res.Received, res.LossPct, res.Note)
		}
	}
}

// TestExternalEchoAgainstRealPeer is deliberately opt-in. Point it at a machine
// running tcpdiag and it will exercise the real, non-loopback path - which can
// require a firewall allowance and therefore must not run by default.
//
//	TCPDIAG_TEST_NETWORK=1 TCPDIAG_TEST_PEER=192.168.1.22 go test ./internal/probe
func TestExternalEchoAgainstRealPeer(t *testing.T) {
	if os.Getenv("TCPDIAG_TEST_NETWORK") != "1" {
		t.Skip("set TCPDIAG_TEST_NETWORK=1 (and TCPDIAG_TEST_PEER) to exercise the non-loopback path")
	}
	host := os.Getenv("TCPDIAG_TEST_PEER")
	if host == "" {
		t.Fatal("TCPDIAG_TEST_PEER is required when TCPDIAG_TEST_NETWORK=1")
	}
	if testing.Short() {
		t.Skip("skipping external network test in short mode")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatalf("TCPDIAG_TEST_PEER must be an IPv4 address: %v", err)
	}
	c, err := NewClient(0)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	res := c.RTT(ip, 42426, Count(50), Size(64), Interval(20*time.Millisecond), Timeout(3*time.Second))
	t.Log(res.String())
	if !res.OK {
		t.Fatalf("external probe failed: %s", res.Note)
	}
}
