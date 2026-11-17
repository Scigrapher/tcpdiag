package probe

import (
	"net"
	"strconv"
	"testing"
	"time"
)

func loopbackTCPServer(t *testing.T) (addr string) {
	t.Helper()
	srv, err := StartTCPServerOn("127.0.0.1", 0)
	if err != nil {
		t.Skipf("cannot bind loopback TCP probe server (%v); skipping network test", err)
	}
	t.Cleanup(func() { srv.Close() })
	return srv.Addr()
}

func TestTCPHandshakeAndEcho(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network probe test in short mode")
	}
	addr := loopbackTCPServer(t)
	if res := TCPHandshake(addr, 10, 0, 2*time.Second); res.Received != 10 {
		t.Fatalf("handshake received %d/10: %s", res.Received, res.Note)
	}
	if res := TCPEcho(addr, "tcp-echo", 100, 64, 0, 2*time.Second, true); res.Received != 100 {
		t.Fatalf("echo received %d/100: %s", res.Received, res.Note)
	}
	if res := TCPEcho(addr, "tcp-small", 300, 1, 0, 2*time.Second, true); res.Received != 300 {
		t.Fatalf("small-write echo received %d/300: %s", res.Received, res.Note)
	}
}

func TestTCPBulkTransfersAndDuplex(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network probe test in short mode")
	}
	addr := loopbackTCPServer(t)
	const n = 256 << 10
	for _, tc := range []struct {
		name   string
		upload bool
	}{
		{"tcp-upload", true},
		{"tcp-download", false},
	} {
		res := TCPTransfer(addr, tc.name, n, tc.upload, 5*time.Second, true)
		if !res.OK || !res.Verified {
			t.Fatalf("%s failed: %s", tc.name, res.Note)
		}
		t.Log(res.String())
	}
	res := TCPDuplex(addr, n, 5*time.Second, true)
	if !res.OK || !res.Verified {
		t.Fatalf("tcp-duplex failed: %s", res.Note)
	}
	t.Log(res.String())
}

// Keep the address parser honest for the helper above.
func TestTCPProbeAddrParses(t *testing.T) {
	addr := loopbackTCPServer(t)
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" {
		t.Fatalf("host=%q", host)
	}
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatalf("port=%q: %v", port, err)
	}
}
