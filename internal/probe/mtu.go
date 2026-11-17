package probe

import (
	"fmt"
	"net"
	"net/netip"
	"time"
)

// PathMTU discovers the largest payload that traverses the path, using the DF
// bit. A path that works at 1472 but not at, say, 1400 with no ICMP feedback
// is a PMTU blackhole - a classic cause of "some connections stall and then
// retransmit forever" that looks like random loss in a single-ended capture.
func PathMTU(dst netip.Addr, port int) Result {
	res := Result{Name: "path-mtu", Target: fmt.Sprintf("%s:%d", dst, port), OK: true}
	sizes := []int{1472, 1400, 1300, 1200, 1100, 1000, 800, 600, 400, 200, 100}
	d := net.Dialer{Timeout: 2 * time.Second, Control: dfControl()}
	for _, size := range sizes {
		conn, err := d.Dial("udp4", net.JoinHostPort(dst.String(), fmt.Sprint(port)))
		if err != nil {
			res.Note = fmt.Sprintf("dial failed: %v", err)
			return res
		}
		pkt := make([]byte, size)
		copy(pkt, magic[:])
		for i := 8; i < size; i++ {
			pkt[i] = byte(i)
		}
		ok := 0
		var lastErr string
		for i := 0; i < 4; i++ {
			_, err := conn.Write(pkt)
			if err != nil {
				lastErr = err.Error()
				break
			}
			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			b := make([]byte, 2048)
			n, err := conn.Read(b)
			if err != nil {
				lastErr = err.Error()
				continue
			}
			if n >= 8 && prefixMatch(b[:n]) {
				ok++
			}
		}
		_ = conn.Close()
		line := fmt.Sprintf("payload %4d B (ip %4d B): %d/4 echoed", size, size+28, ok)
		if lastErr != "" {
			line += " last=" + lastErr
		}
		res.Details = append(res.Details, line)
		if ok >= 3 {
			res.Note = fmt.Sprintf("largest working payload %d bytes => path MTU about %d", size, size+28)
			res.Received = uint64(ok)
			res.Sent = 4
			break
		}
		res.Sent += 4
	}
	return res
}
