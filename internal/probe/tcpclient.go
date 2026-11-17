package probe

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"sort"
	"time"
)

func dialTCPProbe(target string, timeout time.Duration, noDelay bool) (*net.TCPConn, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.Dial("tcp4", target)
	if err != nil {
		return nil, err
	}
	tc, ok := c.(*net.TCPConn)
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("tcp probe: not a TCP connection")
	}
	_ = tc.SetNoDelay(noDelay)
	_ = tc.SetReadBuffer(socketBufferBytes)
	_ = tc.SetWriteBuffer(socketBufferBytes)
	return tc, nil
}

func summarizeSamples(res *Result, samples []float64) {
	if len(samples) == 0 {
		return
	}
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
	var dsum, last float64
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

// TCPHandshake measures repeated connect+zero-byte-echo cycles against the
// always-on TCP probe service. The echo is what proves this is tcpdiag's TCP
// service and that the connection can actually carry a byte in both directions.
func TCPHandshake(target string, count int, interval, timeout time.Duration) Result {
	res := Result{Name: "tcp-handshake", Target: target, OK: true}
	if count <= 0 {
		count = 1
	}
	var samples []float64
	var lastErr error
	for i := 0; i < count; i++ {
		res.Sent++
		start := time.Now()
		c, err := dialTCPProbe(target, timeout, true)
		if err != nil {
			lastErr = err
			time.Sleep(interval)
			continue
		}
		_ = c.SetDeadline(time.Now().Add(timeout))
		h := tcpHeader{Type: tcpMsgEcho, Nonce: rand.Uint32(), Seq: uint32(i)}
		if err := writeAll(c, h.marshal()); err != nil {
			lastErr = err
			_ = c.Close()
			time.Sleep(interval)
			continue
		}
		rh, err := readTCPHeader(c)
		if err != nil {
			lastErr = err
			_ = c.Close()
			time.Sleep(interval)
			continue
		}
		if rh.Type != h.Type || rh.Flags&tcpFlagResponse == 0 || rh.Nonce != h.Nonce || rh.Seq != h.Seq || rh.Length != 0 {
			lastErr = fmt.Errorf("unexpected echo response")
			_ = c.Close()
			time.Sleep(interval)
			continue
		}
		samples = append(samples, float64(time.Since(start).Microseconds())/1000)
		res.Received++
		_ = c.Close()
		time.Sleep(interval)
	}
	summarizeSamples(&res, samples)
	if res.Sent > 0 {
		res.LossPct = 100 * float64(res.Sent-res.Received) / float64(res.Sent)
	}
	if res.Received == 0 {
		res.OK = false
		res.Note = "no successful TCP handshake+echo"
		if lastErr != nil {
			res.Note += ": " + lastErr.Error()
		}
	}
	return res
}

// TCPEcho sends request/response frames over one TCP connection. Small sizes
// exercise the delayed-ACK/Nagle path; larger sizes exercise stream delivery.
func TCPEcho(target, name string, count, size int, interval, timeout time.Duration, noDelay bool) Result {
	res := Result{Name: name, Target: target, OK: true}
	if count <= 0 {
		return res
	}
	if size < 0 {
		size = 0
	}
	if size > 1<<20 {
		size = 1 << 20
	}
	c, err := dialTCPProbe(target, timeout, noDelay)
	if err != nil {
		res.Sent = uint64(count)
		res.OK = false
		res.Note = "dial: " + err.Error()
		return res
	}
	defer c.Close()
	nonce := rand.Uint32()
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(rand.Intn(256))
	}
	var samples []float64
	var lastErr error
	for i := 0; i < count; i++ {
		_ = c.SetDeadline(time.Now().Add(timeout))
		h := tcpHeader{Type: tcpMsgEcho, Nonce: nonce, Seq: uint32(i), Length: uint32(size)}
		start := time.Now()
		if err := writeAll(c, h.marshal()); err != nil {
			lastErr = err
			break
		}
		if err := writeAll(c, payload); err != nil {
			lastErr = err
			break
		}
		rh, err := readTCPHeader(c)
		if err != nil {
			lastErr = err
			break
		}
		if rh.Type != h.Type || rh.Flags&tcpFlagResponse == 0 || rh.Nonce != nonce || rh.Seq != uint32(i) || rh.Length != uint32(size) {
			lastErr = fmt.Errorf("unexpected echo response at seq %d", i)
			break
		}
		if size > 0 {
			body := make([]byte, size)
			if _, err := io.ReadFull(c, body); err != nil {
				lastErr = err
				break
			}
			if !bytes.Equal(body, payload) {
				lastErr = fmt.Errorf("echo payload mismatch at seq %d", i)
				break
			}
		}
		samples = append(samples, float64(time.Since(start).Microseconds())/1000)
		res.Received++
		if interval > 0 {
			time.Sleep(interval)
		}
	}
	res.Sent = uint64(count)
	if res.Sent > 0 {
		res.LossPct = 100 * float64(res.Sent-res.Received) / float64(res.Sent)
	}
	summarizeSamples(&res, samples)
	if lastErr != nil {
		res.Note = lastErr.Error()
	}
	if res.Received == 0 {
		res.OK = false
		if res.Note == "" {
			res.Note = "no TCP echo replies"
		}
	}
	return res
}

// TCPTransfer verifies a bulk stream in one direction using a deterministic
// pattern and CRC32, so throughput cannot be inflated by a truncated transfer.
func TCPTransfer(target, name string, n int, upload bool, timeout time.Duration, noDelay bool) Result {
	res := Result{Name: name, Target: target, OK: true}
	if n <= 0 {
		n = 1
	}
	c, err := dialTCPProbe(target, timeout, noDelay)
	if err != nil {
		res.OK = false
		res.Note = "dial: " + err.Error()
		return res
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	seed := rand.Uint32()
	nonce := rand.Uint32()
	start := time.Now()
	verified := false
	switch {
	case upload:
		h := tcpHeader{Type: tcpMsgUpload, Nonce: nonce, Seq: seed, Length: uint32(n)}
		if err := writeAll(c, h.marshal()); err != nil {
			res.OK = false
			res.Note = "write: " + err.Error()
			return res
		}
		expected, err := writePattern(c, seed, n)
		if err != nil {
			res.OK = false
			res.Note = "upload: " + err.Error()
			return res
		}
		rh, err := readTCPHeader(c)
		if err != nil {
			res.OK = false
			res.Note = "response: " + err.Error()
			return res
		}
		if rh.Type != tcpMsgUpload || rh.Flags&tcpFlagResponse == 0 || rh.Nonce != nonce || rh.Seq != seed || rh.Length != 4 {
			res.OK = false
			res.Note = "unexpected upload response"
			return res
		}
		got, err := readCRC32(c)
		if err != nil {
			res.OK = false
			res.Note = "crc: " + err.Error()
			return res
		}
		verified = got == expected
	default:
		h := tcpHeader{Type: tcpMsgDownload, Nonce: seed, Length: uint32(n)}
		if err := writeAll(c, h.marshal()); err != nil {
			res.OK = false
			res.Note = "write: " + err.Error()
			return res
		}
		rh, err := readTCPHeader(c)
		if err != nil {
			res.OK = false
			res.Note = "response: " + err.Error()
			return res
		}
		if rh.Type != tcpMsgDownload || rh.Flags&tcpFlagResponse == 0 || rh.Nonce != seed || rh.Length != uint32(n) {
			res.OK = false
			res.Note = "unexpected download response"
			return res
		}
		got, err := readPatternCRC(c, n)
		if err != nil {
			res.OK = false
			res.Note = "download: " + err.Error()
			return res
		}
		expected, _ := writePattern(io.Discard, seed, n)
		verified = got == expected
	}
	d := time.Since(start)
	res.Bytes = uint64(n)
	res.Sent = uint64(n)
	if verified {
		res.Received = uint64(n)
	}
	res.DurationMs = float64(d.Microseconds()) / 1000
	if d > 0 {
		res.Mbps = float64(n*8) / d.Seconds() / 1e6
	}
	res.Verified = verified
	res.OK = verified
	if !verified {
		res.Note = "CRC mismatch - transfer was corrupted or truncated"
	}
	return res
}

// TCPDuplex sends and receives bulk streams at the same time on one connection.
// This is the probe that stresses ACK return-path behaviour, not just raw
// one-way throughput.
func TCPDuplex(target string, n int, timeout time.Duration, noDelay bool) Result {
	res := Result{Name: "tcp-duplex", Target: target, OK: true}
	if n <= 0 {
		n = 1
	}
	c, err := dialTCPProbe(target, timeout, noDelay)
	if err != nil {
		res.OK = false
		res.Note = "dial: " + err.Error()
		return res
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	downSeed := rand.Uint32()
	upSeed := rand.Uint32()
	start := time.Now()
	h := tcpHeader{Type: tcpMsgDuplex, Nonce: downSeed, Seq: upSeed, Length: uint32(n)}
	if err := writeAll(c, h.marshal()); err != nil {
		res.OK = false
		res.Note = "write: " + err.Error()
		return res
	}
	type upResult struct {
		crc uint32
		dur time.Duration
		err error
	}
	up := make(chan upResult, 1)
	go func() {
		s := time.Now()
		crc, err := writePattern(c, upSeed, n)
		up <- upResult{crc: crc, dur: time.Since(s), err: err}
	}()
	rh, err := readTCPHeader(c)
	if err != nil {
		res.OK = false
		res.Note = "response: " + err.Error()
		return res
	}
	if rh.Type != tcpMsgDuplex || rh.Flags&tcpFlagResponse == 0 || rh.Nonce != downSeed || rh.Length != uint32(n) {
		res.OK = false
		res.Note = "unexpected duplex response"
		return res
	}
	downStart := time.Now()
	gotDown, err := readPatternCRC(c, n)
	downDur := time.Since(downStart)
	if err != nil {
		res.OK = false
		res.Note = "download: " + err.Error()
		return res
	}
	rh2, err := readTCPHeader(c)
	if err != nil {
		res.OK = false
		res.Note = "upload response: " + err.Error()
		return res
	}
	if rh2.Type != tcpMsgDuplex || rh2.Flags&tcpFlagResponse == 0 || rh2.Nonce != downSeed || rh2.Seq != upSeed || rh2.Length != 4 {
		res.OK = false
		res.Note = "unexpected duplex upload response"
		return res
	}
	gotUp, err := readCRC32(c)
	if err != nil {
		res.OK = false
		res.Note = "upload crc: " + err.Error()
		return res
	}
	ur := <-up
	if ur.err != nil {
		res.OK = false
		res.Note = "upload: " + ur.err.Error()
		return res
	}
	expectedDown, _ := writePattern(io.Discard, downSeed, n)
	verified := gotDown == expectedDown && gotUp == ur.crc
	d := time.Since(start)
	res.Bytes = uint64(2 * n)
	res.DurationMs = float64(d.Microseconds()) / 1000
	if d > 0 {
		res.Mbps = float64(2*n*8) / d.Seconds() / 1e6
	}
	upMbps, downMbps := 0.0, 0.0
	if ur.dur > 0 {
		upMbps = float64(n*8) / ur.dur.Seconds() / 1e6
	}
	if downDur > 0 {
		downMbps = float64(n*8) / downDur.Seconds() / 1e6
	}
	res.Verified = verified
	res.OK = verified
	res.Note = fmt.Sprintf("up %.2f Mbps, down %.2f Mbps", upMbps, downMbps)
	if !verified {
		res.Note = "CRC mismatch - " + res.Note
	}
	return res
}
