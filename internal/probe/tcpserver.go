package probe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// The TCP probe service is deliberately separate from tcpdiag's diagnostic
// data plane. It is an ordinary OS TCP listener, so it is measurable no matter
// whether the instance runs --stack=kernel, raw, both or observe.
var tcpMagic = [8]byte{'T', 'D', 'T', 'C', 'P', '0', '1', 0}

const (
	tcpHeaderSize   = 24
	tcpMaxPayload   = 64 << 20
	tcpMsgEcho      = 1
	tcpMsgUpload    = 2
	tcpMsgDownload  = 3
	tcpMsgDuplex    = 4
	tcpFlagResponse = 1 << 0
	tcpPatternChunk = 32 << 10
)

type tcpHeader struct {
	Type   uint8
	Flags  uint8
	Nonce  uint32
	Seq    uint32
	Length uint32
}

func (h tcpHeader) marshal() []byte {
	b := make([]byte, tcpHeaderSize)
	copy(b[0:8], tcpMagic[:])
	b[8] = h.Type
	b[9] = h.Flags
	binary.BigEndian.PutUint32(b[12:16], h.Nonce)
	binary.BigEndian.PutUint32(b[16:20], h.Seq)
	binary.BigEndian.PutUint32(b[20:24], h.Length)
	return b
}

func readTCPHeader(r io.Reader) (tcpHeader, error) {
	var h tcpHeader
	b := make([]byte, tcpHeaderSize)
	if _, err := io.ReadFull(r, b); err != nil {
		return h, err
	}
	if !bytes.Equal(b[0:8], tcpMagic[:]) {
		return h, errors.New("tcp probe: bad magic")
	}
	h.Type = b[8]
	h.Flags = b[9]
	h.Nonce = binary.BigEndian.Uint32(b[12:16])
	h.Seq = binary.BigEndian.Uint32(b[16:20])
	h.Length = binary.BigEndian.Uint32(b[20:24])
	if h.Length > tcpMaxPayload {
		return h, fmt.Errorf("tcp probe: payload %d exceeds limit", h.Length)
	}
	return h, nil
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

// patternStream is a deterministic, allocation-free byte source. Both ends can
// regenerate exactly the same bytes, so a transfer can be verified end to end
// without trusting the peer's accounting.
func patternState(seed uint32) uint32 {
	if seed == 0 {
		return 0x9e3779b9
	}
	return seed
}

func patternByte(state *uint32) byte {
	x := *state
	x ^= x << 13
	x ^= x >> 17
	x ^= x << 5
	*state = x
	return byte(x >> 24)
}

func fillPattern(b []byte, state *uint32) {
	for i := range b {
		b[i] = patternByte(state)
	}
}

func writePattern(w io.Writer, seed uint32, n int) (uint32, error) {
	state := patternState(seed)
	crc := crc32.NewIEEE()
	buf := make([]byte, tcpPatternChunk)
	for n > 0 {
		m := len(buf)
		if n < m {
			m = n
		}
		fillPattern(buf[:m], &state)
		if err := writeAll(w, buf[:m]); err != nil {
			return 0, err
		}
		_, _ = crc.Write(buf[:m])
		n -= m
	}
	return crc.Sum32(), nil
}

func readPatternCRC(r io.Reader, n int) (uint32, error) {
	crc := crc32.NewIEEE()
	buf := make([]byte, tcpPatternChunk)
	for n > 0 {
		m := len(buf)
		if n < m {
			m = n
		}
		if _, err := io.ReadFull(r, buf[:m]); err != nil {
			return 0, err
		}
		_, _ = crc.Write(buf[:m])
		n -= m
	}
	return crc.Sum32(), nil
}

func writeCRC32(w io.Writer, v uint32) error {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return writeAll(w, b[:])
}

func readCRC32(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

// TCPServer is the always-on OS TCP probe responder.
type TCPServer struct {
	ln      net.Listener
	closed  chan struct{}
	once    sync.Once
	handled atomic.Uint64
}

// StartTCPServer binds the TCP probe port on every interface. Prefer
// StartTCPServerOn in tests and automation, for the same firewall/elevation
// reasons as the UDP echo server.
func StartTCPServer(port int) (*TCPServer, error) {
	return StartTCPServerOn("0.0.0.0", port)
}

func StartTCPServerOn(bind string, port int) (*TCPServer, error) {
	if bind == "" {
		bind = "0.0.0.0"
	}
	ln, err := net.Listen("tcp4", net.JoinHostPort(bind, strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("tcp probe server bind %s:%d: %w", bind, port, err)
	}
	s := &TCPServer{ln: ln, closed: make(chan struct{})}
	go s.loop()
	return s, nil
}

func (s *TCPServer) Addr() string {
	if s == nil || s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

func (s *TCPServer) Close() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		close(s.closed)
		_ = s.ln.Close()
	})
	return nil
}

func (s *TCPServer) loop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
			}
			time.Sleep(20 * time.Millisecond)
			continue
		}
		go s.handle(c)
	}
}

func (s *TCPServer) handle(c net.Conn) {
	defer c.Close()
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetReadBuffer(socketBufferBytes)
		_ = tc.SetWriteBuffer(socketBufferBytes)
	}
	for {
		h, err := readTCPHeader(c)
		if err != nil {
			return
		}
		if h.Flags&tcpFlagResponse != 0 {
			return
		}
		switch h.Type {
		case tcpMsgEcho:
			payload := make([]byte, int(h.Length))
			if _, err := io.ReadFull(c, payload); err != nil {
				return
			}
			resp := h
			resp.Flags |= tcpFlagResponse
			if err := writeAll(c, resp.marshal()); err != nil {
				return
			}
			if err := writeAll(c, payload); err != nil {
				return
			}
			s.handled.Add(1)
		case tcpMsgUpload:
			crc, err := readPatternCRC(c, int(h.Length))
			if err != nil {
				return
			}
			resp := h
			resp.Flags |= tcpFlagResponse
			resp.Length = 4
			if err := writeAll(c, resp.marshal()); err != nil {
				return
			}
			_ = writeCRC32(c, crc)
			s.handled.Add(1)
			return
		case tcpMsgDownload:
			resp := h
			resp.Flags |= tcpFlagResponse
			if err := writeAll(c, resp.marshal()); err != nil {
				return
			}
			if _, err := writePattern(c, h.Nonce, int(h.Length)); err != nil {
				return
			}
			s.handled.Add(1)
			return
		case tcpMsgDuplex:
			type uploadResult struct {
				crc uint32
				err error
			}
			up := make(chan uploadResult, 1)
			go func() {
				crc, err := readPatternCRC(c, int(h.Length))
				up <- uploadResult{crc: crc, err: err}
			}()
			resp := h
			resp.Flags |= tcpFlagResponse
			if err := writeAll(c, resp.marshal()); err != nil {
				return
			}
			if _, err := writePattern(c, h.Nonce, int(h.Length)); err != nil {
				return
			}
			r := <-up
			if r.err != nil {
				return
			}
			done := tcpHeader{Type: tcpMsgDuplex, Flags: tcpFlagResponse, Nonce: h.Nonce, Seq: h.Seq, Length: 4}
			if err := writeAll(c, done.marshal()); err != nil {
				return
			}
			_ = writeCRC32(c, r.crc)
			s.handled.Add(1)
			return
		default:
			return
		}
	}
}
