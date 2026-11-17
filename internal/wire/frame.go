package wire

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Frame types. Everything the two instances exchange rides on one framing
// protocol so that kernel-stack and raw-stack runs are byte-for-byte comparable.
type MsgType uint8

const (
	MsgHandshake  MsgType = 1 // hello: capability + role negotiation
	MsgHandshakeA MsgType = 2 // hello ack
	MsgData       MsgType = 3 // continuous data block, carries an embedded Snapshot
	MsgAck        MsgType = 4 // cumulative ack + Snapshot (used by kernel stack keepalives)
	MsgPing       MsgType = 5 // one-way latency probe
	MsgPong       MsgType = 6
	MsgGoodbye    MsgType = 7
	MsgResume     MsgType = 8 // re-attach a stream after a reconnect, carries chain state
)

const (
	FlagFin        uint16 = 1 << 0
	FlagImpaired   uint16 = 1 << 1 // sender applied artificial impairment to this block
	FlagReplay     uint16 = 1 << 2 // sender is deliberately replaying an old block
	FlagChainReset uint16 = 1 << 3 // receiver should reset its chain expectation
	FlagPriority   uint16 = 1 << 4
)

const (
	Version    uint8  = 1
	HeaderSize        = 64
	magic      uint16 = 0x5444 // "TD"
	// DigestSize is the truncated SHA-256 length carried in the header.
	DigestSize = 16
)

var (
	ErrBadMagic   = errors.New("tcpdiag: bad frame magic")
	ErrBadVersion = errors.New("tcpdiag: unsupported frame version")
	ErrTooLarge   = errors.New("tcpdiag: frame exceeds size limit")
)

// MaxPayload is generous but bounded so a desynchronised stream cannot OOM us.
const MaxPayload = 8 << 20

type Header struct {
	Type           MsgType
	Flags          uint16
	BlockSeq       uint64 // nth data block of this direction
	StreamOffset   uint64 // byte offset of this block in the logical send stream
	PayloadLen     uint32
	ReportLen      uint32
	PrevSentDigest [DigestSize]byte
	RecvDigest     [DigestSize]byte
}

type Frame struct {
	H       Header
	Report  []byte // JSON-encoded Snapshot (may be nil)
	Payload []byte
}

func (h *Header) Marshal(dst []byte) {
	binary.BigEndian.PutUint16(dst[0:2], magic)
	dst[2] = Version
	dst[3] = byte(h.Type)
	binary.BigEndian.PutUint16(dst[4:6], h.Flags)
	binary.BigEndian.PutUint64(dst[6:14], h.BlockSeq)
	binary.BigEndian.PutUint64(dst[14:22], h.StreamOffset)
	binary.BigEndian.PutUint32(dst[22:26], h.PayloadLen)
	binary.BigEndian.PutUint32(dst[26:30], h.ReportLen)
	copy(dst[30:46], h.PrevSentDigest[:])
	copy(dst[46:62], h.RecvDigest[:])
	binary.BigEndian.PutUint16(dst[62:64], 0)
}

func ParseHeader(src []byte) (Header, error) {
	var h Header
	if len(src) < HeaderSize {
		return h, io.ErrUnexpectedEOF
	}
	if binary.BigEndian.Uint16(src[0:2]) != magic {
		return h, ErrBadMagic
	}
	if src[2] != Version {
		return h, ErrBadVersion
	}
	h.Type = MsgType(src[3])
	h.Flags = binary.BigEndian.Uint16(src[4:6])
	h.BlockSeq = binary.BigEndian.Uint64(src[6:14])
	h.StreamOffset = binary.BigEndian.Uint64(src[14:22])
	h.PayloadLen = binary.BigEndian.Uint32(src[22:26])
	h.ReportLen = binary.BigEndian.Uint32(src[26:30])
	copy(h.PrevSentDigest[:], src[30:46])
	copy(h.RecvDigest[:], src[46:62])
	return h, nil
}

// WriteFrame serialises one frame. It is a single Write so that, in raw mode,
// small frames tend to leave as a single segment: useful when correlating what
// the wire actually carried with what the application intended.
func WriteFrame(w io.Writer, f *Frame) error {
	pl, rl := uint32(len(f.Payload)), uint32(len(f.Report))
	if pl > MaxPayload {
		return ErrTooLarge
	}
	h := f.H
	h.PayloadLen, h.ReportLen = pl, rl
	buf := make([]byte, HeaderSize+int(rl)+int(pl))
	h.Marshal(buf)
	copy(buf[HeaderSize:], f.Report)
	copy(buf[HeaderSize+int(rl):], f.Payload)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one frame. Reader should be buffered for performance.
func ReadFrame(r io.Reader) (*Frame, error) {
	hb := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, hb); err != nil {
		return nil, err
	}
	h, err := ParseHeader(hb)
	if err != nil {
		return nil, err
	}
	if h.PayloadLen > MaxPayload || h.ReportLen > MaxPayload {
		return nil, ErrTooLarge
	}
	f := &Frame{H: h}
	n := int(h.ReportLen) + int(h.PayloadLen)
	if n == 0 {
		return f, nil
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	f.Report = body[:h.ReportLen]
	f.Payload = body[h.ReportLen:]
	return f, nil
}

// ---------------------------------------------------------------------------
// Causal chain
// ---------------------------------------------------------------------------
//
// Two interlocking hashes make a one-sided diagnosis possible:
//
//  1. PrevSentDigest links every block a peer *transmits* into a hash chain.
//     A receiver that sees block N whose PrevSentDigest does not match the
//     chain value it computed for block N-1 knows something was dropped,
//     duplicated, or reordered, even when every received byte is intact.
//
//  2. RecvDigest is the chain head of the blocks that peer has *correctly
//     received* - and it seeds the keystream that generates its payload. So a
//     payload that verifies proves, cryptographically, that the blocks the
//     sender believed it had received really did arrive. Loss can therefore be
//     attributed to a direction from a single observation point.

// ChainNext advances a chain head by absorbing one block.
func ChainNext(prev [DigestSize]byte, blockSeq uint64, payload []byte) [DigestSize]byte {
	h := sha256.New()
	h.Write(prev[:])
	var sb [8]byte
	binary.BigEndian.PutUint64(sb[:], blockSeq)
	h.Write(sb[:])
	h.Write(payload)
	var out [DigestSize]byte
	copy(out[:], h.Sum(nil)[:DigestSize])
	return out
}

// Keystream fills out with the deterministic payload for a block. It depends on
// the shared session seed, the block number, AND the sender's receive-chain
// head, which is what couples "what I am sending" to "what I have received".
func Keystream(seed []byte, blockSeq uint64, recvDigest [DigestSize]byte, out []byte) {
	var sb [8]byte
	binary.BigEndian.PutUint64(sb[:], blockSeq)
	var cb [4]byte
	for off := 0; off < len(out); off += sha256.Size {
		h := sha256.New()
		h.Write(seed)
		h.Write(sb[:])
		h.Write(recvDigest[:])
		binary.BigEndian.PutUint32(cb[:], uint32(off/sha256.Size))
		h.Write(cb[:])
		sum := h.Sum(nil)
		n := copy(out[off:], sum)
		if n < sha256.Size {
			break
		}
	}
}

// ExpectedPayload regenerates and compares a received payload.
func ExpectedPayload(seed []byte, f *Frame) bool {
	want := make([]byte, len(f.Payload))
	Keystream(seed, f.H.BlockSeq, f.H.RecvDigest, want)
	if len(want) != len(f.Payload) {
		return false
	}
	// Constant-time-ish compare; miscompares are rare and non-security critical.
	var diff byte
	for i := range want {
		diff |= want[i] ^ f.Payload[i]
	}
	return diff == 0
}

// Handshake is the capability exchange carried in MsgHandshake.Report.
type Handshake struct {
	Protocol   string   `json:"protocol"`
	PeerID     string   `json:"peer_id"`
	PeerName   string   `json:"peer_name"`
	Stack      string   `json:"stack"`
	Role       string   `json:"role"`
	SeedHex    string   `json:"seed"` // shared PRNG seed, hex
	BlockSize  int      `json:"block_size"`
	TotalBytes uint64   `json:"total_bytes"`
	Version    string   `json:"version"`
	OS         string   `json:"os"`
	Arch       string   `json:"arch"`
	Iface      string   `json:"iface"`
	Features   []string `json:"features,omitempty"`
	StartNS    int64    `json:"start_ns"`
}

func Describe(f *Frame) string {
	return fmt.Sprintf("type=%d flags=0x%04x blk=%d off=%d payload=%d report=%d",
		f.H.Type, f.H.Flags, f.H.BlockSeq, f.H.StreamOffset, len(f.Payload), len(f.Report))
}
