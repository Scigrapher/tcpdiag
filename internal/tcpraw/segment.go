package tcpraw

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// TCP control bits as carried on the wire.
const (
	FlagFIN uint8 = 1 << 0
	FlagSYN uint8 = 1 << 1
	FlagRST uint8 = 1 << 2
	FlagPSH uint8 = 1 << 3
	FlagACK uint8 = 1 << 4
	FlagURG uint8 = 1 << 5
	FlagECE uint8 = 1 << 6
	FlagCWR uint8 = 1 << 7
)

func FlagString(f uint8) string {
	s := ""
	for _, b := range []struct {
		bit  uint8
		name string
	}{{FlagFIN, "FIN"}, {FlagSYN, "SYN"}, {FlagRST, "RST"}, {FlagPSH, "PSH"}, {FlagACK, "ACK"}, {FlagURG, "URG"}, {FlagECE, "ECE"}, {FlagCWR, "CWR"}} {
		if f&b.bit != 0 {
			if s != "" {
				s += ","
			}
			s += b.name
		}
	}
	if s == "" {
		return "-"
	}
	return s
}

// SACKBlock is one SACK range [Start, End).
type SACKBlock struct {
	Start uint32
	End   uint32
}

type Options struct {
	MSS            uint16
	WinScale       int
	HasWinScale    bool
	SACK           []SACKBlock
	Timestamp      uint32
	TimestampEcho  uint32
	HasTimestamp   bool
	SACKPermitted  bool
	Challenge      uint32
	HasChallenge   bool
	UnknownOptions int
}

const (
	optEndOfList = 0
	optNop       = 1
	optMSS       = 2
	optWinScale  = 3
	optSACKPerm  = 4
	optSACK      = 5
	optTimestamp = 8
	// Private experimental option: the raw listener echoes the dialer's token
	// in its SYN-ACK. The OS port shield does not echo unknown options, which
	// lets the user-space stack distinguish the two SYN-ACKs on the same tuple.
	optChallenge = 254
)

// Segment is one IPv4/TCP segment plus decode metadata.
type Segment struct {
	// IPv4
	SrcIP, DstIP netip.Addr
	TOS          uint8
	TTL          uint8
	IPID         uint16
	DF           bool
	// TCP
	SrcPort, DstPort uint16
	Seq              uint32
	Ack              uint32
	Flags            uint8
	Window           uint16
	Urgent           uint16
	Opts             Options
	Payload          []byte
	// Decode metadata used by the diagnostic layer.
	ReceivedAt   int64
	HeaderLen    int
	BadChecksum  bool
	ChecksumWant uint16
	ChecksumGot  uint16
}

// SeqSpan returns the number of sequence numbers this segment consumes.
func (s *Segment) SeqSpan() uint32 {
	n := uint32(len(s.Payload))
	if s.Flags&FlagSYN != 0 {
		n++
	}
	if s.Flags&FlagFIN != 0 {
		n++
	}
	return n
}

func (s *Segment) String() string {
	extra := ""
	if len(s.Payload) > 0 {
		extra += fmt.Sprintf(" len=%d", len(s.Payload))
	}
	if s.Opts.HasTimestamp {
		extra += fmt.Sprintf(" ts=%d tsr=%d", s.Opts.Timestamp, s.Opts.TimestampEcho)
	}
	if len(s.Opts.SACK) > 0 {
		extra += fmt.Sprintf(" sack=%d", len(s.Opts.SACK))
	}
	if s.Opts.HasWinScale {
		extra += fmt.Sprintf(" wsc=%d", s.Opts.WinScale)
	}
	if s.Opts.HasChallenge {
		extra += fmt.Sprintf(" chal=%08x", s.Opts.Challenge)
	}
	return fmt.Sprintf("%s:%d->%s:%d %s seq=%d ack=%d win=%d%s",
		s.SrcIP, s.SrcPort, s.DstIP, s.DstPort, FlagString(s.Flags), s.Seq, s.Ack, s.Window, extra)
}

// ---------------------------------------------------------------------------
// Checksums
// ---------------------------------------------------------------------------

// checksum computes the standard Internet 16-bit one's complement sum.
func checksum(b []byte) uint16 {
	var sum uint32
	n := len(b)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if n%2 == 1 {
		sum += uint32(b[n-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func tcpChecksum(src, dst netip.Addr, tcp []byte) uint16 {
	sb, db := src.As4(), dst.As4()
	ph := make([]byte, 0, 12+len(tcp))
	ph = append(ph, sb[:]...)
	ph = append(ph, db[:]...)
	ph = append(ph, 0, 6)
	pl := uint16(len(tcp))
	ph = append(ph, byte(pl>>8), byte(pl))
	ph = append(ph, tcp...)
	return checksum(ph)
}

// ---------------------------------------------------------------------------
// Serialisation
// ---------------------------------------------------------------------------

// Marshal builds the full IPv4 packet carrying this segment.
func (s *Segment) Marshal() []byte {
	// Buffer layout: [0:20] fixed TCP header, [20:60] option space,
	// [60:60+len(payload)] payload staged before the compacting copy.
	buf := make([]byte, 60+len(s.Payload))
	binary.BigEndian.PutUint16(buf[0:2], s.SrcPort)
	binary.BigEndian.PutUint16(buf[2:4], s.DstPort)
	binary.BigEndian.PutUint32(buf[4:8], s.Seq)
	binary.BigEndian.PutUint32(buf[8:12], s.Ack)
	copy(buf[60:], s.Payload)
	n := s.marshalOptions(buf[20:60], false)
	if len(s.Payload) > 0 {
		copy(buf[20+n:], buf[60:60+len(s.Payload)])
	}
	tcp := buf[:20+n+len(s.Payload)]
	tcp[12] = byte(((20 + n) / 4) << 4)
	tcp[13] = s.Flags
	binary.BigEndian.PutUint16(tcp[14:16], s.Window)
	binary.BigEndian.PutUint16(tcp[16:18], 0)
	binary.BigEndian.PutUint16(tcp[18:20], s.Urgent)
	// The checksum covers the segment exactly as transmitted, with the
	// checksum field zeroed; odd lengths are handled inside checksum().
	s.ChecksumWant = tcpChecksum(s.SrcIP, s.DstIP, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], s.ChecksumWant)

	ip := make([]byte, 20)
	ip[0] = 4<<4 | 5 // version 4, IHL 5 (20 byte header)
	ip[1] = s.TOS
	total := 20 + len(tcp)
	binary.BigEndian.PutUint16(ip[2:4], uint16(total))
	binary.BigEndian.PutUint16(ip[4:6], s.IPID)
	if s.DF {
		ip[6] |= 0x40
	}
	ip[7] = 0
	ip[8] = s.TTL
	ip[9] = 6
	sb, db := s.SrcIP.As4(), s.DstIP.As4()
	copy(ip[12:16], sb[:])
	copy(ip[16:20], db[:])
	// The IPv4 checksum covers the addresses too. Computing it before the
	// address fields were filled produced a header that every real stack drops.
	binary.BigEndian.PutUint16(ip[10:12], checksum(ip[:20]))

	out := make([]byte, 20+len(tcp))
	copy(out[0:20], ip)
	copy(out[20:], tcp)
	return out
}

// marshalOptions writes TCP options, returning the number of bytes written.
// reserve=true pads to the 40-byte option space, used when a caller intends to
// append options later (never in practice, but keeps the helper symmetric).
func (s *Segment) marshalOptions(dst []byte, reserve bool) int {
	// The option space is 40 bytes and dst is exactly that. Four SACK blocks
	// need 34 bytes and timestamps another 10, so an unbounded writer overflows
	// it; every write is therefore bounds-checked and the block count is
	// reduced to whatever actually fits.
	space := len(dst)
	n := 0
	put := func(b ...byte) bool {
		if n+len(b) > space {
			return false
		}
		copy(dst[n:], b)
		n += len(b)
		return true
	}
	if s.Opts.MSS > 0 {
		put(optMSS, 4, byte(s.Opts.MSS>>8), byte(s.Opts.MSS))
	}
	if s.Opts.HasWinScale {
		put(optWinScale, 3, byte(s.Opts.WinScale))
	}
	// SACK-Permitted must be emitted, not merely parsed: without it a peer
	// never learns we accept SACK, recovery degrades to retransmitting from the
	// oldest unacked byte, and the extra resends look like spurious
	// retransmissions.
	if s.Opts.SACKPermitted {
		put(optSACKPerm, 2)
	}
	if s.Opts.HasChallenge {
		var b [6]byte
		b[0], b[1] = optChallenge, 6
		binary.BigEndian.PutUint32(b[2:6], s.Opts.Challenge)
		put(b[:]...)
	}
	// Reserve room for the timestamp before filling SACK. RTT accuracy is what
	// keeps the retransmission timer honest and prevents spurious retransmits,
	// so it outranks a fourth SACK block, which is only advisory.
	tsReserve := 0
	if s.Opts.HasTimestamp {
		tsReserve = 10
	}
	limit := space - tsReserve
	if limit < n {
		limit = space
	}
	if len(s.Opts.SACK) > 0 {
		blocks := len(s.Opts.SACK)
		if blocks > 4 {
			blocks = 4
		}
		for blocks > 0 && n+2+8*blocks > limit {
			blocks--
		}
		if blocks > 0 && put(optSACK, byte(2+8*blocks)) {
			for i := 0; i < blocks; i++ {
				var b [8]byte
				binary.BigEndian.PutUint32(b[0:4], s.Opts.SACK[i].Start)
				binary.BigEndian.PutUint32(b[4:8], s.Opts.SACK[i].End)
				if !put(b[:]...) {
					break
				}
			}
		}
	}
	if s.Opts.HasTimestamp && n+10 <= space {
		var b [10]byte
		b[0], b[1] = optTimestamp, 10
		binary.BigEndian.PutUint32(b[2:6], s.Opts.Timestamp)
		binary.BigEndian.PutUint32(b[6:10], s.Opts.TimestampEcho)
		put(b[:]...)
	}
	for n%4 != 0 && n < space {
		put(optNop)
	}
	if reserve {
		for n < space {
			dst[n] = optPadding
			n++
		}
	}
	return n
}

const optPadding = 0

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

// Parse decodes an IPv4 packet into a Segment, validating checksums.
func Parse(pkt []byte) (*Segment, error) {
	if len(pkt) < 20 {
		return nil, fmt.Errorf("tcpraw: short IPv4 packet (%d bytes)", len(pkt))
	}
	if pkt[0]>>4 != 4 {
		return nil, fmt.Errorf("tcpraw: not IPv4 (version %d)", pkt[0]>>4)
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl {
		return nil, fmt.Errorf("tcpraw: bad IHL %d", pkt[0]&0x0f)
	}
	if pkt[9] != 6 {
		return nil, fmt.Errorf("tcpraw: protocol %d is not TCP", pkt[9])
	}
	// Fragments cannot be parsed as TCP and this tool does not reassemble them.
	// SIO_RCVALL hands us every packet the host sees, so malformed input is
	// expected and must never be able to panic the capture loop.
	if fragmented(pkt) {
		return nil, fmt.Errorf("tcpraw: IPv4 fragment")
	}
	s := &Segment{}
	s.TOS = pkt[1]
	s.IPID = binary.BigEndian.Uint16(pkt[4:6])
	s.DF = pkt[6]&0x40 != 0
	s.TTL = pkt[8]
	s.SrcIP, _ = netip.AddrFromSlice(pkt[12:16])
	s.DstIP, _ = netip.AddrFromSlice(pkt[16:20])
	// Trust nothing in the Total Length field. Capture paths can hand over a
	// frame whose length is zero or smaller than the header it plainly has
	// (offload, IP_HDRINCL sends, truncated captures), and slicing straight
	// from that field panics. Clamp it into range instead.
	total := int(binary.BigEndian.Uint16(pkt[2:4]))
	if total < ihl || total > len(pkt) {
		total = len(pkt)
	}
	tcp := pkt[ihl:total]
	if len(tcp) < 20 {
		return nil, fmt.Errorf("tcpraw: short TCP header (%d bytes)", len(tcp))
	}
	s.SrcPort = binary.BigEndian.Uint16(tcp[0:2])
	s.DstPort = binary.BigEndian.Uint16(tcp[2:4])
	s.Seq = binary.BigEndian.Uint32(tcp[4:8])
	s.Ack = binary.BigEndian.Uint32(tcp[8:12])
	s.HeaderLen = int(tcp[12]>>4) * 4
	if s.HeaderLen < 20 || s.HeaderLen > len(tcp) {
		return nil, fmt.Errorf("tcpraw: bad TCP data offset %d", tcp[12]>>4)
	}
	s.Flags = tcp[13]
	s.Window = binary.BigEndian.Uint16(tcp[14:16])
	s.ChecksumGot = binary.BigEndian.Uint16(tcp[16:18])
	s.Urgent = binary.BigEndian.Uint16(tcp[18:20])
	s.parseOptions(tcp[20:s.HeaderLen])
	if s.HeaderLen < len(tcp) {
		s.Payload = append([]byte{}, tcp[s.HeaderLen:]...)
	}
	// Verify the TCP checksum over a copy with the checksum field zeroed.
	cp := append([]byte{}, tcp...)
	want := tcpChecksum(s.SrcIP, s.DstIP, zeroChecksum(cp))
	s.ChecksumWant = want
	s.BadChecksum = want != s.ChecksumGot
	return s, nil
}

func zeroChecksum(tcp []byte) []byte {
	cp := append([]byte{}, tcp...)
	if len(cp) >= 18 {
		cp[16], cp[17] = 0, 0
	}
	return cp
}

func (s *Segment) parseOptions(o []byte) {
	for i := 0; i < len(o); {
		switch o[i] {
		case optEndOfList:
			return
		case optNop:
			i++
			continue
		}
		if i+1 >= len(o) {
			return
		}
		l := int(o[i+1])
		if l < 2 || i+l > len(o) {
			return
		}
		switch o[i] {
		case optMSS:
			if l >= 4 {
				s.Opts.MSS = binary.BigEndian.Uint16(o[i+2 : i+4])
			}
		case optWinScale:
			if l >= 3 {
				s.Opts.HasWinScale = true
				s.Opts.WinScale = int(o[i+2])
			}
		case optSACK:
			if l >= 10 && (l-2)%8 == 0 {
				for j := i + 2; j+8 <= i+l; j += 8 {
					s.Opts.SACK = append(s.Opts.SACK, SACKBlock{
						Start: binary.BigEndian.Uint32(o[j : j+4]),
						End:   binary.BigEndian.Uint32(o[j+4 : j+8]),
					})
				}
			}
		case optSACKPerm:
			s.Opts.SACKPermitted = true
		case optTimestamp:
			if l >= 10 {
				s.Opts.HasTimestamp = true
				s.Opts.Timestamp = binary.BigEndian.Uint32(o[i+2 : i+6])
				s.Opts.TimestampEcho = binary.BigEndian.Uint32(o[i+6 : i+10])
			}
		case optChallenge:
			if l >= 6 {
				s.Opts.HasChallenge = true
				s.Opts.Challenge = binary.BigEndian.Uint32(o[i+2 : i+6])
			}
		default:
			s.Opts.UnknownOptions++
		}
		i += l
	}
}

// ---------------------------------------------------------------------------
// Sequence-number arithmetic (wraparound safe)
// ---------------------------------------------------------------------------

func seqLT(a, b uint32) bool { return int32(a-b) < 0 }
func seqLE(a, b uint32) bool { return int32(a-b) <= 0 }
func seqGT(a, b uint32) bool { return int32(a-b) > 0 }
func seqGE(a, b uint32) bool { return int32(a-b) >= 0 }

// seqIn reports whether seq lies in [start, end).
func seqIn(seq, start, end uint32) bool {
	return seqGE(seq, start) && seqLT(seq, end)
}

// fragmented reports whether an IPv4 header carries the More-Fragments flag or
// a non-zero fragment offset.
func fragmented(pkt []byte) bool {
	if len(pkt) < 8 {
		return true
	}
	if pkt[6]&0x20 != 0 {
		return true // More Fragments
	}
	return pkt[6]&0x1f != 0 || pkt[7] != 0 // fragment offset
}
