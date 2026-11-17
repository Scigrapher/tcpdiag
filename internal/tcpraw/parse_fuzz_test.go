package tcpraw

import (
	"math/rand"
	"net/netip"
	"testing"
)

// ipHdr builds a minimal IPv4 header with the given raw field values so tests
// can produce deliberately impossible packets.
func ipHdr(totalLen int, ihlNibble byte, proto byte, fragHi, fragLo byte) []byte {
	b := make([]byte, 60)
	b[0] = 4<<4 | ihlNibble
	b[2] = byte(totalLen >> 8)
	b[3] = byte(totalLen)
	b[6] = fragHi
	b[7] = fragLo
	b[8] = 64
	b[9] = proto
	copy(b[12:16], netip.MustParseAddr("10.0.0.1").AsSlice())
	copy(b[16:20], netip.MustParseAddr("10.0.0.2").AsSlice())
	// A plausible TCP header follows the 20-byte IP header.
	b[20] = 0x11
	b[21] = 0x12
	b[32] = 5 << 4 // data offset 5
	return b
}

// Every one of these used to be able to panic the capture goroutine.
func TestParseNeverPanicsOnMalformedPackets(t *testing.T) {
	cases := []struct {
		name string
		pkt  []byte
	}{
		{"zero total length", ipHdr(0, 5, 6, 0, 0)},
		{"total length below ihl", ipHdr(10, 5, 6, 0, 0)},
		{"total length one", ipHdr(1, 5, 6, 0, 0)},
		{"huge total length", ipHdr(65535, 5, 6, 0, 0)},
		{"ihl 0", ipHdr(40, 0, 6, 0, 0)},
		{"ihl 1", ipHdr(40, 1, 6, 0, 0)},
		{"ihl 15 with short buffer", func() []byte {
			b := ipHdr(40, 15, 6, 0, 0)
			return b[:30]
		}()},
		{"mf set", ipHdr(40, 5, 6, 0x20, 0)},
		{"fragment offset", ipHdr(40, 5, 6, 0x00, 0x08)},
		{"fragment offset high", ipHdr(40, 5, 6, 0x1f, 0xff)},
		{"non-tcp protocol", ipHdr(40, 5, 17, 0, 0)},
		{"icmp protocol", ipHdr(40, 5, 1, 0, 0)},
		{"version 6", func() []byte { b := ipHdr(40, 5, 6, 0, 0); b[0] = 6<<4 | 5; return b }()},
		{"truncated to 20", ipHdr(40, 5, 6, 0, 0)[:20]},
		{"truncated to 21", ipHdr(40, 5, 6, 0, 0)[:21]},
		{"tcp data offset 0", func() []byte { b := ipHdr(40, 5, 6, 0, 0); b[32] = 0; return b }()},
		{"tcp data offset 15", func() []byte { b := ipHdr(40, 5, 6, 0, 0); b[32] = 15 << 4; return b }()},
		{"tcp data offset 1", func() []byte { b := ipHdr(40, 5, 6, 0, 0); b[32] = 1 << 4; return b }()},
		{"empty", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Parse panicked on %s: %v", tc.name, r)
				}
			}()
			_, _ = Parse(tc.pkt)
		})
	}
}

// The capture loop sees arbitrary bytes; random input must be rejected, not fatal.
func TestParseRandomInputNeverPanics(t *testing.T) {
	rnd := rand.New(rand.NewSource(20260))
	for i := 0; i < 20000; i++ {
		n := rnd.Intn(200)
		b := make([]byte, n)
		rnd.Read(b)
		// Bias toward packets that look like IPv4/TCP so the deeper paths get hit.
		if i%2 == 0 && n >= 40 {
			b[0] = 4<<4 | byte(5+rnd.Intn(11))
			b[9] = 6
			b[2] = byte(rnd.Intn(256))
			b[3] = byte(rnd.Intn(256))
			b[6] = byte(rnd.Intn(256))
			b[7] = byte(rnd.Intn(256))
			b[32] = byte(rnd.Intn(16) << 4)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Parse panicked on random input (len %d): %v", n, r)
				}
			}()
			_, _ = Parse(b)
		}()
	}
}

// A well-formed packet with a deliberately wrong Total Length still parses,
// using the length we were actually handed.
func TestParseRecoversFromBogusTotalLength(t *testing.T) {
	s := &Segment{
		SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("10.0.0.2"),
		SrcPort: 1234, DstPort: 42425, Seq: 7, Flags: FlagSYN, Window: 1460,
		TTL: 64, Opts: Options{MSS: 1400},
	}
	pkt := s.Marshal()
	// Corrupt the length field the way a broken capture path would.
	pkt[2], pkt[3] = 0, 0
	got, err := Parse(pkt)
	if err != nil {
		t.Fatalf("should recover from a zero length field: %v", err)
	}
	if got.SrcPort != 1234 || got.Flags != FlagSYN || got.Opts.MSS != 1400 {
		t.Fatalf("parsed wrong segment: %v", got)
	}
	if got.BadChecksum {
		t.Fatal("checksum should still validate")
	}
}
