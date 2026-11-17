package tcpraw

import (
	"net/netip"
	"testing"
)

func TestSegmentRoundTrip(t *testing.T) {
	s := &Segment{
		SrcIP:   netip.MustParseAddr("10.99.0.1"),
		DstIP:   netip.MustParseAddr("10.99.0.2"),
		SrcPort: 42426, DstPort: 42425,
		Seq:     1234,
		Flags:   FlagSYN,
		Window:  65535,
		TTL:     64,
		IPID:    7,
		Opts:    Options{MSS: 1400, HasWinScale: true, WinScale: 7, SACKPermitted: true, HasChallenge: true, Challenge: 0x12345678},
		Payload: nil,
	}
	pkt := s.Marshal()
	t.Logf("len=%d bytes=% x", len(pkt), pkt)
	got, err := Parse(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.SrcPort != s.SrcPort || got.DstPort != s.DstPort || got.Seq != s.Seq || got.Flags != s.Flags {
		t.Fatalf("round trip mismatch: %+v", got)
	}
	if got.Opts.MSS != 1400 || !got.Opts.HasWinScale || got.Opts.WinScale != 7 {
		t.Fatalf("options lost: %+v", got.Opts)
	}
	if !got.Opts.HasChallenge || got.Opts.Challenge != 0x12345678 || !got.Opts.SACKPermitted {
		t.Fatalf("handshake options lost: %+v", got.Opts)
	}
	if got.BadChecksum {
		t.Fatalf("checksum invalid: want=%04x got=%04x", got.ChecksumWant, got.ChecksumGot)
	}

	// Payload of odd length must survive the checksum too.
	s2 := *s
	s2.Flags = FlagACK | FlagPSH
	s2.Payload = []byte{1, 2, 3, 4, 5}
	g2, err := Parse(s2.Marshal())
	if err != nil {
		t.Fatalf("parse odd payload: %v", err)
	}
	if g2.BadChecksum {
		t.Fatalf("odd-payload checksum invalid: want=%04x got=%04x", g2.ChecksumWant, g2.ChecksumGot)
	}
	if len(g2.Payload) != 5 {
		t.Fatalf("payload lost: %d", len(g2.Payload))
	}

	// SACK option round trip.
	s3 := *s
	s3.Flags = FlagACK
	s3.Opts = Options{SACK: []SACKBlock{{Start: 100, End: 200}, {Start: 300, End: 400}}}
	g3, err := Parse(s3.Marshal())
	if err != nil {
		t.Fatalf("parse sack: %v", err)
	}
	if len(g3.Opts.SACK) != 2 || g3.Opts.SACK[1].End != 400 {
		t.Fatalf("sack lost: %+v", g3.Opts.SACK)
	}
}

// The IPv4 checksum covers the source and destination addresses. Computing it
// before those fields were written made every raw packet invalid on the wire.
func TestMarshalIPv4HeaderChecksum(t *testing.T) {
	s := &Segment{
		SrcIP:   netip.MustParseAddr("192.168.1.49"),
		DstIP:   netip.MustParseAddr("192.168.1.227"),
		SrcPort: 42426, DstPort: 42425,
		Seq: 1, Flags: FlagSYN, Window: 65535, TTL: 64, IPID: 42,
	}
	pkt := s.Marshal()
	if got := checksum(pkt[:20]); got != 0 {
		t.Fatalf("IPv4 header checksum does not validate: residual=%04x header=% x", got, pkt[:20])
	}
	if pkt[12] != 192 || pkt[13] != 168 || pkt[14] != 1 || pkt[15] != 49 ||
		pkt[16] != 192 || pkt[17] != 168 || pkt[18] != 1 || pkt[19] != 227 {
		t.Fatalf("IPv4 addresses not written into header: % x", pkt[12:20])
	}
}

// Four SACK blocks (34 bytes) plus timestamps (10) exceed the 40-byte option
// space. The encoder must degrade gracefully instead of writing out of bounds.
func TestMarshalOptionsRespectsOptionSpace(t *testing.T) {
	cases := []struct {
		name string
		opts Options
	}{
		{"everything at once", Options{
			MSS: 1400, HasWinScale: true, WinScale: 7, SACKPermitted: true, HasTimestamp: true, Timestamp: 99,
			HasChallenge: true, Challenge: 0xdeadbeef,
			SACK: []SACKBlock{{1, 2}, {3, 4}, {5, 6}, {7, 8}},
		}},
		{"4 sacks with timestamps", Options{HasTimestamp: true, SACK: []SACKBlock{{1, 2}, {3, 4}, {5, 6}, {7, 8}}}},
		{"4 sacks alone", Options{SACK: []SACKBlock{{1, 2}, {3, 4}, {5, 6}, {7, 8}}}},
		{"many sacks", Options{HasTimestamp: true, HasWinScale: true, WinScale: 9, SACK: []SACKBlock{
			{1, 2}, {3, 4}, {5, 6}, {7, 8}, {9, 10}, {11, 12},
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Marshal panicked (option overflow): %v", r)
				}
			}()
			s := &Segment{
				SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("10.0.0.2"),
				SrcPort: 1, DstPort: 2, Seq: 5, Ack: 6, Flags: FlagACK, Window: 100, TTL: 64,
				Opts: tc.opts,
			}
			pkt := s.Marshal()
			got, err := Parse(pkt)
			if err != nil {
				t.Fatalf("self-produced packet failed to parse: %v", err)
			}
			if got.BadChecksum {
				t.Fatal("self-produced packet has a bad checksum")
			}
			if got.HeaderLen%4 != 0 || got.HeaderLen < 20 || got.HeaderLen > 60 {
				t.Fatalf("data offset out of range: %d", got.HeaderLen)
			}
			// Whatever fit must still be readable, and never more than 4 blocks.
			if len(got.Opts.SACK) > 4 {
				t.Fatalf("too many SACK blocks: %d", len(got.Opts.SACK))
			}
			if tc.opts.HasTimestamp && got.HeaderLen == 60 && !got.Opts.HasTimestamp {
				t.Error("timestamp option was silently dropped with room to spare")
			}
		})
	}
}
