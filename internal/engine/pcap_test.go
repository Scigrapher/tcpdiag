package engine

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"tcpdiag/internal/tcpraw"
)

// Read a pcap back with no external dependencies and return the global header
// plus the first packet.
func readPCAP(t *testing.T, path string) (network uint32, first []byte) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 24 {
		t.Fatalf("pcap shorter than the global header: %d", len(b))
	}
	if got := binary.LittleEndian.Uint32(b[0:4]); got != 0xa1b2c3d4 {
		t.Fatalf("bad pcap magic %08x", got)
	}
	network = binary.LittleEndian.Uint32(b[20:24])
	if len(b) < 40 {
		t.Fatal("no packets in pcap")
	}
	// Per-packet header is 16 bytes at offset 24: ts_sec, ts_usec, incl_len,
	// orig_len. incl_len therefore lives at 32, not 28.
	incl := int(binary.LittleEndian.Uint32(b[32:36]))
	first = b[40 : 40+incl]
	return network, first
}

// The pcap must be self-describing enough that Wireshark labels the packets
// correctly: link type Raw IPv4 (101) and a genuine IPv4/TCP packet inside.
func TestPCAPWriterProducesDissectableIPv4TCP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.pcap")
	w, err := OpenPCAP(path, DLTRaw)
	if err != nil {
		t.Fatal(err)
	}
	seg := &tcpraw.Segment{
		SrcIP: netip.MustParseAddr("192.168.1.10"), DstIP: netip.MustParseAddr("192.168.1.20"),
		SrcPort: 42426, DstPort: 42425, Seq: 1, Ack: 1,
		Flags: tcpraw.FlagACK | tcpraw.FlagPSH, Window: 1460, TTL: 64,
		Payload: []byte("hello tcpdiag"),
	}
	if err := w.WritePacket(seg.Marshal(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	network, first := readPCAP(t, path)
	if network != DLTRaw {
		t.Fatalf("link type is %d, expected DLT_RAW (%d)", network, DLTRaw)
	}
	if len(first) < 21 {
		t.Fatalf("packet too short: %d", len(first))
	}
	if first[0]>>4 != 4 {
		t.Fatalf("packet does not begin with an IPv4 header (first byte 0x%02x); Wireshark could not dissect it as IP", first[0])
	}
	if ihl := int(first[0]&0x0f) * 4; ihl < 20 {
		t.Fatalf("bogus IHL %d", first[0]&0x0f)
	}
	if first[9] != 6 {
		t.Fatalf("IP protocol is %d, not TCP(6) - this is what makes Wireshark label the traffic as something else", first[9])
	}
	if first[12] != 192 || first[13] != 168 || first[14] != 1 || first[15] != 10 {
		t.Fatal("source address corrupted")
	}
	if got := binary.BigEndian.Uint16(first[20:22]); got != 42426 {
		t.Fatalf("source port %d, expected 42426", got)
	}
	if got := binary.BigEndian.Uint16(first[22:24]); got != 42425 {
		t.Fatalf("dest port %d, expected 42425", got)
	}
}

// With --pcap-dlt ethernet the record length must include the synthetic
// Ethernet header, otherwise Wireshark reads a truncated frame.
func TestPCAPWriterEthernetRecordLength(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eth.pcap")
	w, err := OpenPCAP(path, DLTEther)
	if err != nil {
		t.Fatal(err)
	}
	ip := testTCPPacket(42426, 42425, 7)
	if err := w.WritePacket(ip, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := int(binary.LittleEndian.Uint32(raw[32:36])); got != 14+len(ip) {
		t.Fatalf("record length %d, want %d (14-byte Ethernet + %d-byte IP)", got, 14+len(ip), len(ip))
	}
	network, first := readPCAP(t, path)
	if network != DLTEther {
		t.Fatalf("link type %d, want Ethernet (%d)", network, DLTEther)
	}
	if len(first) != 14+len(ip) || binary.BigEndian.Uint16(first[12:14]) != 0x0800 || first[14]>>4 != 4 {
		t.Fatalf("bad Ethernet framing: %x", first[:min(18, len(first))])
	}
}

// A DLT_RAW file may only contain bare IP packets. Writing anything else is
// what makes Wireshark read the first byte as an absurd IP version and dissect
// the traffic as something it is not, so the writer has to notice.
func TestPCAPWriterFlagsNonIPPayloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "suspect.pcap")
	w, _ := OpenPCAP(path, DLTRaw)
	eth := make([]byte, 60)
	eth[12], eth[13] = 0x08, 0x00 // an Ethernet frame: wrong for DLT_RAW
	_ = w.WritePacket(eth, time.Now())
	ethFramed := make([]byte, 74)
	ethFramed[12], ethFramed[13] = 0x08, 0x00
	_ = w.WritePacket(ethFramed, time.Now())
	_ = w.Close()

	w2, _ := os.Open(path)
	_ = w2.Close()
	w3, _ := OpenPCAP(filepath.Join(t.TempDir(), "ok.pcap"), DLTRaw)
	seg := &tcpraw.Segment{
		SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("10.0.0.2"),
		SrcPort: 1, DstPort: 2, Seq: 1, Ack: 1, Flags: tcpraw.FlagACK, Window: 100, TTL: 64,
	}
	_ = w3.WritePacket(seg.Marshal(), time.Now())
	_ = w3.Close()

	// Re-open the suspect file through a fresh writer instance to read the
	// counter back after the writes.
	path2 := filepath.Join(t.TempDir(), "count.pcap")
	w4, _ := OpenPCAP(path2, DLTRaw)
	_ = w4.WritePacket(eth, time.Now())
	if got := w4.Suspect(); got != 1 {
		t.Errorf("suspect counter = %d, want 1", got)
	}
	_ = w4.WritePacket(seg.Marshal(), time.Now())
	if got := w4.Suspect(); got != 1 {
		t.Errorf("suspect counter should not grow for IP packets, got %d", got)
	}
	_ = w4.Close()
}

func testTCPPacket(srcPort, dstPort uint16, seq uint32) []byte {
	seg := &tcpraw.Segment{
		SrcIP: netip.MustParseAddr("192.168.1.10"), DstIP: netip.MustParseAddr("192.168.1.20"),
		SrcPort: srcPort, DstPort: dstPort, Seq: seq, Ack: 1,
		Flags: tcpraw.FlagSYN, Window: 64240, TTL: 64,
	}
	return seg.Marshal()
}

func testUDPPacket(srcPort, dstPort uint16) []byte {
	p := make([]byte, 20+8+4)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 17
	copy(p[12:16], []byte{192, 168, 1, 10})
	copy(p[16:20], []byte{192, 168, 1, 20})
	binary.BigEndian.PutUint16(p[20:22], srcPort)
	binary.BigEndian.PutUint16(p[22:24], dstPort)
	binary.BigEndian.PutUint16(p[24:26], 12)
	return p
}

func testICMPTimeExceeded(quoted []byte) []byte {
	icmp := make([]byte, 8+len(quoted))
	icmp[0] = 11 // time exceeded
	copy(icmp[8:], quoted)
	p := make([]byte, 20+len(icmp))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	p[8] = 64
	p[9] = 1
	copy(p[12:16], []byte{192, 168, 1, 1})
	copy(p[16:20], []byte{192, 168, 1, 10})
	copy(p[20:], icmp)
	return p
}

// The capture file must contain the diagnostic flows and nothing else: a host
// with ordinary SSH/HTTPS sessions open would otherwise fill it with unrelated
// traffic from the same peer address.
func TestPCAPFilterKeepsOnlyTCPDiagFlows(t *testing.T) {
	f := NewPCAPFilter([]uint16{42424, 42425, 42426, 42077})
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"raw data", testTCPPacket(42426, 42425, 1), true},
		{"kernel data", testTCPPacket(50123, 42424, 1), true},
		{"probe echo", testUDPPacket(42426, 50000), true},
		{"discovery beacon", testUDPPacket(42077, 42077), true},
		{"unrelated https", testTCPPacket(50123, 443, 1), false},
		{"unrelated ssh", testTCPPacket(22, 50123, 1), false},
		{"ttl probe quoted", testICMPTimeExceeded(testUDPPacket(50000, 42426)), true},
		{"unrelated icmp quote", testICMPTimeExceeded(testTCPPacket(50123, 443, 1)), false},
	}
	for _, tc := range cases {
		if got := f.Match(tc.pkt); got != tc.want {
			t.Errorf("%s: Match=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPCAPFilterLearnsDiscoveredPeerPorts(t *testing.T) {
	f := NewPCAPFilter([]uint16{42425})
	custom := testTCPPacket(50000, 43000, 1)
	if f.Match(custom) {
		t.Fatal("custom peer port should be filtered before discovery")
	}
	f.AddPorts(43000, 43001)
	if !f.Match(custom) {
		t.Fatal("custom peer port should match after discovery")
	}
}

func TestPCAPWriterFiltersAndRecordsInjectedPackets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filtered.pcap")
	w, err := OpenPCAP(path, DLTRaw)
	if err != nil {
		t.Fatal(err)
	}
	w.SetFilter(NewPCAPFilter([]uint16{42425}))
	now := time.Now()
	first := testTCPPacket(42426, 42425, 100)
	other := testTCPPacket(42426, 42425, 200)
	unrelated := testTCPPacket(50123, 443, 300)

	if err := w.WriteCaptured(first, now); err != nil {
		t.Fatal(err)
	}
	// The platform capture and the local injection path can both report the
	// same bytes. Only one copy belongs in the file.
	if err := w.WriteInjected(first, now); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteCaptured(unrelated, now); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteInjected(other, now); err != nil {
		t.Fatal(err)
	}
	if got := w.Count(); got != 2 {
		t.Errorf("wrote %d packets, want 2", got)
	}
	if got := w.Filtered(); got != 1 {
		t.Errorf("filtered %d packets, want 1", got)
	}
	if got := w.Injected(); got != 1 {
		t.Errorf("recorded %d injected packets, want 1", got)
	}
	if got := w.Duplicates(); got != 1 {
		t.Errorf("suppressed %d duplicates, want 1", got)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
}
