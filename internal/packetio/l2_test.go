package packetio

import (
	"encoding/hex"
	"testing"
)

// A real discovery beacon captured with its Ethernet header intact, taken from
// a user report. It is genuinely UDP (IP protocol 17) on port 42077; the point
// is that the capture source included 14 bytes of Ethernet in front of it,
// which would make a DLT_RAW pcap undissectable.
const beaconHex = "ffffffffffffc87f545ac9990800450001112ef00000801185b9c0a801e3c0a801ffa45da45d00fda58d"

func beaconBytes(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(beaconHex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStripL2RemovesEthernetFrame(t *testing.T) {
	b := beaconBytes(t)
	if IsIP(b) {
		t.Fatal("fixture should start with an Ethernet header, not an IP header")
	}
	payload, hadL2, et := StripL2(b)
	if !hadL2 {
		t.Fatal("the Ethernet header should have been detected")
	}
	if et != etypeIPv4 {
		t.Fatalf("ethertype = 0x%04x, want 0x0800", et)
	}
	if !IsIPv4(payload) {
		t.Fatalf("payload is not a bare IPv4 packet; first byte 0x%02x", payload[0])
	}
	// The IP header must now be at offset 0, so the protocol field is at 9.
	if len(payload) < 21 {
		t.Fatalf("payload too short: %d", len(payload))
	}
	if payload[9] != 17 {
		t.Fatalf("IP protocol = %d, want 17 (UDP): this frame really is UDP", payload[9])
	}
	// Ports 42077 -> 42077 confirm it is a discovery beacon.
	sport := int(payload[20])<<8 | int(payload[21])
	dport := int(payload[22])<<8 | int(payload[23])
	if sport != 42077 || dport != 42077 {
		t.Fatalf("UDP ports %d->%d, want 42077->42077", sport, dport)
	}
}

func TestStripL2LeavesBareIppackets(t *testing.T) {
	ip := beaconBytes(t)[14:]
	payload, hadL2, et := StripL2(ip)
	if hadL2 {
		t.Fatal("a bare IP packet must not be reported as link-layer framed")
	}
	if et != 0 {
		t.Fatalf("ethertype should be 0, got 0x%04x", et)
	}
	if len(payload) != len(ip) {
		t.Fatal("bare IP payload must be returned unchanged")
	}
	if !IsIPv4(payload) {
		t.Fatal("should still be IPv4")
	}
}

func TestStripL2HandlesOtherFrames(t *testing.T) {
	// ARP frame
	arp := make([]byte, 42)
	arp[12], arp[13] = 0x08, 0x06
	if _, hadL2, et := StripL2(arp); !hadL2 || et != etypeARP {
		t.Error("ARP frame should be detected so callers can drop it")
	}
	// IPv6 over Ethernet
	v6 := make([]byte, 14+40)
	v6[12], v6[13] = 0x86, 0xdd
	v6[14] = 6 << 4
	if _, hadL2, et := StripL2(v6); !hadL2 || et != etypeIPv6 {
		t.Error("IPv6 frame should be detected")
	}
	// Junk must be returned untouched rather than panic.
	for _, junk := range [][]byte{nil, {0x01}, make([]byte, 13), make([]byte, 14)} {
		got, had, _ := StripL2(junk)
		if had {
			t.Errorf("short junk %v wrongly reported as L2", junk)
		}
		if len(got) != len(junk) {
			t.Errorf("junk %v was truncated", junk)
		}
	}
}

func TestIsIPHelpers(t *testing.T) {
	ip := beaconBytes(t)[14:]
	if !IsIPv4(ip) || !IsIP(ip) || IsIPv6(ip) {
		t.Error("IPv4 classification wrong")
	}
	v6 := make([]byte, 40)
	v6[0] = 6 << 4
	if !IsIPv6(v6) || !IsIP(v6) || IsIPv4(v6) {
		t.Error("IPv6 classification wrong")
	}
	if IsIP(nil) || IsIPv4(nil) || IsIPv6(nil) {
		t.Error("nil must not be classified as IP")
	}
	if IsIPv4([]byte{0xff, 0xff}) {
		t.Error("a broadcast frame must not be classified as IPv4")
	}
}
