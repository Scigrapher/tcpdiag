//go:build windows

package packetio

import "testing"

func TestValidRecvLenRejectsSocketError(t *testing.T) {
	const cap = 1 << 16
	if validRecvLen(0xFFFFFFFF, cap) {
		t.Fatal("SOCKET_ERROR surfaced as 0xFFFFFFFF must not be treated as a packet length")
	}
	if validRecvLen(0, cap) {
		t.Fatal("zero-length read must not be treated as a packet")
	}
	if !validRecvLen(cap, cap) {
		t.Fatal("a full-buffer packet must be accepted")
	}
	if validRecvLen(cap+1, cap) {
		t.Fatal("an oversized length must be rejected")
	}
}

func TestNpcapDevicesDiscoverable(t *testing.T) {
	devs, err := npcapDevices()
	if err != nil {
		t.Skipf("Npcap not available: %v", err)
	}
	if len(devs) == 0 {
		t.Fatal("Npcap is loaded but reported no devices")
	}
}
