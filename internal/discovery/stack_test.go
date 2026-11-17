package discovery

import (
	"net/netip"
	"testing"
)

func TestStacksCompatible(t *testing.T) {
	cases := []struct {
		local, peer string
		want        bool
	}{
		{"raw", "raw", true},
		{"raw", "both", true},
		{"raw", "kernel", false},
		{"raw", "observe", false},
		{"kernel", "observe", true},
		{"kernel", "both", true},
		{"kernel", "raw", false},
		{"observe", "raw", false},
		{"both", "raw", true},
		{"both", "kernel", true},
		{"raw", "", true}, // older peer did not advertise a stack
	}
	for _, tc := range cases {
		if got := StacksCompatible(tc.local, tc.peer); got != tc.want {
			t.Errorf("StacksCompatible(%q, %q)=%v, want %v", tc.local, tc.peer, got, tc.want)
		}
	}
}

func TestPeerEndpointsFollowAdvertisedStack(t *testing.T) {
	raw := &Peer{
		Announce: Announce{Stack: "raw", RawIP: "192.168.1.20", RawPort: 42425},
		DataIP:   "192.168.1.20", DataPort: 42424, Via: netip.MustParseAddr("192.168.1.20"),
	}
	if ep, ok := raw.KernelEndpoint(); ok {
		t.Errorf("raw-only peer must not advertise a kernel endpoint, got %q", ep)
	}
	if ep, ok := raw.RawEndpoint(); !ok || ep != "192.168.1.20:42425" {
		t.Errorf("raw endpoint = %q/%v", ep, ok)
	}

	kernel := &Peer{
		Announce: Announce{Stack: "kernel", TCPAddr: "192.168.1.21:42424"},
		DataIP:   "192.168.1.21", DataPort: 42424, Via: netip.MustParseAddr("192.168.1.21"),
	}
	if ep, ok := kernel.KernelEndpoint(); !ok || ep != "192.168.1.21:42424" {
		t.Errorf("kernel endpoint = %q/%v", ep, ok)
	}
	if ep, ok := kernel.RawEndpoint(); ok {
		t.Errorf("kernel-only peer must not advertise a raw endpoint, got %q", ep)
	}
}
