package discovery

import (
	"net/netip"
	"testing"
)

// No sockets here: these are the pure decisions that decide whether two nodes
// can find and reach each other.

func TestResolveReachablePrefersBeaconSource(t *testing.T) {
	from := netip.MustParseAddr("192.168.1.50")
	a := Announce{
		RawIP:   "172.30.160.1",
		TCPAddr: "172.30.160.1:42424",
		IPs:     []string{"172.30.160.1", "192.168.1.50"},
	}
	ip, _ := resolveReachable(a, from)
	if ip != "192.168.1.50" {
		t.Fatalf("chose %q; must prefer the address the beacon actually arrived from", ip)
	}
}

func TestResolveReachableFallsBackToSameSubnet(t *testing.T) {
	from := netip.MustParseAddr("192.168.1.50")
	a := Announce{RawIP: "192.168.1.227", TCPAddr: "192.168.1.227:42424", IPs: []string{"172.30.160.1", "192.168.1.227"}}
	ip, _ := resolveReachable(a, from)
	if ip != "192.168.1.227" {
		t.Fatalf("chose %q; want the address on the same /24 as the beacon", ip)
	}
}

func TestResolveReachableRejectsUnreachableAdvertisedAddress(t *testing.T) {
	// The original bug: a peer whose preferred address is a virtual adapter on
	// a private network that nothing on the LAN can reach.
	from := netip.MustParseAddr("192.168.1.50")
	a := Announce{RawIP: "172.30.160.1", TCPAddr: "172.30.160.1:42424", IPs: []string{"172.30.160.1"}}
	ip, _ := resolveReachable(a, from)
	if ip != "192.168.1.50" {
		t.Fatalf("chose %q; nothing advertised is reachable, so the beacon source must be used", ip)
	}
}

func TestResolveReachableWithNoAddresses(t *testing.T) {
	from := netip.MustParseAddr("10.5.5.5")
	ip, _ := resolveReachable(Announce{}, from)
	if ip != "10.5.5.5" {
		t.Fatalf("chose %q, want the beacon source", ip)
	}
}

func TestDataPortOf(t *testing.T) {
	if got := dataPortOf(Announce{TCPAddr: "192.168.1.5:43000"}); got != 43000 {
		t.Fatalf("got %d", got)
	}
	if got := dataPortOf(Announce{}); got != 42424 {
		t.Fatalf("default should be 42424, got %d", got)
	}
	if got := dataPortOf(Announce{TCPAddr: "garbage"}); got != 42424 {
		t.Fatalf("malformed address should fall back to the default, got %d", got)
	}
}

func TestQuietOverrides(t *testing.T) {
	m := &Manager{}
	if m.Quiet() {
		t.Fatal("must start non-quiet")
	}
	m.SetQuiet(true)
	if !m.Quiet() {
		t.Fatal("SetQuiet(true) should suppress beacons")
	}
	m.SetAlwaysAdvertise(true)
	if m.Quiet() {
		t.Fatal("--keep-advertising must override quiet")
	}
	m.SetAlwaysAdvertise(false)
	if !m.Quiet() {
		t.Fatal("quiet should return once the override is cleared")
	}
}

func TestKnownTracksPeers(t *testing.T) {
	m := &Manager{peers: map[string]*Peer{}}
	if m.known("abc") {
		t.Fatal("unknown id should not be known")
	}
	m.peers["abc"] = &Peer{}
	if !m.known("abc") {
		t.Fatal("recorded id should be known")
	}
}
