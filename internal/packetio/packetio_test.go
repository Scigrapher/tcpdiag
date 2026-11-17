package packetio

import (
	"net/netip"
	"testing"
	"time"
)

func TestParseImpairment(t *testing.T) {
	im, err := ParseImpairment("loss=1.5,delay=12ms,jitter=4ms,dup=0.5,reorder=1,rate=100,burst=3@20")
	if err != nil {
		t.Fatal(err)
	}
	if im.LossPct != 1.5 || im.DupPct != 0.5 || im.ReorderPct != 1 {
		t.Fatalf("percentages wrong: %+v", im)
	}
	if im.Delay != 12*time.Millisecond || im.Jitter != 4*time.Millisecond {
		t.Fatalf("durations wrong: %+v", im)
	}
	if im.BurstLen != 3 || im.BurstPct != 20 {
		t.Fatalf("burst wrong: %+v", im)
	}
	if im.RateMbps != 100 {
		t.Fatalf("rate wrong: %v", im.RateMbps)
	}
	if !im.Enabled() {
		t.Fatal("should be enabled")
	}
	if _, err := ParseImpairment("loss=150"); err == nil {
		t.Fatal("out of range percentage must be rejected")
	}
	if _, err := ParseImpairment("nonsense"); err == nil {
		t.Fatal("malformed spec must be rejected")
	}
	none, err := ParseImpairment("")
	if err != nil || none != nil {
		t.Fatalf("empty spec must mean no impairment: %v %v", none, err)
	}
}

func ipPacket(src, dst netip.Addr, proto uint8) []byte {
	b := make([]byte, 40)
	b[0] = 4<<4 | 5
	b[9] = proto
	copy(b[12:16], src.AsSlice())
	copy(b[16:20], dst.AsSlice())
	return b
}

func TestSimDeliversAndDropsDeterministically(t *testing.T) {
	a := netip.MustParseAddr("10.9.0.1")
	b := netip.MustParseAddr("10.9.0.2")
	im, _ := ParseImpairment("loss=50")
	hub := NewSimHub(42)
	sa, sb := hub.Attach("a", a), hub.Attach("b", b)
	hub.SetLink(a, b, im)

	// A frame with no destination on the virtual LAN must be rejected.
	stray := hub.Attach("c", netip.MustParseAddr("10.9.0.3"))
	if err := stray.Send(ipPacket(a, netip.MustParseAddr("10.9.0.9"), 6)); err == nil {
		t.Fatal("sending to an unattached address must fail")
	}

	const n = 200
	for i := 0; i < n; i++ {
		if err := sa.Send(ipPacket(a, b, 6)); err != nil {
			t.Fatal(err)
		}
	}
	got := 0
	deadline := time.Now().Add(2 * time.Second)
	for got < n && time.Now().Before(deadline) {
		select {
		case <-sb.Recv():
			got++
		case <-time.After(250 * time.Millisecond):
			i := 0
			for i < n && time.Now().Before(deadline) {
				select {
				case <-sb.Recv():
					got++
				case <-time.After(50 * time.Millisecond):
					i++
				}
			}
		}
	}
	if got == 0 || got == n {
		t.Fatalf("50%% loss should deliver some but not all: got %d", got)
	}
	if hub.Dropped == 0 {
		t.Fatal("drops should be counted")
	}
	t.Logf("delivered %d/%d, hub dropped %d", got, n, hub.Dropped)
}

func TestDstSrcAddrValidation(t *testing.T) {
	if _, err := DstAddr([]byte{1, 2, 3}); err == nil {
		t.Fatal("short packet must be rejected")
	}
	bad := ipPacket(netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2"), 6)
	bad[0] = 6<<4 | 5
	if _, err := DstAddr(bad); err == nil {
		t.Fatal("non-IPv4 must be rejected")
	}
	got, err := DstAddr(ipPacket(netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2"), 6))
	if err != nil || got.String() != "2.2.2.2" {
		t.Fatalf("dst: %v %v", got, err)
	}
	src, err := SrcAddr(ipPacket(netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2"), 6))
	if err != nil || src.String() != "1.1.1.1" {
		t.Fatalf("src: %v %v", src, err)
	}
}
