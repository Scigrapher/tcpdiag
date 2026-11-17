package kernelstat

import "testing"

type fakeReader map[string]uint64

func (f fakeReader) Name() string            { return "fake" }
func (f fakeReader) Read() map[string]uint64 { return map[string]uint64(f) }

func TestDeltasForCountersOnly(t *testing.T) {
	base := fakeReader{
		"win_tcp_retrans_segs": 100,
		"win_tcp_in_segs":      500,
		"win_tcp_rto_min_ms":   200,
		"win_tcp_rto_max_ms":   10000,
		"win_tcp_curr_estab":   3,
	}
	d := NewDiffer(base)
	d.Delta() // establish the baseline
	got := d.Delta()
	if _, ok := got["win_tcp_retrans_segs/s"]; !ok {
		t.Error("counters must get a per-second rate")
	}
	if _, ok := got["win_tcp_in_segs/s"]; !ok {
		t.Error("counters must get a per-second rate")
	}
	for _, gauge := range []string{"win_tcp_rto_min_ms/s", "win_tcp_rto_max_ms/s", "win_tcp_curr_estab/s"} {
		if _, ok := got[gauge]; ok {
			t.Errorf("gauge %q must not be rate-normalised", gauge)
		}
	}
	if got["win_tcp_rto_min_ms"] != 200 {
		t.Errorf("gauge level lost: %d", got["win_tcp_rto_min_ms"])
	}
}

func TestIsGauge(t *testing.T) {
	yes := []string{"a_min_ms", "a_max_ms", "curr_estab", "rto_algorithm"}
	no := []string{"win_tcp_retrans_segs", "tcp_insegs", "tcpext_tcpspuriousrtos"}
	for _, k := range yes {
		if !isGauge(k) {
			t.Errorf("%q should be a gauge", k)
		}
	}
	for _, k := range no {
		if isGauge(k) {
			t.Errorf("%q should be a counter", k)
		}
	}
}
