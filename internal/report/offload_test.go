package report

import (
	"strings"
	"testing"
	"time"
)

// Oversized captured packets are the signature of NIC receive offload, which is
// a leading cause of Dup-ACK / Spurious-Retransmission annotations that never
// happened on the wire. The report must name it.
func TestOffloadEvidenceIsReported(t *testing.T) {
	l, r := base(), base()
	l.Kernel = map[string]uint64{
		"offload_coalesced_segments": 4312,
		"offload_max_segment_bytes":  65535,
	}
	fs := Diagnose(Input{Local: l, Peer: r, Duration: 10 * time.Second})
	f := find(fs, "OFFLOAD_LOCAL")
	if f == nil {
		t.Fatalf("expected an offload finding, got %d findings", len(fs))
	}
	if f.Severity != High {
		t.Errorf("offload should be High, got %s", f.Severity)
	}
	if !strings.Contains(strings.ToLower(f.Cause), "offload") &&
		!strings.Contains(strings.ToLower(f.Cause), "coalesc") {
		t.Errorf("cause should name offload/coalescing: %s", f.Cause)
	}
	md := Markdown(Input{Local: l, Peer: r, Duration: time.Second}, fs)
	if !strings.Contains(md, "coalesced") {
		t.Error("markdown report must surface the offload finding")
	}
	tx := Text(Input{Local: l, Peer: r, Duration: time.Second}, fs)
	if !strings.Contains(tx, "coalesced") {
		t.Error("terminal report must surface the offload finding")
	}
	if !strings.Contains(tx, "offload_coalesced_segments") {
		t.Error("the offload counters must appear in the kernel counter table")
	}
}

func TestNoOffloadEvidenceProducesNoFinding(t *testing.T) {
	l, r := base(), base()
	l.Kernel = map[string]uint64{"win_tcp_retrans_segs": 3}
	fs := Diagnose(Input{Local: l, Peer: r, Duration: time.Second})
	if find(fs, "OFFLOAD") != nil {
		t.Fatal("must not invent an offload finding when none was observed")
	}
}
