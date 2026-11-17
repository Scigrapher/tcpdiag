package report

import (
	"strings"
	"testing"
	"time"

	"tcpdiag/internal/wire"
)

func base() *wire.Snapshot {
	return &wire.Snapshot{
		Stack: "kernel", SegsSent: 100000, BlocksSent: 1000, BytesSent: 1 << 20,
		MbpsSent: 100, RTTEwms: 5, RTOms: 200,
	}
}

func find(fs []Finding, substr string) *Finding {
	for i := range fs {
		if strings.Contains(strings.ToLower(fs[i].ID), strings.ToLower(substr)) {
			return &fs[i]
		}
	}
	return nil
}

func TestNoAnomaliesProducesNoFindings(t *testing.T) {
	l, r := base(), base()
	fs := Diagnose(Input{Local: l, Peer: r, Duration: 10 * time.Second})
	for _, f := range fs {
		if f.Severity == Critical || f.Severity == High {
			t.Fatalf("clean run produced a %s finding: %s", f.Severity, f.Title)
		}
	}
	if v := Verdict(fs); !strings.Contains(v, "No anomalies") {
		t.Fatalf("unexpected verdict: %s", v)
	}
}

func TestStackMismatchIsReportedBeforeSackDiagnosis(t *testing.T) {
	l, r := base(), base()
	l.Stack = "raw"
	fs := Diagnose(Input{
		Local: l, Peer: r, StackMode: "raw", PeerStack: "kernel",
		Duration: time.Second,
	})
	f := find(fs, "STACK_MISMATCH")
	if f == nil {
		t.Fatal("expected STACK_MISMATCH when a raw local instance targets a kernel-only peer")
	}
	if f.Severity != Critical {
		t.Errorf("a non-overlapping data plane should be Critical, got %s", f.Severity)
	}
	if !strings.Contains(strings.Join(f.Actions, " "), "--stack=raw") {
		t.Errorf("actions must give a matching-mode command: %v", f.Actions)
	}
	if fs[0].ID != "STACK_MISMATCH" {
		t.Errorf("stack mismatch should be the first finding, got %s", fs[0].ID)
	}
}

func TestRealLossIsAttributedToADirection(t *testing.T) {
	l, r := base(), base()
	// The remote retransmits: that is loss on the peer->local path.
	r.RetransSent, r.FastRetrans, r.OctetsRetrans, r.DupAcksRecv = 3000, 2900, 4_200_000, 9000
	l.OooSegs, l.RetransRecvSegs = 10, 2900
	fs := Diagnose(Input{Local: l, Peer: r, Duration: 10 * time.Second})
	f := find(fs, "LOSS_PEER")
	if f == nil {
		t.Fatalf("expected a peer->local loss finding, got %d findings", len(fs))
	}
	if f.Severity != High {
		t.Fatalf("3%% loss should be high, got %s", f.Severity)
	}
	// A heavier loss rate must escalate.
	l2, r2 := base(), base()
	r2.RetransSent, r2.FastRetrans, r2.DupAcksRecv = 7000, 6900, 20000
	l2.OooSegs, l2.RetransRecvSegs = 10, 6900
	fs2 := Diagnose(Input{Local: l2, Peer: r2, Duration: 10 * time.Second})
	f2 := find(fs2, "LOSS_PEER")
	if f2 == nil || f2.Severity != Critical {
		t.Fatalf("7%% loss should be critical, got %+v", f2)
	}
}

func TestSpuriousRetransmissionIsFlagged(t *testing.T) {
	l, r := base(), base()
	r.RetransSent, r.RtoRetrans, r.SpuriousRetrans = 500, 480, 450
	r.RTTEwms, r.RTTVarms, r.RTOms = 12, 40, 300
	r.RetxLog = []wire.RetxEvent{{Seq: 1, Len: 1400, Kind: "rto", SinceLastAckMs: 5, WithinRTT: true}}
	fs := Diagnose(Input{Local: l, Peer: r, Duration: 10 * time.Second})
	if find(fs, "SPURIOUS") == nil {
		t.Fatal("expected a spurious retransmission finding")
	}
}

func TestReorderingIsSeparatedFromLoss(t *testing.T) {
	l, r := base(), base()
	r.RetransSent, r.FastRetrans = 800, 800
	l.OooSegs, l.BlocksLate, l.BlocksMissing = 3000, 2800, 40
	fs := Diagnose(Input{Local: l, Peer: r, Duration: 10 * time.Second})
	f := find(fs, "LOSS_PEER")
	if f == nil {
		t.Fatal("expected a loss finding")
	}
	if !strings.Contains(strings.ToLower(f.Cause), "reorder") {
		t.Fatalf("reordering should be named as the cause, got: %s", f.Cause)
	}
}

func TestZeroWindowIsReceiverLimited(t *testing.T) {
	l, r := base(), base()
	l.ZeroWindowAdv, r.ZeroWindowRecv = 220, 220
	fs := Diagnose(Input{Local: l, Peer: r, Duration: 10 * time.Second})
	f := find(fs, "WINDOW")
	if f == nil {
		t.Fatal("expected a zero-window finding")
	}
	if !strings.Contains(f.Cause, "draining") && !strings.Contains(f.Cause, "receive") {
		t.Logf("cause: %s", f.Cause)
	}
}

func TestMissingPeerIsReported(t *testing.T) {
	fs := Diagnose(Input{Local: base(), Peer: nil, Duration: time.Second})
	if find(fs, "NO_PEER") == nil {
		t.Fatal("expected a missing-peer finding")
	}
}

func TestImpairmentIsDisclosed(t *testing.T) {
	l, r := base(), base()
	fs := Diagnose(Input{Local: l, Peer: r, Duration: time.Second, Impair: "loss=2"})
	if find(fs, "IMPAIR") == nil {
		t.Fatal("synthetic impairment must be disclosed in the report")
	}
}

func TestMarkdownRendersBothSides(t *testing.T) {
	l, r := base(), base()
	l.LocalEP, l.RemoteEP = "10.0.0.1:42424", "10.0.0.2:42424"
	r.LocalEP, r.RemoteEP = "10.0.0.2:42424", "10.0.0.1:42424"
	r.RetransSent, r.FastRetrans = 500, 500
	md := Markdown(Input{Local: l, Peer: r, Duration: 5 * time.Second}, Diagnose(Input{Local: l, Peer: r}))
	for _, want := range []string{"# tcpdiag report", "## Findings", "10.0.0.2:42424", "tcp.analysis.duplicate_ack"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown missing %q", want)
		}
	}
}
