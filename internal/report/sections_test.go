package report

import (
	"strings"
	"testing"
	"time"

	"tcpdiag/internal/wire"
)

func pairWith(k, r func(*wire.Snapshot)) (*StackPair, *StackPair) {
	ks, rs := base(), base()
	if k != nil {
		k(ks)
	}
	if r != nil {
		r(rs)
	}
	return &StackPair{Stack: "kernel", Local: ks, Peer: base()}, &StackPair{Stack: "raw", Local: rs, Peer: base()}
}

func TestStackComparisonDetectsKernelOnlyRetransmission(t *testing.T) {
	kernel, raw := pairWith(
		func(s *wire.Snapshot) { s.RetransSent, s.SegsSent, s.FastRetrans = 4000, 100000, 3900 },
		func(s *wire.Snapshot) { s.RetransSent, s.SegsSent = 12, 98000 },
	)
	fs := StackComparison(kernel, raw)
	if find(fs, "STACK_KERNEL_ONLY") == nil {
		t.Fatalf("expected STACK_KERNEL_ONLY, got %+v", fs)
	}
	if !strings.Contains(strings.ToLower(fs[0].Cause), "inside the host") {
		t.Errorf("cause should point inside the host: %s", fs[0].Cause)
	}
	// The actions must be concrete commands, not "compare the stacks".
	joined := strings.Join(fs[0].Actions, "\n")
	if !strings.Contains(joined, "tcpdiag -stack=both") {
		t.Errorf("actions must contain an exact command: %s", joined)
	}
	if !strings.Contains(joined, "Get-NetAdapterAdvancedProperty") {
		t.Errorf("actions should give the exact offload commands: %s", joined)
	}
}

func TestStackComparisonAgreementImplicatesNetwork(t *testing.T) {
	kernel, raw := pairWith(
		func(s *wire.Snapshot) { s.RetransSent, s.SegsSent, s.FastRetrans = 5000, 100000, 4900 },
		func(s *wire.Snapshot) { s.RetransSent, s.SegsSent, s.FastRetrans = 4600, 99000, 4500 },
	)
	fs := StackComparison(kernel, raw)
	if find(fs, "STACK_AGREE") == nil {
		t.Fatalf("expected STACK_AGREE, got %+v", fs)
	}
	if fs[0].Severity != High {
		t.Errorf("agreement should be High, got %s", fs[0].Severity)
	}
}

func TestStackComparisonNilSafe(t *testing.T) {
	if got := StackComparison(nil, nil); got != nil {
		t.Error("nil pairs must yield no findings")
	}
	kernel, _ := pairWith(nil, nil)
	if got := StackComparison(kernel, nil); got != nil {
		t.Error("a single stack must not produce a comparison")
	}
}

func TestCaptureFindingNoTCP(t *testing.T) {
	c := &wire.Capture{Engine: "windows-rawsock", Packets: 412, Bytes: 30000, UDP: 412}
	fs := CaptureFinding(c, "raw")
	f := find(fs, "CAPTURE_NO_TCP")
	if f == nil {
		t.Fatalf("expected CAPTURE_NO_TCP, got %+v", fs)
	}
	if f.Severity != Critical {
		t.Errorf("capturing no TCP in raw mode should be Critical, got %s", f.Severity)
	}
	joined := strings.Join(f.Actions, "\n")
	for _, want := range []string{"tcpdiag -stack=raw", "-local-ip", "firewall", "42425"} {
		if !strings.Contains(joined, want) {
			t.Errorf("actions missing %q:\n%s", want, joined)
		}
	}
}

func TestCaptureFindingHealthyCaptureSilent(t *testing.T) {
	c := &wire.Capture{Engine: "windows-rawsock", Packets: 50000, TCP: 49000, UDP: 900, DiagTCP: 48000, DiagUDP: 800, Injected: 25000}
	if fs := CaptureFinding(c, "raw"); len(fs) != 0 {
		t.Fatalf("a healthy capture should produce no findings, got %+v", fs)
	}
}

// A host with unrelated TCP sessions can make the capture look healthy while
// tcpdiag's own TCP is missing entirely. That distinction must be a finding.
func TestCaptureFindingOnlyUnrelatedTCP(t *testing.T) {
	c := &wire.Capture{Engine: "windows-rawsock", Packets: 500, TCP: 142, UDP: 358}
	fs := CaptureFinding(c, "raw")
	f := find(fs, "CAPTURE_NO_DIAG_TCP")
	if f == nil {
		t.Fatalf("expected CAPTURE_NO_DIAG_TCP, got %+v", fs)
	}
	if f.Severity != Critical {
		t.Errorf("no tcpdiag TCP should be Critical, got %s", f.Severity)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "other applications") {
		t.Errorf("evidence should separate unrelated TCP: %v", f.Evidence)
	}
}

// The Windows capture path can omit locally injected raw TCP even though it is
// on the wire. That is a platform limitation, not a failed handshake, and the
// advice differs.
func TestCaptureFindingInjectedTCPNotSeen(t *testing.T) {
	c := &wire.Capture{Engine: "windows-rawsock-kernelip", Packets: 500, TCP: 142, UDP: 358, Injected: 41, PCAPSynthetic: 41, PCAP: "wire.pcap"}
	fs := CaptureFinding(c, "raw")
	f := find(fs, "CAPTURE_TCP_UNSEEN")
	if f == nil {
		t.Fatalf("expected CAPTURE_TCP_UNSEEN, got %+v", fs)
	}
	if f.Severity != High {
		t.Errorf("a capture blind spot should be High, got %s", f.Severity)
	}
	if !strings.Contains(strings.Join(f.Actions, " "), "locally injected") {
		t.Errorf("advice must explain that the pcap still has our TX: %v", f.Actions)
	}
}

func TestCaptureLinesExplainThePcapScope(t *testing.T) {
	c := &wire.Capture{
		Engine: "windows-rawsock", Packets: 900, TCP: 120, UDP: 780,
		DiagTCP: 40, DiagUDP: 700, MaxBytes: 1460,
		PCAP: "wire.pcap", PCAPFiltered: 123, PCAPSynthetic: 41, PCAPDuplicate: 2,
	}
	lines := strings.Join(CaptureLines(c), "\n")
	for _, want := range []string{
		"tcpdiag flows only: tcp 40, udp 700",
		"123 unrelated packet(s) omitted",
		"41 locally injected packet(s)",
		"2 duplicate(s) suppressed",
	} {
		if !strings.Contains(lines, want) {
			t.Errorf("capture summary missing %q:\n%s", want, lines)
		}
	}
}

func TestCaptureFindingTxOnly(t *testing.T) {
	c := &wire.Capture{Engine: "linux-afpacket", Packets: 0, Injected: 5000, TxBytes: 100000}
	fs := CaptureFinding(c, "both")
	if find(fs, "CAPTURE_TX_ONLY") == nil {
		t.Fatalf("expected CAPTURE_TX_ONLY, got %+v", fs)
	}
}

func TestReportsRenderNewSections(t *testing.T) {
	kernel, raw := pairWith(
		func(s *wire.Snapshot) { s.RetransSent, s.SegsSent, s.FastRetrans = 4000, 100000, 3900 },
		func(s *wire.Snapshot) { s.RetransSent, s.SegsSent = 12, 98000 },
	)
	in := Input{
		Local: kernel.Local, Peer: kernel.Peer, Duration: 10 * time.Second,
		StackMode: "both", Kernel: kernel, Raw: raw,
		Capture: &wire.Capture{Engine: "windows-rawsock", Packets: 900, TCP: 880, UDP: 20, DiagTCP: 800, DiagUDP: 10, MaxBytes: 1500, Injected: 450, PCAP: "wire.pcap"},
	}
	fs := Diagnose(in)
	if find(fs, "STACK_KERNEL_ONLY") == nil {
		t.Fatal("Diagnose must include the stack comparison")
	}
	tx := Text(in, fs)
	for _, want := range []string{"WIRE OBSERVATION", "STACK COMPARISON", "windows-rawsock", "tcp 880", "wire.pcap"} {
		if !strings.Contains(tx, want) {
			t.Errorf("terminal report missing %q", want)
		}
	}
	md := Markdown(in, fs)
	for _, want := range []string{"## Wire observation", "## Stack comparison", "windows-rawsock"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown report missing %q", want)
		}
	}
}

// The whole point of the change: no finding may tell the user to go capture
// when tcpdiag is already capturing, nor tell them to "compare the stacks"
// without giving the command.
func TestActionsAreActionable(t *testing.T) {
	kernel, raw := pairWith(
		func(s *wire.Snapshot) { s.RetransSent, s.SegsSent, s.FastRetrans = 4000, 100000, 3900 },
		func(s *wire.Snapshot) { s.RetransSent, s.SegsSent = 12, 98000 },
	)
	in := Input{Local: kernel.Local, Peer: kernel.Peer, Duration: time.Second, StackMode: "both", Kernel: kernel, Raw: raw}
	for _, f := range Diagnose(in) {
		for _, a := range f.Actions {
			low := strings.ToLower(a)
			if low == "capture on both ends" || strings.Contains(low, "compare --stack=kernel against --stack=raw") {
				t.Errorf("finding %s still contains vague advice: %q", f.ID, a)
			}
		}
	}
}
