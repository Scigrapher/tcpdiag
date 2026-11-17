package report

import (
	"strings"
	"testing"
	"time"

	"tcpdiag/internal/wire"
)

// The SACK verdict must come from the observed SYN options, not from substring
// matching on notes: a peer that never sent a SYN is a different conclusion
// from a peer that sent a SYN without SACK-Permitted.
func TestSackFindingUsesObservedSynOptions(t *testing.T) {
	l, r := base(), base()
	l.Stack = "raw"
	l.SawPeerSyn = true
	l.PeerSACK = false
	l.PeerSynOpts = "MSS=1400, WindowScale=7"
	fs := Diagnose(Input{Local: l, Peer: r, Duration: time.Second})
	f := find(fs, "NOSACK")
	if f == nil {
		t.Fatal("expected a NOSACK finding when the SYN lacked SACK-Permitted")
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "MSS=1400, WindowScale=7") {
		t.Errorf("evidence must quote the observed options: %v", f.Evidence)
	}
	joined := strings.Join(f.Actions, " ")
	if !strings.Contains(joined, "--version") {
		t.Errorf("actions should include checking the build matches: %s", joined)
	}
}

func TestSackNegotiatedProducesNoFinding(t *testing.T) {
	l, r := base(), base()
	l.Stack = "raw"
	l.SawPeerSyn = true
	l.PeerSACK = true
	l.PeerSynOpts = "MSS=1400, WindowScale=7, SACK-Permitted, Timestamps"
	fs := Diagnose(Input{Local: l, Peer: r, Duration: time.Second})
	if find(fs, "NOSACK") != nil {
		t.Fatal("a negotiated SACK must not produce the finding")
	}
}

func TestMissingSynIsReportedSeparately(t *testing.T) {
	l, r := base(), base()
	l.Stack = "raw"
	l.SawPeerSyn = false
	l.PeerSACK = false
	fs := Diagnose(Input{Local: l, Peer: r, Duration: time.Second})
	if find(fs, "NOPEERSYN") == nil {
		t.Fatal("expected NOPEERSYN when no SYN was observed")
	}
	if find(fs, "NOSACK") != nil {
		t.Error("must not claim the peer lacks SACK when its SYN was never seen")
	}
}

func TestMissingSynFindingNamesTheConnectionState(t *testing.T) {
	l, r := base(), base()
	l.Stack = "raw"
	l.State = "SYN-SENT"
	l.SynRetrans = 5
	fs := Diagnose(Input{Local: l, Peer: r, Duration: time.Second})
	f := find(fs, "NOPEERSYN")
	if f == nil {
		t.Fatal("expected NOPEERSYN")
	}
	ev := strings.Join(f.Evidence, " ")
	if !strings.Contains(ev, "SYN-SENT") || !strings.Contains(ev, "5 SYN retransmission") {
		t.Errorf("evidence must explain how far the handshake got: %v", f.Evidence)
	}
	if !strings.Contains(strings.Join(f.Actions, " "), "handshake never completed") {
		t.Errorf("actions must call out the failed handshake: %v", f.Actions)
	}
	if f.Severity != High {
		t.Errorf("a stuck SYN-SENT handshake should be High, got %s", f.Severity)
	}
}

func TestNeverEstablishedRawSessionIsCritical(t *testing.T) {
	l, r := base(), base()
	l.Stack = "raw"
	l.State = "not established"
	fs := Diagnose(Input{Local: l, Peer: r, Duration: time.Second, StackMode: "raw"})
	f := find(fs, "NOPEERSYN")
	if f == nil {
		t.Fatal("expected NOPEERSYN")
	}
	if f.Severity != Critical {
		t.Errorf("a raw-only run with no session should be Critical, got %s", f.Severity)
	}
}

// This is the reported field case: the capture contains plenty of TCP, but it
// all belongs to other applications, while tcpdiag's raw session never came up.
// The report must say both things instead of leaving the user with "all UDP".
func TestReportDistinguishesUnrelatedTCPFromTCPDiagTraffic(t *testing.T) {
	l, r := base(), base()
	l.Stack = "raw"
	l.State = "not established"
	in := Input{
		Local: l, Peer: r, Duration: 112 * time.Second, StackMode: "raw",
		Capture: &wire.Capture{
			Engine: "windows-rawsock-kernelip", Packets: 2144, Bytes: 1796126,
			TCP: 142, UDP: 2000, DiagTCP: 0, DiagUDP: 1900,
			Injected: 41, TxBytes: 2460, PCAP: "test.pcap", PCAPSynthetic: 41,
		},
	}
	fs := Diagnose(in)
	noSyn := find(fs, "NOPEERSYN")
	if noSyn == nil || noSyn.Severity != Critical {
		t.Fatalf("expected a Critical no-handshake finding, got %+v", noSyn)
	}
	unseen := find(fs, "CAPTURE_TCP_UNSEEN")
	if unseen == nil {
		t.Fatal("expected the capture to explain that its TCP is not tcpdiag's")
	}
	if !strings.Contains(strings.Join(unseen.Evidence, " "), "tcpdiag-flow TCP=0") {
		t.Errorf("evidence must separate tcpdiag TCP from other TCP: %v", unseen.Evidence)
	}
}

func TestKernelStackNotSubjectToRawSackRules(t *testing.T) {
	l, r := base(), base()
	l.Stack = "kernel"
	l.SawPeerSyn = false
	l.PeerSACK = false
	fs := Diagnose(Input{Local: l, Peer: r, Duration: time.Second})
	if find(fs, "NOSACK") != nil || find(fs, "NOPEERSYN") != nil {
		t.Error("the raw-stack SYN rules must not fire for the kernel stack")
	}
}

func TestCaptureControlTrafficSeparatesToolNoise(t *testing.T) {
	c := &wire.Capture{
		Engine: "windows-rawsock", Packets: 1200, TCP: 1100, UDP: 100, DiagTCP: 1000, DiagUDP: 90,
		Control: 95, MaxBytes: 1500, Injected: 600,
	}
	lines := strings.Join(CaptureLines(c), "\n")
	if !strings.Contains(lines, "95 are tcpdiag control traffic") {
		t.Errorf("control traffic must be broken out:\n%s", lines)
	}
	// Healthy capture still produces no findings.
	if fs := CaptureFinding(c, "both"); len(fs) != 0 {
		t.Errorf("unexpected findings: %+v", fs)
	}
}
