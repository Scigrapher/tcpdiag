package report

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"tcpdiag/internal/discovery"
	"tcpdiag/internal/wire"
)

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

type Finding struct {
	ID         string             `json:"id"`
	Title      string             `json:"title"`
	Severity   Severity           `json:"severity"`
	Confidence string             `json:"confidence"`
	Direction  string             `json:"direction,omitempty"`
	Evidence   []string           `json:"evidence,omitempty"`
	Cause      string             `json:"cause,omitempty"`
	Actions    []string           `json:"actions,omitempty"`
	Filters    []string           `json:"filters,omitempty"`
	Metrics    map[string]float64 `json:"metrics,omitempty"`
}

type Input struct {
	Local       *wire.Snapshot    `json:"local"`
	Peer        *wire.Snapshot    `json:"peer"`
	KernelLocal map[string]uint64 `json:"kernel_local,omitempty"`
	KernelPeer  map[string]uint64 `json:"kernel_peer,omitempty"`
	Duration    time.Duration     `json:"duration_ns"`
	AppRTTMs    float64           `json:"app_rtt_ms"`
	Impair      string            `json:"impair,omitempty"`
	StackMode   string            `json:"stack_mode"`
	PeerStack   string            `json:"peer_stack,omitempty"`
	ProbeNotes  []string          `json:"probe_notes,omitempty"`
	Capture     *wire.Capture     `json:"capture,omitempty"`
	Kernel      *StackPair        `json:"kernel,omitempty"`
	Raw         *StackPair        `json:"raw,omitempty"`
}

func f64(v uint64) float64 { return float64(v) }

func pct(n, d uint64) float64 {
	if d == 0 {
		return 0
	}
	return 100 * float64(n) / float64(d)
}

func ratio(a, b float64) float64 {
	if b == 0 {
		return math.Inf(1)
	}
	return a / b
}

func stackPlanes(s string) string {
	switch s {
	case "raw":
		return "user-space raw TCP only"
	case "kernel":
		return "OS TCP only"
	case "observe":
		return "OS TCP data plane plus passive raw capture"
	case "both":
		return "OS TCP and user-space raw TCP"
	default:
		return "unknown or older mode"
	}
}

// Diagnose turns the two embedded snapshots into ranked findings. It reasons
// about the *pair* of views, which is what makes a single observation point
// sufficient: each side reports its own retransmits, dup-ACKs, holes and
// timers, so loss can be attributed to a direction and separated from
// reordering, receiver limits, and over-eager timers.
func Diagnose(in Input) []Finding {
	var out []Finding
	l, r := in.Local, in.Peer
	if l == nil || r == nil {
		return append(out, Finding{
			ID: "NO_PEER", Title: "Only one side reported", Severity: High, Confidence: "high",
			Evidence: []string{"the far side never delivered a telemetry block"},
			Cause:    "the peer never completed a handshake, or its return path is blocked",
			Actions:  []string{"confirm both instances discovered each other (tcpdiag --list-peers)", "check host firewalls for the data and raw ports"},
		})
	}

	if in.PeerStack != "" && !discovery.StacksCompatible(in.StackMode, in.PeerStack) {
		out = append(out, Finding{
			ID:         "STACK_MISMATCH",
			Title:      fmt.Sprintf("Stack mismatch: local %s and peer %s share no data plane", in.StackMode, in.PeerStack),
			Severity:   Critical,
			Confidence: "high",
			Evidence: []string{
				fmt.Sprintf("local mode %s starts: %s", in.StackMode, stackPlanes(in.StackMode)),
				fmt.Sprintf("peer mode %s starts: %s", in.PeerStack, stackPlanes(in.PeerStack)),
				"user-space raw TCP can only talk to raw/both; the kernel data plane can only talk to kernel/both/observe",
			},
			Cause: "the two instances are running different data planes, so the connection attempts are aimed at ports the other side never opens. A raw handshake to tcp/42425 cannot succeed against a kernel-only peer, and a kernel dial to tcp/42424 cannot succeed against a raw-only peer",
			Actions: []string{
				"run both machines with the same mode: tcpdiag --stack=raw on both, or --stack=kernel on both",
				"or use --stack=both on at least one side so it can meet the other's plane",
				"verify with tcpdiag peers: the stack column shows each peer's advertised mode",
			},
		})
	}

	totalSent := l.SegsSent + r.SegsSent
	if totalSent == 0 {
		totalSent = l.BytesSent/1460 + r.BytesSent/1460
	}

	// --- 1. Loss, attributed to a direction --------------------------------
	for _, d := range []struct {
		name      string
		sender    *wire.Snapshot
		receiver  *wire.Snapshot
		direction string
	}{{"peer->local", r, l, "inbound (peer to us)"}, {"local->peer", l, r, "outbound (us to peer)"}} {
		s, rcv := d.sender, d.receiver
		if s.RetransSent == 0 {
			continue
		}
		base := s.SegsSent
		if base == 0 {
			base = s.BytesSent / uint64(1460)
		}
		lr := pct(s.RetransSent, base)
		sev := Low
		if lr > 5 {
			sev = Critical
		} else if lr > 1 {
			sev = High
		} else if lr > 0.1 {
			sev = Medium
		}
		f := Finding{
			ID:         "LOSS_" + strings.ToUpper(d.name),
			Title:      fmt.Sprintf("%.3f%% of %s segments were retransmitted", lr, d.direction),
			Severity:   sev,
			Confidence: "high",
			Direction:  d.direction,
			Evidence: []string{
				fmt.Sprintf("sender retransmitted %d segments (%d octets) out of %d sent", s.RetransSent, s.OctetsRetrans, base),
				fmt.Sprintf("receiver observed %d missing blocks, %d out-of-order segments, %d late arrivals", rcv.BlocksMissing, rcv.OooSegs, rcv.BlocksLate),
				fmt.Sprintf("fast retransmits %d, RTO retransmits %d, spurious %d", s.FastRetrans, s.RtoRetrans, s.SpuriousRetrans),
				fmt.Sprintf("duplicate ACKs received by sender: %d", s.DupAcksRecv),
			},
			Metrics: map[string]float64{"loss_pct": lr, "retrans": f64(s.RetransSent), "dup_acks": f64(s.DupAcksRecv)},
			Filters: []string{"tcp.analysis.fast_retransmission", "tcp.analysis.duplicate_ack", "tcp.analysis.lost_segment"},
		}
		switch {
		case s.SpuriousRetrans > s.RetransSent/3 && s.RetransSent > 0:
			f.Cause = "a large share of retransmits fired before the estimated RTT had elapsed: the retransmission timer, not the path, is the primary suspect"
			f.Actions = []string{
				"raise the minimum RTO (raw mode: --min-rto 20ms) and compare",
				"enable TCP timestamps so RTT estimation is not corrupted by delayed ACKs",
				"check for a middlebox that delays ACKs (proxy/firewall/WAN optimiser)",
			}
		case rcv.OooSegs > rcv.BlocksMissing && rcv.OooSegs > 10:
			f.Cause = "out-of-order delivery dominates missing data: the path is reordering packets, and the stack reacts as if they were lost"
			f.Actions = []string{
				"check for NIC multi-queue (RSS/RPS) or interrupt coalescing reordering flows",
				"check for bonding/team interfaces or ECMP paths with different latency",
				"on Wi-Fi, look for aggregation/retry behaviour and channel contention",
				"temporarily disable LRO/GRO to rule out offload-induced reordering",
			}
			f.Filters = append(f.Filters, "tcp.analysis.out_of_order")
		case s.FastRetrans > 0 && s.RtoRetrans == 0:
			f.Cause = "loss is recovered by fast retransmit: a router or AP dropped packets while three later segments got through - classic congestion or wireless drop"
			f.Actions = []string{
				"measure the queueing delay of the path (tcpdiag --probe) to look for bufferbloat",
				"reduce the offered rate or enable AQM (fq_codel/scheduler) on the first hop",
				"if the loss is one-directional, inspect the uplink/AP of that direction",
			}
		case s.RtoRetrans > 0:
			f.Cause = "timeouts were needed, meaning whole windows went missing at once or ACKs stopped returning"
			f.Actions = []string{
				"look for burst loss (tcpdiag --impair burst=3@20 to compare the signature)",
				"inspect interface error/drop counters on both hosts and the first switch port",
			}
		}
		out = append(out, f)
	}

	// --- 2. Spurious retransmission analysis --------------------------------
	for _, s := range []struct {
		who *wire.Snapshot
		tag string
	}{{l, "local"}, {r, "remote"}} {
		snap := s.who
		if snap.SpuriousRetrans == 0 && snap.SpuriousRecv == 0 {
			continue
		}
		sev := High
		if snap.SpuriousRetrans+snap.SpuriousRecv > 100 {
			sev = Critical
		}
		f := Finding{
			ID:         "SPURIOUS_" + strings.ToUpper(s.tag),
			Title:      fmt.Sprintf("%d spurious retransmission(s) observed on the %s side", snap.SpuriousRetrans+snap.SpuriousRecv, s.tag),
			Severity:   sev,
			Confidence: "medium",
			Evidence:   []string{},
			Filters:    []string{"tcp.analysis.spurious_retransmission", "tcp.time_delta > 0"},
		}
		for _, e := range snap.RetxLog {
			if e.Kind == "rto" || e.WithinRTT {
				f.Evidence = append(f.Evidence, fmt.Sprintf("%s seq=%d len=%d fired %dms after last ACK%s", e.Kind, e.Seq, e.Len, e.SinceLastAckMs, map[bool]string{true: ", WITHIN estimated RTT", false: ""}[e.WithinRTT]))
			}
		}
		if len(f.Evidence) == 0 {
			f.Evidence = append(f.Evidence, fmt.Sprintf("sender reported spurious_retrans=%d, receiver saw already-ACKed data again=%d", snap.SpuriousRetrans, snap.SpuriousRecv))
		}
		rtoRatio := 0.0
		if snap.RTTEwms > 0 {
			rtoRatio = snap.RTOms / snap.RTTEwms
		}
		switch {
		case snap.RTTVarms > snap.RTTEwms*0.5:
			f.Cause = fmt.Sprintf("RTT is highly variable (SRTT %.2fms, RTTVAR %.2fms, RTO %.0fms): delayed ACKs plus variance make the retransmit timer expire while the original data is still in flight", snap.RTTEwms, snap.RTTVarms, snap.RTOms)
			f.Actions = []string{
				"enable TCP timestamps (raw mode: --timestamps, kernel: net.ipv4.tcp_timestamps=1)",
				"disable delayed ACKs on the receiver, or test with them forced on/off to compare",
				"look for bufferbloat: a shallow-queue path with occasional 100ms+ stalls produces exactly this",
			}
		case rtoRatio > 0 && rtoRatio < 2:
			f.Cause = fmt.Sprintf("RTO (%.0fms) is only %.1fx the smoothed RTT (%.2fms): the timer is too tight for this path", snap.RTOms, rtoRatio, snap.RTTEwms)
			f.Actions = []string{"raise --min-rto, or in kernel mode increase the initial RTO / enable consistent RTT sampling"}
		case snap.SpuriousRecv > 0 && snap.SpuriousRetrans == 0:
			f.Cause = "the receiver saw data again that it had already acknowledged. When the sender did not report retransmitting, this is usually NIC receive offload (LRO/GRO) or a capturing point that makes one segment look like two"
			f.Actions = []string{
				"disable LRO/GRO/RSC and re-run to see whether the annotation disappears",
				"capture at the sender as well: offload makes single-sided captures lie",
				"check for a transparent proxy or VPN that duplicates segments",
			}
		default:
			f.Cause = "segments were resent that the peer had already acknowledged"
			f.Actions = []string{"Run the comparison and read the STACK COMPARISON section: tcpdiag -stack=both -report both.md -v"}
		}
		out = append(out, f)
	}

	// --- 3. Dup ACK pressure -------------------------------------------------
	if d := l.DupAcksRecv + r.DupAcksRecv; d > 0 {
		sev := Info
		if d > 1000 {
			sev = Medium
		}
		out = append(out, Finding{
			ID: "DUPACK", Title: fmt.Sprintf("%d duplicate ACK(s) exchanged", d), Severity: sev, Confidence: "high",
			Evidence: []string{
				fmt.Sprintf("local received %d, remote received %d", l.DupAcksRecv, r.DupAcksRecv),
				fmt.Sprintf("holes seen: local %d, remote %d", l.BlocksMissing, r.BlocksMissing),
			},
			Cause:   "duplicate ACKs are a receiver telling a sender 'I have a hole at sequence X'. They are only bad when they are numerous or spurious - see the loss/reordering findings for attribution",
			Actions: []string{"use the Wireshark filter tcp.analysis.duplicate_ack and check the ack number is constant per burst"},
			Filters: []string{"tcp.analysis.duplicate_ack"},
		})
	}

	// --- 4. Receiver-limited, not network-limited ---------------------------
	if l.ZeroWindowAdv+r.ZeroWindowAdv > 0 || l.ZeroWindowRecv+r.ZeroWindowRecv > 0 {
		out = append(out, Finding{
			ID: "WINDOW", Title: "Zero window / flow-control stall detected", Severity: High, Confidence: "high",
			Evidence: []string{
				fmt.Sprintf("local advertised 0 window %d time(s), remote advertised 0 window %d time(s)", l.ZeroWindowAdv, r.ZeroWindowAdv),
				fmt.Sprintf("zero windows received: local %d, remote %d", l.ZeroWindowRecv, r.ZeroWindowRecv),
				fmt.Sprintf("window probes: local %d, remote %d", l.WindowProbes, r.WindowProbes),
			},
			Cause:   "a receive application is not draining the socket. Retransmissions caused by a stalled receiver look identical to network loss in a one-sided capture",
			Actions: []string{"raise the socket buffer (--rcv-buf) and read faster on the receiving side", "check CPU saturation / softirq saturation on the receiver"},
			Filters: []string{"tcp.analysis.zero_window", "tcp.analysis.window_update"},
			Metrics: map[string]float64{"zw_adv": f64(l.ZeroWindowAdv + r.ZeroWindowAdv)},
		})
	}

	// --- 5. Window scaling / BDP --------------------------------------------
	bdp := l.RTTEwms * l.MbpsSent / 8000.0 // KiB
	if bdp > 64 && l.PeerWindow < 1<<16 {
		out = append(out, Finding{
			ID: "SCALING", Title: "Receive window is too small for the bandwidth-delay product", Severity: Medium, Confidence: "medium",
			Evidence: []string{fmt.Sprintf("BDP is about %.0f KiB but the advertised window is %.0f KiB", bdp, float64(l.PeerWindow)/1024)},
			Cause:    "window scaling is missing or the socket buffer is small; throughput collapses and the sender idles, which invites timeouts",
			Actions:  []string{"raise --rcv-buf / SO_RCVBUF", "verify window scaling is not disabled (Windows: netsh interface tcp show global)"},
		})
	}
	// Decided from the recorded SYN options rather than substring matching on
	// free-text notes: an absent option and an unobserved SYN are different
	// conclusions and must not be reported as the same one.
	if l.Stack == "raw" && l.SawPeerSyn && !l.PeerSACK {
		out = append(out, Finding{
			ID:         "NOSACK",
			Title:      "Peer SYN carried no SACK-Permitted option",
			Severity:   Low,
			Confidence: "high",
			Evidence: []string{
				"observed peer SYN options: [" + l.PeerSynOpts + "]",
			},
			Cause:   "without SACK the sender retransmits everything after a hole instead of only the missing range, which inflates retransmission counts and produces spurious retransmissions",
			Actions: []string{"confirm both machines run the same build: tcpdiag --version", "enable SACK on the peer: Windows: netsh int tcp set global sack=enabled ; Linux: sysctl net.ipv4.tcp_sack=1", "re-run with -v and check the peer SYN options line for SACK-Permitted"},
		})
	}
	if l.Stack == "raw" && !l.SawPeerSyn {
		severity := Info
		switch l.State {
		case "not established", "CLOSED":
			severity = Critical
		case "SYN-SENT", "SYN-RECEIVED":
			severity = High
		}
		evidence := []string{"the local raw stack never saw a SYN from the peer"}
		if l.State != "" {
			evidence = append(evidence, "local raw connection state: "+l.State)
		}
		if l.SynRetrans > 0 {
			evidence = append(evidence, fmt.Sprintf("it sent %d SYN retransmission(s) without a reply", l.SynRetrans))
		}
		if l.SegsSent > 0 {
			evidence = append(evidence, fmt.Sprintf("segments sent by the raw stack: %d", l.SegsSent))
		}
		for _, n := range l.Notes {
			if strings.HasPrefix(n, "raw session not established") {
				evidence = append(evidence, n)
			}
		}
		actions := []string{
			"check the WIRE OBSERVATION section for whether any TCP reached this host",
			"verify inbound tcp/42425-42426 is allowed through the local firewall",
			"run with -v and check the first raw connect error (it names the exact failure)",
		}
		if l.State == "SYN-SENT" {
			actions = append([]string{
				"the raw handshake never completed: confirm the peer is listening on tcp/42425 and allows inbound tcp/42425-42426",
			}, actions...)
		}
		title := "No peer SYN was observed, so SACK negotiation is unknown"
		switch l.State {
		case "SYN-SENT":
			title = "Raw TCP handshake never completed: no SYN/ACK from the peer"
		case "not established":
			title = "Raw TCP session was never established"
		}
		out = append(out, Finding{
			ID:         "NOPEERSYN",
			Title:      title,
			Severity:   severity,
			Confidence: "high",
			Evidence:   evidence,
			Cause:      "the raw connection is not established, so there is no SYN option set to judge; reporting a SACK verdict would be a guess",
			Actions:    actions,
		})
	}

	// --- 6. Bufferbloat / RTT variance --------------------------------------
	if l.Hist != nil && l.Hist.Count > 20 {
		p50 := percentile(l.Hist, 0.50)
		p99 := percentile(l.Hist, 0.99)
		if p50 > 0 && ratio(p99, p50) > 5 {
			out = append(out, Finding{
				ID: "BUFFERBLOAT", Title: fmt.Sprintf("RTT is unstable: p50 %.1fms vs p99 %.1fms", p50, p99), Severity: High, Confidence: "medium",
				Evidence: []string{fmt.Sprintf("min %.1fms max %.1fms over %d samples", l.Hist.MinMs, l.Hist.MaxMs, l.Hist.Count)},
				Cause:    "queueing delay spikes - a shallow-queue router, Wi-Fi retries, or an unmanaged uplink. Every spike risks an RTO, which is the most common cause of spurious retransmissions on real networks",
				Actions:  []string{"run --probe to measure the RTT distribution under load", "enable AQM on the first hop, or throttle the sender below the link rate"},
			})
		}
	}

	// --- 7. Path asymmetry ---------------------------------------------------
	li := pct(l.RetransSent, max64(l.SegsSent, 1))
	ri := pct(r.RetransSent, max64(r.SegsSent, 1))
	if math.Abs(li-ri) > 1.0 && (li > 0.5 || ri > 0.5) {
		out = append(out, Finding{
			ID: "ASYM", Title: fmt.Sprintf("Loss is asymmetric: %.3f%% one way vs %.3f%% the other", li, ri), Severity: Medium, Confidence: "high",
			Evidence: []string{fmt.Sprintf("local retransmits %d, remote retransmits %d", l.RetransSent, r.RetransSent)},
			Cause:    "one direction of the path is worse. A single-ended capture will under- or over-report the problem",
			Actions:  []string{"test the bad direction specifically (tcpdiag --probe --direction)", "inspect the AP/uplink and any shaper on that direction"},
		})
	}

	// --- 8. Kernel vs custom stack divergence --------------------------------
	if len(in.KernelLocal) > 0 {
		if kr, ok := in.KernelLocal["win_tcp_retrans_segs/s"]; ok && kr > 0 && l.RetransSent == 0 && in.StackMode == "both" {
			out = append(out, Finding{
				ID: "OFFLOAD", Title: "Kernel retransmits although our own stack on the same path does not", Severity: Medium, Confidence: "medium",
				Evidence: []string{fmt.Sprintf("kernel delta retrans/s = %d while raw stack retransmits = %d", kr, l.RetransSent)},
				Cause:    "driver/stack behaviour or NIC offload rather than the path. Offload and capture placement are the most common source of bogus Dup-ACK / Spurious-Retransmission annotations",
				Actions:  []string{"disable LRO/GRO/RSC and TCP offload (task offload) and re-run", "capture on both ends rather than one", "compare netsh int tcp show global / sysctl tcp_* settings"},
			})
		}
	}

	// --- 8b. NIC receive offload evidence -----------------------------------
	for _, side := range []struct {
		tag  string
		snap *wire.Snapshot
	}{{"local", l}, {"remote", r}} {
		k := side.snap.Kernel
		if k == nil {
			continue
		}
		big, ok := k["offload_coalesced_segments"]
		if !ok || big == 0 {
			continue
		}
		out = append(out, Finding{
			ID:         "OFFLOAD_" + strings.ToUpper(side.tag),
			Title:      fmt.Sprintf("%d coalesced segments seen on the %s side (largest %d bytes)", big, side.tag, k["offload_max_segment_bytes"]),
			Severity:   High,
			Confidence: "high",
			Evidence: []string{
				fmt.Sprintf("%d captured packets were far larger than one MTU, which a NIC only produces after receive segment coalescing", big),
				fmt.Sprintf("largest captured segment was %d bytes", k["offload_max_segment_bytes"]),
			},
			Cause: "receive offload (RSC/LRO/GRO) merges arriving segments before they are captured. An analyser then sees byte ranges it believes were already delivered and reports Dup ACK, Fast Retransmission and Spurious Retransmission that never happened on the wire",
			Actions: []string{
				"disable receive offload and re-run: netsh interface tcp set global autotuninglevel=disabled, and turn off LRO/GRO/RSC on the adapter",
				"compare --stack=kernel against --stack=raw: the raw engine sees the same coalesced bytes, so a clean raw result points at analysis artefacts",
				"re-run with --pcap wire.pcap on both ends; the WIRE OBSERVATION section of each report is the comparison",
			},
			Filters: []string{"tcp.analysis.spurious_retransmission", "tcp.len > 1460"},
		})
	}

	// --- 9. RST / middlebox --------------------------------------------------
	if l.RstRecv+r.RstRecv > 0 {
		out = append(out, Finding{
			ID: "RST", Title: fmt.Sprintf("%d RST segment(s) received", l.RstRecv+r.RstRecv), Severity: Medium, Confidence: "medium",
			Evidence: []string{fmt.Sprintf("local %d, remote %d", l.RstRecv, r.RstRecv)},
			Cause:    "unexpected resets usually mean a firewall/NAT/stateful device is killing the flow, or a stale connection was addressed",
			Actions:  []string{"check idle-timeout settings on any NAT/firewall in the path", "enable keepalives / sustained low-rate traffic (--rate 0.1) to test the idle-timeout hypothesis"},
			Filters:  []string{"tcp.flags.reset == 1"},
		})
	}

	// The tool does the comparisons itself rather than instructing the user to
	// perform them by hand.
	out = append(out, StackComparison(in.Kernel, in.Raw)...)
	out = append(out, CaptureFinding(in.Capture, in.StackMode)...)

	for _, n := range in.ProbeNotes {
		out = append(out, Finding{ID: "PROBE", Title: n, Severity: Info, Confidence: "high"})
	}
	if in.Impair != "" && in.Impair != "none" {
		out = append(out, Finding{
			ID: "IMPAIR", Title: "Artificial impairment is enabled - results are synthetic", Severity: Info, Confidence: "high",
			Evidence: []string{in.Impair},
			Cause:    "defects are being injected locally by tcpdiag to reproduce symptoms",
		})
	}

	// Sanity: peer views should roughly agree with ours.
	if l.DupAcksRecv > 0 && r.DupAcksSent > 0 {
		ratio := ratio(f64(l.DupAcksRecv), f64(r.DupAcksSent))
		if ratio < 0.5 || ratio > 2 {
			out = append(out, Finding{
				ID: "CROSSCHECK", Title: "The two sides disagree about duplicate ACK counts", Severity: Low, Confidence: "medium",
				Evidence: []string{fmt.Sprintf("we received %d dup-ACKs; peer says it sent %d", l.DupAcksRecv, r.DupAcksSent)},
				Cause:    "one direction of the path is dropping ACKs, or one side's counters are counting differently (offload)",
			})
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return rank(out[i].Severity) < rank(out[j].Severity) })
	return out
}

func rank(s Severity) int {
	switch s {
	case Critical:
		return 0
	case High:
		return 1
	case Medium:
		return 2
	case Low:
		return 3
	}
	return 4
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func percentile(h *wire.RTTHistogram, p float64) float64 {
	if h == nil || h.Count == 0 {
		return 0
	}
	target := uint64(math.Ceil(p * float64(h.Count)))
	var run uint64
	for i, c := range h.Buckets {
		run += c
		if run >= target {
			if i == 0 {
				return 0.5
			}
			return math.Pow(2, float64(i-1))
		}
	}
	return h.MaxMs
}
