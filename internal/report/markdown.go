package report

import (
	"fmt"
	"strings"
	"time"
)

// Verdict is the one-paragraph answer to "what is actually wrong".
func Verdict(fs []Finding) string {
	if len(fs) == 0 {
		return "No anomalies detected in the sampled window: no missing blocks, no reordering and no retransmissions were observed on either side."
	}
	var b strings.Builder
	counts := map[Severity]int{}
	for _, f := range fs {
		counts[f.Severity]++
	}
	b.WriteString(fmt.Sprintf("%d finding(s): %d critical, %d high, %d medium, %d low.",
		len(fs), counts[Critical], counts[High], counts[Medium], counts[Low]))
	for _, f := range fs {
		if f.Severity == Critical || f.Severity == High {
			b.WriteString(" Most significant: " + f.Title + ". ")
			if f.Cause != "" {
				b.WriteString(f.Cause + ".")
			}
			break
		}
	}
	return b.String()
}

func bar(v float64, max float64, width int) string {
	if max <= 0 {
		return ""
	}
	n := int(v / max * float64(width))
	if n < 0 {
		n = 0
	}
	if n > width {
		n = width
	}
	return strings.Repeat("#", n)
}

// Markdown renders a human-readable diagnosis.
func Markdown(in Input, fs []Finding) string {
	var b strings.Builder
	l, r := in.Local, in.Peer
	b.WriteString("# tcpdiag report\n\n")
	b.WriteString(fmt.Sprintf("Generated %s, sampled over %s, stack mode `%s`.\n\n",
		time.Now().Format(time.RFC3339), in.Duration.Round(time.Millisecond), in.StackMode))
	b.WriteString("```\n" + Verdict(fs) + "\n```\n\n")

	if l != nil && r != nil {
		b.WriteString("## Side-by-side\n\n")
		b.WriteString("| metric | local | remote |\n|---|---:|---:|\n")
		row := func(name string, a, c interface{}) {
			b.WriteString(fmt.Sprintf("| %s | %v | %v |\n", name, a, c))
		}
		row("stack", l.Stack, r.Stack)
		row("endpoints", l.LocalEP+" -> "+l.RemoteEP, r.LocalEP+" -> "+r.RemoteEP)
		row("Mbit/s sent", fmt.Sprintf("%.2f", l.MbpsSent), fmt.Sprintf("%.2f", r.MbpsSent))
		row("Mbit/s received", fmt.Sprintf("%.2f", l.MbpsRecv), fmt.Sprintf("%.2f", r.MbpsRecv))
		row("segments sent", l.SegsSent, r.SegsSent)
		row("retransmitted", l.RetransSent, r.RetransSent)
		row("  fast retransmit", l.FastRetrans, r.FastRetrans)
		row("  RTO retransmit", l.RtoRetrans, r.RtoRetrans)
		row("  spurious", l.SpuriousRetrans, r.SpuriousRetrans)
		row("dup-ACKs sent", l.DupAcksSent, r.DupAcksSent)
		row("dup-ACKs received", l.DupAcksRecv, r.DupAcksRecv)
		row("missing blocks", l.BlocksMissing, r.BlocksMissing)
		row("transport hole bytes", l.HoleBytes, r.HoleBytes)
		row("out-of-order segs", l.OooSegs, r.OooSegs)
		row("late (reordered) blocks", l.BlocksLate, r.BlocksLate)
		row("chain mismatches", l.ChainMismatch, r.ChainMismatch)
		row("zero window adv", l.ZeroWindowAdv, r.ZeroWindowAdv)
		row("zero window recv", l.ZeroWindowRecv, r.ZeroWindowRecv)
		row("SRTT ms", fmt.Sprintf("%.2f", l.RTTEwms), fmt.Sprintf("%.2f", r.RTTEwms))
		row("RTTVAR ms", fmt.Sprintf("%.2f", l.RTTVarms), fmt.Sprintf("%.2f", r.RTTVarms))
		row("RTO ms", fmt.Sprintf("%.0f", l.RTOms), fmt.Sprintf("%.0f", r.RTOms))
		row("cwnd bytes", l.Cwnd, r.Cwnd)
		row("peer window bytes", l.PeerWindow, r.PeerWindow)
		row("RSTs received", l.RstRecv, r.RstRecv)
		b.WriteString("\n")
		if l.Hist != nil && l.Hist.Count > 0 {
			b.WriteString("### Local RTT distribution (ms)\n\n```\n")
			for i, c := range l.Hist.Buckets {
				if c == 0 {
					continue
				}
				lo, hi := 0.0, 1.0
				if i > 0 {
					lo = math2(i)
					hi = lo * 2
				}
				b.WriteString(fmt.Sprintf("%8.2f-%-8.2f %8d %s\n", lo, hi, c, bar(float64(c), float64(maxBucket(l.Hist.Buckets)), 40)))
			}
			b.WriteString("```\n\n")
		}
	}

	b.WriteString("## Findings\n\n")
	if len(fs) == 0 {
		b.WriteString("Nothing to report.\n\n")
	}
	for i, f := range fs {
		b.WriteString(fmt.Sprintf("### %d. [%s] %s\n\n", i+1, strings.ToUpper(string(f.Severity)), f.Title))
		if f.Confidence != "" {
			b.WriteString(fmt.Sprintf("*Confidence:* %s", f.Confidence))
			if f.Direction != "" {
				b.WriteString(fmt.Sprintf(" *Direction:* %s", f.Direction))
			}
			b.WriteString("\n\n")
		}
		if len(f.Evidence) > 0 {
			b.WriteString("**Evidence**\n\n")
			for _, e := range f.Evidence {
				b.WriteString("- " + e + "\n")
			}
			b.WriteString("\n")
		}
		if f.Cause != "" {
			b.WriteString("**Likely cause:** " + f.Cause + "\n\n")
		}
		if len(f.Actions) > 0 {
			b.WriteString("**What to do**\n\n")
			for _, a := range f.Actions {
				b.WriteString("- [ ] " + a + "\n")
			}
			b.WriteString("\n")
		}
		if len(f.Filters) > 0 {
			b.WriteString("**Wireshark:** ")
			for _, fl := range f.Filters {
				b.WriteString("`" + fl + "`  ")
			}
			b.WriteString("\n\n")
		}
	}

	kl, kr := counterPair(in)
	if len(kl) > 0 || len(kr) > 0 {
		b.WriteString("## Kernel counters (delta over the window)\n\n")
		b.WriteString("| counter | local | remote |\n|---|---:|---:|\n")
		keys := map[string]bool{}
		for k := range kl {
			keys[k] = true
		}
		for k := range kr {
			keys[k] = true
		}
		var ks []string
		for k := range keys {
			if strings.HasSuffix(k, "/s") || strings.Contains(k, "retrans") || strings.Contains(k, "spurious") || strings.Contains(k, "offload") || strings.Contains(k, "timeout") {
				ks = append(ks, k)
			}
		}
		sortStrings(ks)
		for _, k := range ks {
			b.WriteString(fmt.Sprintf("| %s | %d | %d |\n", k, kl[k], kr[k]))
		}
		b.WriteString("\n")
	}

	if in.Capture != nil {
		b.WriteString("## Wire observation (what tcpdiag itself captured)\n\n")
		for _, line := range CaptureLines(in.Capture) {
			b.WriteString("- " + line + "\n")
		}
		if in.Capture.PCAP != "" {
			b.WriteString(fmt.Sprintf("- pcap written to `%s`\n", in.Capture.PCAP))
		}
		b.WriteString("\n")
	}

	if in.Kernel != nil && in.Raw != nil && in.Kernel.Local != nil && in.Raw.Local != nil {
		k, r := in.Kernel.Local, in.Raw.Local
		b.WriteString("## Stack comparison (kernel vs custom, same path)\n\n")
		b.WriteString("| metric | kernel | custom |\n|---|---:|---:|\n")
		pair := func(name string, a, c uint64) {
			b.WriteString(fmt.Sprintf("| %s | %d | %d |\n", name, a, c))
		}
		pair("segments sent", k.SegsSent, r.SegsSent)
		pair("retransmitted", k.RetransSent, r.RetransSent)
		pair("  fast retransmit", k.FastRetrans, r.FastRetrans)
		pair("  RTO retransmit", k.RtoRetrans, r.RtoRetrans)
		pair("  spurious", k.SpuriousRetrans, r.SpuriousRetrans)
		pair("dup-ACKs received", k.DupAcksRecv, r.DupAcksRecv)
		pair("out-of-order segs", k.OooSegs, r.OooSegs)
		pair("missing blocks", k.BlocksMissing, r.BlocksMissing)
		b.WriteString(fmt.Sprintf("| retransmit rate | %.3f%% | %.3f%% |\n\n", lossPct(k), lossPct(r)))
		b.WriteString("Two independent implementations measured the same path. If only the kernel retransmits, " +
			"look inside the host (stack timers or NIC offload). If both do, the network is the cause.\n\n")
	}

	b.WriteString("## Wireshark filters worth running\n\n")
	b.WriteString("```\n")
	b.WriteString("tcp.analysis.duplicate_ack\n")
	b.WriteString("tcp.analysis.fast_retransmission\n")
	b.WriteString("tcp.analysis.spurious_retransmission\n")
	b.WriteString("tcp.analysis.out_of_order\n")
	b.WriteString("tcp.analysis.zero_window\n")
	b.WriteString("tcp.analysis.lost_segment\n")
	b.WriteString("tcp.flags.reset == 1\n")
	b.WriteString("```\n\n")
	b.WriteString("Offload (TSO/LRO/GRO) makes a single-sided capture misleading. tcpdiag already captures\n")
	b.WriteString("on both ends: run it with `--pcap wire.pcap` on each machine and compare the Wire\n")
	b.WriteString("observation sections, or run `tcpdiag -stack=both` to get the stack comparison in a\n")
	b.WriteString("single report.\n")
	return b.String()
}

func maxBucket(v []uint64) uint64 {
	var m uint64
	for _, x := range v {
		if x > m {
			m = x
		}
	}
	return m
}

func math2(i int) float64 {
	x := 1.0
	for j := 0; j < i-1; j++ {
		x *= 2
	}
	return x
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
