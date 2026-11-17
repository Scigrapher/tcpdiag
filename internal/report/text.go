package report

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// This file renders the report for a terminal. The markdown renderer is for
// files; printing it to a console leaves the reader counting pipe characters
// and nothing lines up. Here every table is measured first and then padded to
// the widest cell in each column, so the columns actually align on screen.

const (
	textMargin = "  "
	textWrapAt = 96
	textMinCol = 4
	numSep     = "  "
)

func dwidth(s string) int { return utf8.RuneCountInString(s) }

func padRight(s string, w int) string {
	if d := dwidth(s); d >= w {
		return s
	} else {
		return s + strings.Repeat(" ", w-d)
	}
}

func padLeft(s string, w int) string {
	if d := dwidth(s); d >= w {
		return s
	} else {
		return strings.Repeat(" ", w-d) + s
	}
}

// textTable is a column-aligned block of text.
// Table is a column-aligned text block for terminal output. Columns are measured
// across every cell first, then padded, so numeric columns line up on screen
// regardless of how large the values grow.
type Table struct {
	headers  []string
	right    []bool
	rows     [][]string
	noHeader bool
}

func NewTable(headers []string, right []bool) *Table {
	t := &Table{headers: append([]string{}, headers...)}
	t.right = append([]bool{}, right...)
	for len(t.right) < len(headers) {
		t.right = append(t.right, false)
	}
	return t
}

// Add appends one row.
func (t *Table) Add(vals ...string) {
	row := make([]string, len(t.headers))
	copy(row, vals)
	for i := range row {
		if i >= len(vals) {
			row[i] = ""
		}
	}
	t.rows = append(t.rows, row)
}

// OmitHeader drops the title row and its rule, for label/value blocks.
func (t *Table) OmitHeader() { t.noHeader = true }

// Render returns the aligned block, prefixed on each line by indent.
func (t *Table) Render(indent string) string {
	n := len(t.headers)
	if n == 0 {
		return ""
	}
	w := make([]int, n)
	for i, h := range t.headers {
		w[i] = dwidth(h)
		if w[i] < textMinCol {
			w[i] = textMinCol
		}
	}
	for _, r := range t.rows {
		for i := 0; i < n && i < len(r); i++ {
			if d := dwidth(r[i]); d > w[i] {
				w[i] = d
			}
		}
	}
	cell := func(s string, i int) string {
		if t.right[i] {
			return padLeft(s, w[i])
		}
		return padRight(s, w[i])
	}
	var b strings.Builder
	hdr := make([]string, n)
	sep := make([]string, n)
	for i := 0; i < n; i++ {
		hdr[i] = cell(t.headers[i], i)
		sep[i] = strings.Repeat("-", w[i])
	}
	if !t.noHeader {
		b.WriteString(indent + strings.TrimRight(strings.Join(hdr, numSep), " ") + "\n")
		b.WriteString(indent + strings.Join(sep, numSep) + "\n")
	}
	for _, r := range t.rows {
		cells := make([]string, n)
		for i := 0; i < n; i++ {
			cells[i] = cell(r[i], i)
		}
		b.WriteString(indent + strings.TrimRight(strings.Join(cells, numSep), " ") + "\n")
	}
	return b.String()
}

// wrap folds a long paragraph to the given width with a hanging indent.
func wrap(s, indent string, width int) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return indent + "\n"
	}
	var b strings.Builder
	line := indent
	for _, wd := range words {
		if dwidth(line)+1+dwidth(wd) > width && line != indent {
			b.WriteString(strings.TrimRight(line, " ") + "\n")
			line = indent
		}
		line += wd + " "
	}
	b.WriteString(strings.TrimRight(line, " ") + "\n")
	return b.String()
}

// counterPair returns the OS counters to display, falling back to the maps
// embedded in the snapshots when the caller did not supply separate ones.
func counterPair(in Input) (local, remote map[string]uint64) {
	local, remote = in.KernelLocal, in.KernelPeer
	if len(local) == 0 && in.Local != nil {
		local = in.Local.Kernel
	}
	if len(remote) == 0 && in.Peer != nil {
		remote = in.Peer.Kernel
	}
	return local, remote
}

func heading(b *strings.Builder, title string) {
	b.WriteString("\n" + title + "\n")
	b.WriteString(strings.Repeat("-", dwidth(title)) + "\n")
}

func u64(v uint64) string { return strconv.FormatUint(v, 10) }

func flt(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) }

// Text renders the whole report for a terminal.
func Text(in Input, fs []Finding) string {
	var b strings.Builder
	l, r := in.Local, in.Peer

	b.WriteString("tcpdiag report\n")
	b.WriteString(strings.Repeat("=", 14) + "\n")
	meta := NewTable([]string{"", ""}, []bool{false, false})
	meta.OmitHeader()
	meta.Add("Generated", time.Now().Format(time.RFC3339))
	meta.Add("Sampled over", in.Duration.Round(time.Millisecond).String())
	meta.Add("Stack mode", in.StackMode)
	if in.AppRTTMs > 0 {
		meta.Add("Application RTT", fmt.Sprintf("%.2f ms", in.AppRTTMs))
	}
	impaired := in.Impair != "" && in.Impair != "none"
	if impaired {
		meta.Add("Impairment", in.Impair)
	}
	b.WriteString(meta.Render(textMargin))
	if impaired {
		// A single long token (the impairment spec) must not drag the whole
		// block past the wrap width, so the caveat gets its own folded line.
		b.WriteString(wrap("These defects were injected locally by tcpdiag; the findings below describe synthetic conditions, not your network.",
			textMargin, textWrapAt))
	}

	heading(&b, "VERDICT")
	b.WriteString(wrap(Verdict(fs), textMargin, textWrapAt))

	if l != nil && r != nil {
		heading(&b, "SIDE BY SIDE")
		t := NewTable([]string{"metric", "local", "remote"}, []bool{false, true, true})
		row := func(name string, a, c string) { t.Add(name, a, c) }
		row("stack", l.Stack, r.Stack)
		// Endpoints are deliberately not a table row: a 34-character address
		// pair would force the two numeric columns apart and destroy the
		// alignment of every number below it.
		b.WriteString(textMargin + "local  " + l.LocalEP + " -> " + l.RemoteEP + "\n")
		b.WriteString(textMargin + "remote " + r.LocalEP + " -> " + r.RemoteEP + "\n")
		row("Mbit/s sent", flt(l.MbpsSent), flt(r.MbpsSent))
		row("Mbit/s received", flt(l.MbpsRecv), flt(r.MbpsRecv))
		row("segments sent", u64(l.SegsSent), u64(r.SegsSent))
		row("retransmitted", u64(l.RetransSent), u64(r.RetransSent))
		row("  fast retransmit", u64(l.FastRetrans), u64(r.FastRetrans))
		row("  RTO retransmit", u64(l.RtoRetrans), u64(r.RtoRetrans))
		row("  spurious", u64(l.SpuriousRetrans), u64(r.SpuriousRetrans))
		row("dup-ACKs sent", u64(l.DupAcksSent), u64(r.DupAcksSent))
		row("dup-ACKs received", u64(l.DupAcksRecv), u64(r.DupAcksRecv))
		row("missing blocks", u64(l.BlocksMissing), u64(r.BlocksMissing))
		row("transport hole bytes", u64(l.HoleBytes), u64(r.HoleBytes))
		row("out-of-order segs", u64(l.OooSegs), u64(r.OooSegs))
		row("late (reordered) blocks", u64(l.BlocksLate), u64(r.BlocksLate))
		row("chain mismatches", u64(l.ChainMismatch), u64(r.ChainMismatch))
		row("zero window advertised", u64(l.ZeroWindowAdv), u64(r.ZeroWindowAdv))
		row("zero window received", u64(l.ZeroWindowRecv), u64(r.ZeroWindowRecv))
		row("SRTT ms", flt(l.RTTEwms), flt(r.RTTEwms))
		row("RTTVAR ms", flt(l.RTTVarms), flt(r.RTTVarms))
		row("RTO ms", flt(l.RTOms), flt(r.RTOms))
		row("cwnd bytes", u64(uint64(l.Cwnd)), u64(uint64(r.Cwnd)))
		row("peer window bytes", u64(uint64(l.PeerWindow)), u64(uint64(r.PeerWindow)))
		row("RSTs received", u64(l.RstRecv), u64(r.RstRecv))
		b.WriteString(t.Render(textMargin))

		if l.Hist != nil && l.Hist.Count > 0 {
			b.WriteString("\n" + textMargin + "local RTT distribution (ms)\n")
			h := NewTable([]string{"range", "count", ""}, []bool{true, true, false})
			peak := maxBucket(l.Hist.Buckets)
			for i, c := range l.Hist.Buckets {
				if c == 0 {
					continue
				}
				lo, hi := 0.0, 1.0
				if i > 0 {
					lo = math2(i)
					hi = lo * 2
				}
				h.Add(fmt.Sprintf("%.2f-%.2f", lo, hi), u64(c), bar(float64(c), float64(peak), 30))
			}
			b.WriteString(h.Render(textMargin + "  "))
		}
	}

	heading(&b, "FINDINGS")
	if len(fs) == 0 {
		b.WriteString(textMargin + "Nothing to report.\n")
	}
	numWidth := len(strconv.Itoa(len(fs)))
	for i, f := range fs {
		num := padRight(fmt.Sprintf("%d.", i+1), numWidth)
		b.WriteString("\n" + textMargin + num + " [" + strings.ToUpper(string(f.Severity)) + "] " + f.Title + "\n")
		meta := ""
		if f.Confidence != "" {
			meta += "confidence " + f.Confidence
		}
		if f.Direction != "" {
			if meta != "" {
				meta += "   "
			}
			meta += "direction " + f.Direction
		}
		if meta != "" {
			b.WriteString(wrap(meta, textMargin+strings.Repeat(" ", numWidth+1), textWrapAt))
		}
		if len(f.Evidence) > 0 {
			b.WriteString(textMargin + strings.Repeat(" ", numWidth+1) + "evidence:\n")
			for _, ev := range f.Evidence {
				b.WriteString(wrap("- "+ev, textMargin+strings.Repeat(" ", numWidth+3), textWrapAt))
			}
		}
		if f.Cause != "" {
			b.WriteString(textMargin + strings.Repeat(" ", numWidth+1) + "likely cause:\n")
			b.WriteString(wrap(f.Cause, textMargin+strings.Repeat(" ", numWidth+3), textWrapAt))
		}
		if len(f.Actions) > 0 {
			b.WriteString(textMargin + strings.Repeat(" ", numWidth+1) + "what to do:\n")
			for _, a := range f.Actions {
				b.WriteString(wrap("[ ] "+a, textMargin+strings.Repeat(" ", numWidth+3), textWrapAt))
			}
		}
		if len(f.Filters) > 0 {
			b.WriteString(wrap("wireshark: "+strings.Join(f.Filters, "   "),
				textMargin+strings.Repeat(" ", numWidth+1), textWrapAt))
		}
	}

	kl, kr := counterPair(in)
	if len(kl) > 0 || len(kr) > 0 {
		heading(&b, "KERNEL COUNTERS  (delta over the window)")
		t := NewTable([]string{"counter", "local", "remote"}, []bool{false, true, true})
		keys := map[string]bool{}
		for k := range kl {
			keys[k] = true
		}
		for k := range kr {
			keys[k] = true
		}
		var ks []string
		for k := range keys {
			if strings.HasSuffix(k, "/s") || strings.Contains(k, "retrans") ||
				strings.Contains(k, "spurious") || strings.Contains(k, "offload") || strings.Contains(k, "timeout") {
				ks = append(ks, k)
			}
		}
		sortStrings(ks)
		for _, k := range ks {
			t.Add(k, u64(kl[k]), u64(kr[k]))
		}
		b.WriteString(t.Render(textMargin))
	}

	if in.Capture != nil {
		heading(&b, "WIRE OBSERVATION  (what tcpdiag itself captured)")
		for _, line := range CaptureLines(in.Capture) {
			b.WriteString(wrap(line, textMargin, textWrapAt))
		}
		if in.Capture.PCAP != "" {
			b.WriteString(wrap("pcap written to: "+in.Capture.PCAP+" (open in Wireshark if you want, but the analysis above is tcpdiag's own)", textMargin, textWrapAt))
		}
	}

	if in.Kernel != nil && in.Raw != nil && in.Kernel.Local != nil && in.Raw.Local != nil {
		heading(&b, "STACK COMPARISON  (kernel vs custom stack, same path)")
		k, r := in.Kernel.Local, in.Raw.Local
		t := NewTable([]string{"metric", "kernel", "custom"}, []bool{false, true, true})
		add3 := func(name string, a, c uint64) { t.Add(name, u64(a), u64(c)) }
		add3("segments sent", k.SegsSent, r.SegsSent)
		add3("retransmitted", k.RetransSent, r.RetransSent)
		add3("  fast retransmit", k.FastRetrans, r.FastRetrans)
		add3("  RTO retransmit", k.RtoRetrans, r.RtoRetrans)
		add3("  spurious", k.SpuriousRetrans, r.SpuriousRetrans)
		add3("dup-ACKs received", k.DupAcksRecv, r.DupAcksRecv)
		add3("out-of-order segs", k.OooSegs, r.OooSegs)
		add3("missing blocks", k.BlocksMissing, r.BlocksMissing)
		t.Add("retransmit rate", fmt.Sprintf("%.3f%%", lossPct(k)), fmt.Sprintf("%.3f%%", lossPct(r)))
		b.WriteString(t.Render(textMargin))
		b.WriteString(wrap("Two independent implementations measured the same path. If only the kernel retransmits, look inside the host (stack timers or NIC offload). If both do, the network is the cause.", textMargin, textWrapAt))
	}

	heading(&b, "WIRESHARK FILTERS WORTH RUNNING")
	for _, f := range []string{
		"tcp.analysis.duplicate_ack",
		"tcp.analysis.fast_retransmission",
		"tcp.analysis.spurious_retransmission",
		"tcp.analysis.out_of_order",
		"tcp.analysis.zero_window",
		"tcp.analysis.lost_segment",
		"tcp.flags.reset == 1",
	} {
		b.WriteString(textMargin + f + "\n")
	}
	b.WriteString("\n" + wrap("Offload (TSO/LRO/GRO) makes a single-sided capture misleading. tcpdiag already captures on both ends: run it with --pcap wire.pcap on each machine and compare the WIRE OBSERVATION sections, or run tcpdiag -stack=both to get the STACK COMPARISON above in a single report.", textMargin, textWrapAt))
	return b.String()
}
