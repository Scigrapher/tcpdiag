package report

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"tcpdiag/internal/wire"
)

func wideInput() Input {
	l, r := base(), base()
	// Deliberately extreme magnitudes: a correct renderer must keep the columns
	// aligned regardless of how wide the values become.
	l.SegsSent, r.SegsSent = 1, 12345678
	l.BytesSent, r.BytesSent = 7, 9876543210
	l.RetransSent, r.RetransSent = 0, 99999
	l.RTTEwms, r.RTTEwms = 0.5, 1234.5
	l.PeerWindow, r.PeerWindow = 512, 4194304
	l.Hist = &wire.RTTHistogram{
		Buckets: []uint64{0, 0, 5, 120, 3000, 0, 1},
		Count:   3126, MinMs: 4, MaxMs: 1500,
	}
	l.LocalEP, l.RemoteEP = "192.168.1.40", "192.168.1.41"
	r.LocalEP, r.RemoteEP = "192.168.1.41", "192.168.1.40"
	return Input{Local: l, Peer: r, Duration: 9 * time.Second, StackMode: "both"}
}

// The table renderer must right-align numeric columns so that every row ends
// at the same screen column, no matter how different the values are.
// tableRows returns the data rows of the first table whose header line
// contains all of the given words, plus the column at which the table ends.
func tableRows(t *testing.T, lines []string, headerWords ...string) (rows []string, end int) {
	t.Helper()
	for i, ln := range lines {
		ok := true
		for _, w := range headerWords {
			if !strings.Contains(ln, w) {
				ok = false
				break
			}
		}
		if !ok || i+2 >= len(lines) {
			continue
		}
		rule := strings.TrimLeft(lines[i+1], " ")
		if !strings.HasPrefix(strings.TrimSpace(rule), "--") {
			continue
		}
		end = len(strings.TrimRight(lines[i+1], " "))
		for j := i + 2; j < len(lines); j++ {
			ln := lines[j]
			if strings.TrimRight(ln, " ") == "" || !strings.HasPrefix(ln, "  ") {
				return rows, end
			}
			rows = append(rows, ln)
		}
		return rows, end
	}
	t.Fatalf("no table with header %v found", headerWords)
	return nil, 0
}

// The table renderer must right-align numeric columns so that every row ends
// at the same screen column, no matter how different the values are.
func TestTextReportColumnsAlign(t *testing.T) {
	out := Text(wideInput(), nil)
	lines := strings.Split(out, "\n")

	rows, end := tableRows(t, lines, "metric", "local", "remote")
	if len(rows) < 15 {
		t.Fatalf("expected the side-by-side table, got %d rows", len(rows))
	}
	for _, ln := range rows {
		if got := len(strings.TrimRight(ln, " ")); got != end {
			t.Fatalf("row ends at %d but the rule ends at %d:\n  %q", got, end, ln)
		}
	}
	// Numeric columns are right-aligned, so the widest and narrowest values
	// must share a right edge.
	var lastCols []int
	for _, ln := range rows {
		if strings.Contains(ln, "stack") {
			continue
		}
		lastCols = append(lastCols, len(strings.TrimRight(ln, " ")))
	}
	for _, c := range lastCols {
		if c != end {
			t.Fatalf("numeric right edge %d != %d", c, end)
		}
	}

	hrows, hend := tableRows(t, lines, "range", "count")
	if len(hrows) == 0 {
		t.Fatal("expected an RTT histogram table")
	}
	for _, ln := range hrows {
		// Bar rows may legitimately be shorter when the bar is empty.
		if strings.Contains(strings.TrimRight(ln, " "), "#") {
			if len(strings.TrimRight(ln, " ")) > hend {
				t.Fatalf("histogram bar overflowed the table: %q", ln)
			}
		}
	}
}
func TestTextReportWrapsAndHasNoMarkdown(t *testing.T) {
	in := wideInput()
	out := Text(in, Diagnose(in))
	if strings.Contains(out, "|") {
		t.Fatal("terminal report must not contain markdown table pipes")
	}
	if strings.Contains(out, "---:") {
		t.Fatal("terminal report must not contain markdown alignment markers")
	}
	for i, ln := range strings.Split(out, "\n") {
		if len(ln) > 110 {
			t.Fatalf("line %d is %d chars, not wrapped: %q", i+1, len(ln), ln)
		}
	}
	for _, want := range []string{"VERDICT", "SIDE BY SIDE", "FINDINGS", "WIRESHARK FILTERS", "192.168.1.41"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing section or value %q", want)
		}
	}
}

func TestTextTablePadsToWidestCell(t *testing.T) {
	tbl := NewTable([]string{"name", "value"}, []bool{false, true})
	tbl.Add("a", "1")
	tbl.Add("longername", "1000000")
	got := strings.TrimRight(tbl.Render(""), "\n")
	lines := strings.Split(got, "\n")
	if len(lines) != 4 {
		t.Fatalf("want header, rule, 2 rows; got %d lines: %q", len(lines), got)
	}
	wantEnd := len(lines[1])
	for _, ln := range lines {
		if len(strings.TrimRight(ln, " ")) != wantEnd {
			t.Fatalf("row %q does not end at column %d", ln, wantEnd)
		}
	}
	// The right-aligned column must place the short number at the same offset.
	i1 := strings.Index(lines[2], "1")
	last1 := strings.LastIndex(lines[2], "1")
	if last1 != len(lines[2])-1 {
		t.Fatalf("value not right-aligned: %q (i=%d last=%d)", lines[2], i1, last1)
	}
	if !strings.HasSuffix(lines[3], "1000000") {
		t.Fatalf("long value not at column end: %q", lines[3])
	}
}

func TestTextReportDisclosesImpairment(t *testing.T) {
	in := wideInput()
	in.Impair = "loss=2,delay=12ms"
	out := Text(in, nil)
	if !strings.Contains(out, "Impairment") || !strings.Contains(out, "synthetic") {
		t.Fatal("impairment must be disclosed in the terminal report")
	}
}

func TestTextReportKernelCountersTable(t *testing.T) {
	in := wideInput()
	in.KernelLocal = map[string]uint64{"win_tcp_retrans_segs": 42, "win_tcp_retrans_segs/s": 7}
	in.KernelPeer = map[string]uint64{"win_tcp_retrans_segs": 900000, "win_tcp_retrans_segs/s": 123456}
	out := Text(in, nil)
	if !strings.Contains(out, "KERNEL COUNTERS") {
		t.Fatal("kernel counter section missing")
	}
	if !strings.Contains(out, strconv.FormatUint(900000, 10)) {
		t.Fatal("remote kernel counter missing")
	}
}
