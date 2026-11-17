package stats

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"tcpdiag/internal/wire"
)

// Histogram is a lock-protected latency histogram with exponentially growing
// buckets. Bucket 0 covers [0,1) ms, bucket i covers [2^(i-1), 2^i) ms.
type Histogram struct {
	mu      sync.Mutex
	buckets []uint64
	count   uint64
	sum     float64
	min     float64
	max     float64
}

const histBuckets = 24

func NewHistogram() *Histogram {
	return &Histogram{buckets: make([]uint64, histBuckets), min: math.Inf(1)}
}

func (h *Histogram) bucket(v float64) int {
	if v < 1 {
		return 0
	}
	b := 1
	edge := 1.0
	for b < histBuckets-1 {
		edge *= 2
		if v < edge {
			return b
		}
		b++
	}
	return histBuckets - 1
}

func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	h.buckets[h.bucket(v)]++
	h.count++
	h.sum += v
	if v < h.min {
		h.min = v
	}
	if v > h.max {
		h.max = v
	}
	h.mu.Unlock()
}

func (h *Histogram) Snapshot() *wire.RTTHistogram {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]uint64, len(h.buckets))
	copy(out, h.buckets)
	min, max := h.min, h.max
	if h.count == 0 {
		min, max = 0, 0
	}
	return &wire.RTTHistogram{Buckets: out, Count: h.count, SumMs: h.sum, MinMs: min, MaxMs: max}
}

func (h *Histogram) Percentile(p float64) float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.count == 0 {
		return 0
	}
	target := uint64(math.Ceil(p * float64(h.count)))
	if target == 0 {
		target = 1
	}
	var run uint64
	for i, c := range h.buckets {
		run += c
		if run >= target {
			if i == 0 {
				return 0.5
			}
			return math.Pow(2, float64(i-1))
		}
	}
	return h.max
}

func (h *Histogram) Mean() float64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.count == 0 {
		return 0
	}
	return h.sum / float64(h.count)
}

// Meter computes a sliding-window throughput figure.
type Meter struct {
	mu     sync.Mutex
	bytes  uint64
	at     time.Time
	perSec float64
}

func NewMeter() *Meter { return &Meter{at: time.Now()} }

func (m *Meter) Add(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bytes += uint64(n)
}

// Rate recomputes and returns bits/sec over the elapsed window.
func (m *Meter) Rate() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	dt := now.Sub(m.at).Seconds()
	if dt < 0.05 {
		return m.perSec
	}
	d := float64(m.bytes)
	m.bytes = 0
	m.at = now
	m.perSec = d * 8 / dt
	return m.perSec
}

func (m *Meter) Total() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bytes
}

// EventRing keeps the most recent N events for embedding in reports.
type EventRing struct {
	mu    sync.Mutex
	items []wire.RetxEvent
	max   int
}

func NewEventRing(max int) *EventRing { return &EventRing{max: max} }

func (r *EventRing) Add(e wire.RetxEvent) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, e)
	if len(r.items) > r.max {
		r.items = r.items[len(r.items)-r.max:]
	}
}

func (r *EventRing) Snapshot() []wire.RetxEvent {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]wire.RetxEvent, len(r.items))
	copy(out, r.items)
	return out
}

// GapRing tracks open and recently closed block gaps.
type GapRing struct {
	mu      sync.Mutex
	open    map[uint64]*wire.Gap
	closed  []*wire.Gap
	max     int
	maxOpen int
	missing uint64
	maxGap  uint32
}

func NewGapRing(max, maxOpen int) *GapRing {
	return &GapRing{open: map[uint64]*wire.Gap{}, max: max, maxOpen: maxOpen}
}

// Open records a new hole [from,to).
func (g *GapRing) Open(from, to uint64) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if to > from {
		g.missing += to - from
		if uint32(to-from) > g.maxGap {
			g.maxGap = uint32(to - from)
		}
	}
	if len(g.open) >= g.maxOpen {
		return
	}
	g.open[from] = &wire.Gap{From: from, To: to, Detected: time.Now().UnixNano()}
}

// FillBelow closes every recorded hole that has become contiguous with low
// (i.e. fully repaired) and attributes the repair to src.
func (g *GapRing) FillBelow(low uint64, src string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for from, gp := range g.open {
		if gp.To <= low {
			gp.Filled = time.Now().UnixNano()
			gp.FillSrc = src
			g.closed = append(g.closed, gp)
			if len(g.closed) > g.max {
				g.closed = g.closed[len(g.closed)-g.max:]
			}
			delete(g.open, from)
		}
	}
}

// Fill closes a hole and records how it was repaired.
func (g *GapRing) Fill(from uint64, src string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	gp, ok := g.open[from]
	if !ok {
		return
	}
	gp.Filled = time.Now().UnixNano()
	gp.FillSrc = src
	g.closed = append(g.closed, gp)
	if len(g.closed) > g.max {
		g.closed = g.closed[len(g.closed)-g.max:]
	}
	delete(g.open, from)
}

func (g *GapRing) Snapshot() ([]wire.Gap, uint32) {
	if g == nil {
		return nil, 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]wire.Gap, 0, len(g.closed)+len(g.open))
	for _, gp := range g.closed {
		out = append(out, *gp)
	}
	for _, gp := range g.open {
		out = append(out, *gp)
	}
	return out, uint32(len(g.open))
}

func (g *GapRing) Missing() uint64 {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.missing
}

func (g *GapRing) MaxGap() uint32 {
	if g == nil {
		return 0
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.maxGap
}

// Counters is the shared counter set both engines write into.
type Counters struct {
	BlocksSent      atomic.Uint64
	BytesSent       atomic.Uint64
	BlocksRecv      atomic.Uint64
	BytesRecv       atomic.Uint64
	BlocksMissing   atomic.Uint64
	BlocksDup       atomic.Uint64
	BlocksLate      atomic.Uint64
	BlocksOOO       atomic.Uint64
	ChainMismatch   atomic.Uint64
	RetransSent     atomic.Uint64
	RtoRetrans      atomic.Uint64
	FastRetrans     atomic.Uint64
	SpuriousRetrans atomic.Uint64
	SpuriousSack    atomic.Uint64
	SpuriousRecv    atomic.Uint64
	RetransRecv     atomic.Uint64
	OooSegs         atomic.Uint64
	SegsSent        atomic.Uint64
	SegsRecv        atomic.Uint64
	AckSegsRecv     atomic.Uint64
	BufFullStalls   atomic.Uint64
	SynRetrans      atomic.Uint64
	OctetsRetrans   atomic.Uint64
	MaxRetrPerSeq   atomic.Uint64
	DupAcksSent     atomic.Uint64
	DupAcksRecv     atomic.Uint64
	DelayedAcks     atomic.Uint64
	AckLatencyNS    atomic.Uint64
	SackBlocks      atomic.Uint64
	ZeroWindowAdv   atomic.Uint64
	ZeroWindowRecv  atomic.Uint64
	WindowProbes    atomic.Uint64
	RtoExpires      atomic.Uint64
	RstRecv         atomic.Uint64
}
