package kernelstat

import (
	"strings"
	"sync"
	"time"
)

// Reader pulls the operating system's own TCP counters so the tool's private
// measurements can be cross-checked against what the kernel believes it did.
// A disagreement between the two is itself a finding: it usually points at NIC
// offload, a driver, or a middlebox rather than the application.
type Reader interface {
	Name() string
	Read() map[string]uint64
}

// Differ turns a monotonic counter source into per-interval rates plus running
// totals, which is what actually answers "how many segments did the kernel
// retransmit just now".
type Differ struct {
	mu     sync.Mutex
	r      Reader
	last   map[string]uint64
	lastAt time.Time
	name   string
}

// NewDiffer wraps a Reader.
func NewDiffer(r Reader) *Differ {
	return &Differ{r: r, last: map[string]uint64{}, name: r.Name(), lastAt: time.Now()}
}

// Name identifies the underlying source.
func (d *Differ) Name() string { return d.name }

// Delta returns cumulative counters plus "<name>/s" per-second rates measured
// since the previous call.
func (d *Differ) Delta() map[string]uint64 {
	cur := d.r.Read()
	d.mu.Lock()
	defer d.mu.Unlock()
	dt := time.Since(d.lastAt).Seconds()
	if dt < 0.001 {
		dt = 0.001
	}
	out := make(map[string]uint64, len(cur)*2)
	for k, v := range cur {
		out[k] = v
		if isGauge(k) {
			// A rate is meaningless for configuration values and instantaneous
			// gauges (RTO bounds, current connection count), so only the level
			// is published.
			continue
		}
		if prev, ok := d.last[k]; ok && v >= prev {
			out[k+"/s"] = uint64(float64(v-prev) / dt)
		}
	}
	d.last = cur
	d.lastAt = time.Now()
	return out
}

// isGauge reports whether a counter name denotes a level or a configured limit
// rather than a monotonically increasing total.
func isGauge(k string) bool {
	lower := strings.ToLower(k)
	for _, sub := range []string{"_min", "_max", "curr", "_state", "algorithm", "maxconn", "max_conn"} {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}
