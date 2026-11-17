package tcpraw

import (
	"math"
	"time"
)

// RTTEstimator implements RFC 6299 timers with configurable clamps. Diagnostic
// runs on a LAN want a much tighter floor than the RFC's 1s default, otherwise
// genuine loss and a merely slow path look identical for seconds at a time.
type RTTEstimator struct {
	SRTT    time.Duration
	RTTVar  time.Duration
	RTO     time.Duration
	MinRTO  time.Duration
	MaxRTO  time.Duration
	Initial time.Duration
	Have    bool
	Expiry  uint64
}

func NewRTTEstimator(minRTO, maxRTO, initial time.Duration) *RTTEstimator {
	if minRTO <= 0 {
		minRTO = 200 * time.Microsecond
	}
	if maxRTO <= 0 {
		maxRTO = 60 * time.Second
	}
	if initial <= 0 {
		initial = 1 * time.Second
	}
	return &RTTEstimator{MinRTO: minRTO, MaxRTO: maxRTO, RTO: initial, Initial: initial}
}

// Update folds in one RTT sample. Karn's rule means only clean, never-
// retransmitted samples reach this function.
func (r *RTTEstimator) Update(sample time.Duration) {
	if sample <= 0 {
		return
	}
	s := float64(sample)
	if !r.Have {
		r.SRTT = sample
		r.RTTVar = sample / 2
		r.Have = true
	} else {
		g, b := 0.125, 0.25
		diff := float64(r.SRTT) - s
		if diff < 0 {
			diff = -diff
		}
		r.RTTVar = time.Duration((1-b)*float64(r.RTTVar) + b*diff)
		r.SRTT = time.Duration((1-g)*float64(r.SRTT) + g*s)
	}
	rto := r.SRTT + time.Duration(math.Round(4*float64(r.RTTVar)))
	if rto < r.MinRTO {
		rto = r.MinRTO
	}
	if rto > r.MaxRTO {
		rto = r.MaxRTO
	}
	r.RTO = rto
}

// Backoff doubles the RTO after a timeout.
func (r *RTTEstimator) Backoff() {
	r.RTO *= 2
	if r.RTO > r.MaxRTO {
		r.RTO = r.MaxRTO
	}
	r.Expiry++
}

// Reset returns to the initial (post-fragility) RTO.
func (r *RTTEstimator) Reset() {
	r.RTO = r.Initial
	r.Have = false
	r.SRTT, r.RTTVar = 0, 0
}

// TooEarly reports whether a retransmission fired before the path RTT estimate
// could plausibly have elapsed. Retransmissions that fire here are the classic
// source of Wireshark's "TCP Spurious Retransmission" annotation.
func (r *RTTEstimator) TooEarly(sinceLastAck time.Duration) bool {
	if !r.Have {
		return false
	}
	return sinceLastAck < r.SRTT+2*r.RTTVar
}
