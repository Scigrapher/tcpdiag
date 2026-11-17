package tcpraw

import (
	"sync"
	"time"

	"tcpdiag/internal/stats"
	"tcpdiag/internal/wire"
)

// Observer is a passive TCP analyser: it watches a conversation the *kernel*
// stack owns and reproduces the annotations Wireshark would draw - TCP Dup
// ACK, TCP Fast Retransmission, TCP Spurious Retransmission, Out-Of-Order,
// Zero Window - using only sequence-number evidence from the wire.
//
// This matters because those three annotations are exactly the symptoms being
// investigated, and they can be produced either by real loss or by a stack
// that retransmits too eagerly. Comparing what the kernel connection looks
// like on the wire with what our own stack does on the same path separates the
// two explanations.
type Observer struct {
	mu       sync.Mutex
	key      Key
	Counters *stats.Counters
	Hist     *stats.Histogram
	Ring     *stats.EventRing
	Gaps     *stats.GapRing
	name     string
	start    time.Time

	// outbound (local -> remote) tracking
	oMaxDataEnd   uint32
	oHaveSeq      bool
	oLastDataSeq  uint32
	oLastDataLen  uint32
	oLastDataAt   time.Time
	oPeerAck      uint32
	oHavePeerAck  bool
	oUnackedBytes uint32

	// inbound (remote -> local) tracking
	iMaxDataEnd  uint32
	iHaveSeq     bool
	iOurAck      uint32
	iHaveOurAck  bool
	iLastDataSeq uint32
	iLastDataAt  time.Time
	iDupRun      int
	oDupRun      int

	lastEmittedAck  uint32
	haveEmittedAck  bool
	lastObservedAck uint32
	haveObservedAck bool

	// rtt bookkeeping via timestamps
	lastTsSent  map[uint32]int64
	lastDataAck map[uint32]int64
}

// NewObserver starts watching one conversation.
func NewObserver(dmx *Demux, key Key, name string) *Observer {
	o := &Observer{
		key:         key,
		name:        name,
		Counters:    &stats.Counters{},
		Hist:        stats.NewHistogram(),
		Ring:        stats.NewEventRing(256),
		Gaps:        stats.NewGapRing(64, 64),
		start:       time.Now(),
		lastTsSent:  map[uint32]int64{},
		lastDataAck: map[uint32]int64{},
	}
	dmx.Register(key, o.observe)
	return o
}

func (o *Observer) outbound(s *Segment) bool { return s.SrcIP == o.key.A && s.SrcPort == o.key.APort }

func (o *Observer) observe(s *Segment) {
	o.mu.Lock()
	defer o.mu.Unlock()
	now := time.Unix(0, s.ReceivedAt)
	if !o.oHavePeerAck {
		o.oHavePeerAck = true
		o.oPeerAck = s.Ack
	}
	if o.outbound(s) {
		o.observeOutbound(s, now)
	} else {
		o.observeInbound(s, now)
	}
}

func (o *Observer) observeOutbound(s *Segment, now time.Time) {
	o.Counters.SegsSent.Add(1)
	if s.Flags&FlagACK != 0 {
		if s.Window == 0 {
			o.Counters.ZeroWindowAdv.Add(1)
		}
		// Duplicate ACK emitted by us: same ack number as last time while the
		// peer still has data above it that we have not acknowledged.
		if o.haveEmittedAck && s.Ack == o.lastEmittedAck && s.Ack != 0 &&
			o.iMaxDataEnd != 0 && seqLT(s.Ack, o.iMaxDataEnd) && len(s.Payload) == 0 {
			o.oDupRun++
			if o.oDupRun >= 1 {
				o.Counters.DupAcksSent.Add(1)
			}
		} else if !o.haveEmittedAck || s.Ack != o.lastEmittedAck {
			o.oDupRun = 0
		}
		o.haveEmittedAck = true
		o.lastEmittedAck = s.Ack
	}
	if len(s.Payload) == 0 {
		return
	}
	end := s.Seq + uint32(len(s.Payload))
	if o.oHaveSeq && seqLT(s.Seq, o.oMaxDataEnd) {
		// We are re-sending bytes we already sent.
		o.Counters.RetransSent.Add(1)
		o.Counters.OctetsRetrans.Add(uint64(len(s.Payload)))
		kind := "fast_retransmit"
		spurious := o.oHavePeerAck && seqLE(end, o.oPeerAck)
		if spurious {
			kind = "rto"
			o.Counters.SpuriousRetrans.Add(1)
		}
		if o.oDupRun >= 3 {
			o.Counters.FastRetrans.Add(1)
			kind = "fast_retransmit"
		}
		o.Ring.Add(wire.RetxEvent{
			Seq: s.Seq, Len: uint32(len(s.Payload)), Kind: kind, At: now.UnixNano(),
			AlreadyAcked: spurious, OctetsReSent: uint64(len(s.Payload)),
		})
	} else if o.oHaveSeq && seqGT(s.Seq, o.oMaxDataEnd) {
		o.Gaps.Open(uint64(o.oMaxDataEnd), uint64(s.Seq))
	}
	if !o.oHaveSeq || seqGT(end, o.oMaxDataEnd) {
		o.oMaxDataEnd = end
		o.oHaveSeq = true
	}
	o.oLastDataSeq, o.oLastDataLen, o.oLastDataAt = s.Seq, uint32(len(s.Payload)), now
	if s.Opts.HasTimestamp {
		o.lastTsSent[s.Opts.Timestamp] = now.UnixNano()
		if len(o.lastTsSent) > 512 {
			for k := range o.lastTsSent {
				if len(o.lastTsSent) > 384 {
					delete(o.lastTsSent, k)
				} else {
					break
				}
			}
		}
	}
}

func (o *Observer) observeInbound(s *Segment, now time.Time) {
	o.Counters.SegsRecv.Add(1)
	if s.Flags&FlagRST != 0 {
		o.Counters.RstRecv.Add(1)
	}
	if s.Flags&FlagACK != 0 {
		if s.Window == 0 {
			o.Counters.ZeroWindowRecv.Add(1)
		}
		// Duplicate ACK from the peer.
		if o.haveObservedAck && s.Ack == o.lastObservedAck && s.Ack != 0 &&
			o.oMaxDataEnd != 0 && seqLT(s.Ack, o.oMaxDataEnd) && len(s.Payload) == 0 {
			o.iDupRun++
			o.Counters.DupAcksRecv.Add(1)
		} else if !o.haveObservedAck || s.Ack != o.lastObservedAck {
			o.iDupRun = 0
		}
		o.haveObservedAck = true
		o.lastObservedAck = s.Ack
		if o.oHaveSeq && seqGT(s.Ack, o.oPeerAck) {
			o.oPeerAck = s.Ack
			if o.oLastDataLen > 0 && seqLE(o.oLastDataSeq+o.oLastDataLen, s.Ack) {
				rtt := now.Sub(o.oLastDataAt)
				if rtt > 0 && rtt < 30*time.Second {
					o.Hist.Observe(float64(rtt) / float64(time.Millisecond))
				}
			}
		}
	}
	if len(s.Payload) == 0 {
		return
	}
	end := s.Seq + uint32(len(s.Payload))
	if o.iHaveSeq && seqLT(s.Seq, o.iMaxDataEnd) {
		// Data we have already seen arriving again.
		o.Counters.RetransRecv.Add(1)
		if o.iHaveOurAck && seqLE(end, o.iOurAck) {
			o.Counters.SpuriousRecv.Add(1)
			o.Ring.Add(wire.RetxEvent{Seq: s.Seq, Len: uint32(len(s.Payload)), Kind: "rto", At: now.UnixNano(), AlreadyAcked: true})
		} else {
			o.Ring.Add(wire.RetxEvent{Seq: s.Seq, Len: uint32(len(s.Payload)), Kind: "fast_retransmit", At: now.UnixNano()})
		}
	} else if o.iHaveSeq && seqGT(s.Seq, o.iMaxDataEnd) {
		o.Counters.OooSegs.Add(1)
		o.Gaps.Open(uint64(o.iMaxDataEnd), uint64(s.Seq))
	}
	if o.iHaveOurAck == false || seqGT(s.Ack, o.iOurAck) {
		o.iOurAck = s.Ack
		o.iHaveOurAck = true
	}
	if !o.iHaveSeq || seqGT(end, o.iMaxDataEnd) {
		o.iMaxDataEnd = end
		o.iHaveSeq = true
	}
	o.iLastDataSeq, o.iLastDataAt = s.Seq, now
	o.Counters.BytesRecv.Add(uint64(len(s.Payload)))
}

// Snapshot renders the observed conversation as a wire.Snapshot.
func (o *Observer) Snapshot() *wire.Snapshot {
	o.mu.Lock()
	defer o.mu.Unlock()
	cs := o.Counters
	s := &wire.Snapshot{
		Generated:       time.Now().UnixNano(),
		Stack:           "observe",
		SegsSent:        cs.SegsSent.Load(),
		SegsRecv:        cs.SegsRecv.Load(),
		BytesRecv:       cs.BytesRecv.Load(),
		RetransSent:     cs.RetransSent.Load(),
		OctetsRetrans:   cs.OctetsRetrans.Load(),
		SpuriousRetrans: cs.SpuriousRetrans.Load(),
		RetransRecvSegs: cs.RetransRecv.Load(),
		SpuriousRecv:    cs.SpuriousRecv.Load(),
		OooSegs:         cs.OooSegs.Load(),
		DupAcksSent:     cs.DupAcksSent.Load(),
		DupAcksRecv:     cs.DupAcksRecv.Load(),
		ZeroWindowAdv:   cs.ZeroWindowAdv.Load(),
		ZeroWindowRecv:  cs.ZeroWindowRecv.Load(),
		RTTEwms:         o.Hist.Mean(),
		Hist:            o.Hist.Snapshot(),
		RetxLog:         o.Ring.Snapshot(),
		LocalEP:         o.key.A.String() + ":" + itoa(int(o.key.APort)),
		RemoteEP:        o.key.B.String() + ":" + itoa(int(o.key.BPort)),
		Iface:           o.name,
	}
	g, open := o.Gaps.Snapshot()
	s.Gaps = g
	s.OpenGaps = open
	s.MaxGapSeen = o.Gaps.MaxGap()
	s.HoleBytes = o.Gaps.Missing()
	s.ElapsedSec = time.Since(o.start).Seconds()
	return s
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
