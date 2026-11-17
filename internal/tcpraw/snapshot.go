package tcpraw

import (
	"time"

	"tcpdiag/internal/wire"
)

// Snapshot exports the connection's instrumented counters for embedding in the
// data stream and for the local report.
func (c *Conn) Snapshot() *wire.Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	cs := c.Counters
	s := &wire.Snapshot{
		Generated:        time.Now().UnixNano(),
		Stack:            "raw",
		BlocksSent:       cs.BlocksSent.Load(),
		BytesSent:        cs.BytesSent.Load(),
		BlocksRecv:       cs.BlocksRecv.Load(),
		BytesRecv:        cs.BytesRecv.Load(),
		RetransSent:      cs.RetransSent.Load(),
		RtoRetrans:       cs.RtoRetrans.Load(),
		FastRetrans:      cs.FastRetrans.Load(),
		SpuriousRetrans:  cs.SpuriousRetrans.Load(),
		SpuriousSack:     cs.SpuriousSack.Load(),
		SpuriousRecv:     cs.SpuriousRecv.Load(),
		RetransRecvSegs:  cs.RetransRecv.Load(),
		OooSegs:          cs.OooSegs.Load(),
		SynRetrans:       cs.SynRetrans.Load(),
		OctetsRetrans:    cs.OctetsRetrans.Load(),
		MaxRetransPerSeq: uint32(cs.MaxRetrPerSeq.Load()),
		SegsSent:         cs.SegsSent.Load(),
		SegsRecv:         cs.SegsRecv.Load(),
		AckSegsRecv:      cs.AckSegsRecv.Load(),
		BufFullStalls:    cs.BufFullStalls.Load(),
		DupAcksSent:      cs.DupAcksSent.Load(),
		DupAcksRecv:      cs.DupAcksRecv.Load(),
		DelayedAcks:      cs.DelayedAcks.Load(),
		SackBlocks:       cs.SackBlocks.Load(),
		ZeroWindowAdv:    cs.ZeroWindowAdv.Load(),
		ZeroWindowRecv:   cs.ZeroWindowRecv.Load(),
		WindowProbes:     cs.WindowProbes.Load(),
		Cwnd:             c.cwnd,
		InFlight:         c.inFlight,
		PeerWindow:       c.peerWin,
		AdvWindow:        c.advertisedWindow(),
		RcvBufBytes:      uint32(c.cfg.RcvBuf),
		SndBufBytes:      uint32(c.cfg.SndBuf),
		RTTEwms:          float64(c.rto.SRTT) / float64(time.Millisecond),
		RTTVarms:         float64(c.rto.RTTVar) / float64(time.Millisecond),
		RTOms:            float64(c.rto.RTO) / float64(time.Millisecond),
		RTOExpire:        c.rto.Expiry,
		Hist:             c.Hist.Snapshot(),
		RetxLog:          c.Ring.Snapshot(),
		LocalEP:          c.key.A.String() + ":" + itoa(int(c.key.APort)),
		RemoteEP:         c.key.B.String() + ":" + itoa(int(c.key.BPort)),
	}
	g, open := c.Gaps.Snapshot()
	s.Gaps = g
	s.OpenGaps = open
	s.MaxGapSeen = c.Gaps.MaxGap()
	s.HoleBytes = c.Gaps.Missing()
	s.ElapsedSec = time.Since(c.startAt).Seconds()
	s.SawPeerSyn = c.sawPeerSyn
	s.PeerSACK = c.peerSACKOK
	s.PeerSynOpts = c.peerSynOpts
	s.State = c.state.String()
	switch {
	case !c.sawPeerSyn:
		s.Notes = append(s.Notes, "peer SYN not observed yet; SACK state is unknown")
	case c.peerSACKOK:
		s.Notes = append(s.Notes, "peer negotiated SACK ["+c.peerSynOpts+"]")
	default:
		s.Notes = append(s.Notes, "peer SYN carried no SACK-Permitted option ["+c.peerSynOpts+"] - retransmits are coarser and dup-ACK storms last longer")
	}
	if c.peerScale == 0 {
		s.Notes = append(s.Notes, "peer did not negotiate window scaling (max effective window 64 KiB)")
	}
	return s
}

// StateString is a stable label for reports.
func (c *Conn) StateString() string { return c.State().String() }
