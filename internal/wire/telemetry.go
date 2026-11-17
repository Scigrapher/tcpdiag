package wire

// Gap records a hole observed in the incoming block sequence and how long it
// took to fill, whether by in-order arrival or by a retransmission.
type Gap struct {
	From     uint64 `json:"from"`
	To       uint64 `json:"to"` // exclusive
	Detected int64  `json:"detected_ns"`
	Filled   int64  `json:"filled_ns,omitempty"` // 0 == still open
	FillSrc  string `json:"fill_src,omitempty"`  // in_order | retransmit | timeout
}

// RetxEvent records one retransmission made by the local stack together with
// the evidence needed to decide whether it was genuine loss, a timeout
// artefact, or a spurious resend of data the peer already acknowledged.
type RetxEvent struct {
	Seq             uint32 `json:"seq"`
	Len             uint32 `json:"len"`
	Kind            string `json:"kind"` // fast_retransmit | rto | zero_window_probe | syn | keepalive
	At              int64  `json:"at_ns"`
	SinceLastAckMs  int64  `json:"since_last_ack_ms"`
	SinceLastDataMs int64  `json:"since_last_data_ms"`
	AlreadyAcked    bool   `json:"already_acked"` // peer had already ACKed/SACKed this range
	WithinRTT       bool   `json:"within_rtt"`    // fired sooner than SRTT+2*RTTVAR => too aggressive
	RetransmitCount uint32 `json:"retransmit_count"`
	OctetsReSent    uint64 `json:"octets_resent"`
}

// RTTHistogram uses exponentially growing buckets: bucket 0 covers [0,1) ms,
// bucket i covers [2^(i-1), 2^i) ms.
type RTTHistogram struct {
	Buckets []uint64 `json:"buckets"`
	Count   uint64   `json:"count"`
	SumMs   float64  `json:"sum_ms"`
	MinMs   float64  `json:"min_ms"`
	MaxMs   float64  `json:"max_ms"`
}

// Snapshot is the self-description a peer embeds in every block it transmits.
// Because it rides inside the *data* stream, the far side can reconstruct the
// health of both directions without ever touching the remote machine.
type Snapshot struct {
	Generated int64  `json:"gen_ns"`
	PeerID    string `json:"peer_id"`
	PeerName  string `json:"peer_name"`
	Stack     string `json:"stack"` // kernel | raw | sim

	// Application throughput
	BlocksSent  uint64  `json:"blocks_sent"`
	BytesSent   uint64  `json:"bytes_sent"`
	BlocksRecv  uint64  `json:"blocks_recv"`
	BytesRecv   uint64  `json:"bytes_recv"`
	MbpsSent    float64 `json:"mbps_sent"`
	MbpsRecv    float64 `json:"mbps_recv"`
	AvgMbpsSent float64 `json:"avg_mbps_sent"`
	AvgMbpsRecv float64 `json:"avg_mbps_recv"`
	ElapsedSec  float64 `json:"elapsed_sec"`

	// Ingress integrity of the stream we are receiving
	BlocksMissing uint64 `json:"blocks_missing"`
	BlocksDup     uint64 `json:"blocks_dup"`
	BlocksOOO     uint64 `json:"blocks_ooo"`
	BlocksLate    uint64 `json:"blocks_late"`
	ChainMismatch uint64 `json:"chain_mismatch"`
	OpenGaps      uint32 `json:"open_gaps"`
	MaxGapSeen    uint32 `json:"max_gap_seen"`
	HoleBytes     uint64 `json:"hole_bytes"`
	Gaps          []Gap  `json:"gaps,omitempty"`

	// Egress retransmission behaviour of our own stack
	RetransSent      uint64 `json:"retrans_sent"`
	RtoRetrans       uint64 `json:"rto_retrans"`
	FastRetrans      uint64 `json:"fast_retrans"`
	SpuriousRetrans  uint64 `json:"spurious_retrans"`
	SpuriousSack     uint64 `json:"spurious_sack_retrans"`
	SynRetrans       uint64 `json:"syn_retrans"`
	OctetsRetrans    uint64 `json:"octets_retrans"`
	MaxRetransPerSeq uint32 `json:"max_retrans_per_seq"`

	// Segment-level view (mirrors what Wireshark annotates)
	SpuriousRecv    uint64 `json:"spurious_retrans_recv"`
	RetransRecvSegs uint64 `json:"retrans_segs_recv"`
	OooSegs         uint64 `json:"out_of_order_segs"`
	SegsSent        uint64 `json:"segs_sent"`
	SegsRecv        uint64 `json:"segs_recv"`
	AckSegsRecv     uint64 `json:"ack_segs_recv"`
	BufFullStalls   uint64 `json:"buf_full_stalls"`
	RstRecv         uint64 `json:"rst_recv"`

	// Acknowledgement behaviour
	DupAcksSent  uint64  `json:"dup_acks_sent"`
	DupAcksRecv  uint64  `json:"dup_acks_recv"`
	DelayedAcks  uint64  `json:"delayed_acks"`
	AckLatencyMs float64 `json:"ack_latency_ms"`
	SackBlocks   uint64  `json:"sack_blocks"`
	SawPeerSyn   bool    `json:"saw_peer_syn"`
	PeerSACK     bool    `json:"peer_sack"`
	PeerSynOpts  string  `json:"peer_syn_options,omitempty"`
	State        string  `json:"state,omitempty"`

	// Flow control
	ZeroWindowAdv  uint64 `json:"zero_window_adv"`  // we told the peer to stop
	ZeroWindowRecv uint64 `json:"zero_window_recv"` // peer told us to stop
	WindowProbes   uint64 `json:"window_probes"`
	AdvWindow      uint32 `json:"adv_window"`
	PeerWindow     uint32 `json:"peer_window"`
	Cwnd           uint32 `json:"cwnd"`
	InFlight       uint32 `json:"in_flight"`
	RcvBufBytes    uint32 `json:"rcv_buf_bytes"`
	SndBufBytes    uint32 `json:"snd_buf_bytes"`

	// Timers / path quality
	RTTEwms   float64           `json:"rtt_ewms"`
	RTTVarms  float64           `json:"rtt_varms"`
	RTOms     float64           `json:"rto_ms"`
	RTOExpire uint64            `json:"rto_expires"`
	Hist      *RTTHistogram     `json:"hist,omitempty"`
	RetxLog   []RetxEvent       `json:"retx_log,omitempty"`
	Kernel    map[string]uint64 `json:"kernel,omitempty"`

	Iface    string   `json:"iface,omitempty"`
	LocalEP  string   `json:"local_ep,omitempty"`
	RemoteEP string   `json:"remote_ep,omitempty"`
	Notes    []string `json:"notes,omitempty"`
}

// Add merges another snapshot's counters into this one. Used by --stack=both to
// present kernel and raw engines side by side and as a combined total.
func (s *Snapshot) Add(o *Snapshot) {
	if o == nil {
		return
	}
	if s.Stack == "" {
		s.Stack = o.Stack
	}
	if s.PeerID == "" {
		s.PeerID = o.PeerID
	}
	if s.PeerName == "" {
		s.PeerName = o.PeerName
	}
	s.BlocksSent += o.BlocksSent
	s.BytesSent += o.BytesSent
	s.BlocksRecv += o.BlocksRecv
	s.BytesRecv += o.BytesRecv
	s.MbpsSent += o.MbpsSent
	s.MbpsRecv += o.MbpsRecv
	s.BlocksMissing += o.BlocksMissing
	s.BlocksDup += o.BlocksDup
	s.BlocksOOO += o.BlocksOOO
	s.BlocksLate += o.BlocksLate
	s.ChainMismatch += o.ChainMismatch
	s.OpenGaps += o.OpenGaps
	if o.MaxGapSeen > s.MaxGapSeen {
		s.MaxGapSeen = o.MaxGapSeen
		s.HoleBytes += o.HoleBytes
	}
	s.RetransSent += o.RetransSent
	s.RtoRetrans += o.RtoRetrans
	s.FastRetrans += o.FastRetrans
	s.SpuriousRetrans += o.SpuriousRetrans
	s.SpuriousSack += o.SpuriousSack
	s.SpuriousRecv += o.SpuriousRecv
	s.RetransRecvSegs += o.RetransRecvSegs
	s.OooSegs += o.OooSegs
	s.SegsSent += o.SegsSent
	s.SegsRecv += o.SegsRecv
	s.AckSegsRecv += o.AckSegsRecv
	s.BufFullStalls += o.BufFullStalls
	s.RstRecv += o.RstRecv
	s.SynRetrans += o.SynRetrans
	s.OctetsRetrans += o.OctetsRetrans
	if o.MaxRetransPerSeq > s.MaxRetransPerSeq {
		s.MaxRetransPerSeq = o.MaxRetransPerSeq
	}
	s.DupAcksSent += o.DupAcksSent
	s.DupAcksRecv += o.DupAcksRecv
	s.DelayedAcks += o.DelayedAcks
	if o.AckLatencyMs > s.AckLatencyMs {
		s.AckLatencyMs = o.AckLatencyMs
	}
	s.ZeroWindowAdv += o.ZeroWindowAdv
	s.ZeroWindowRecv += o.ZeroWindowRecv
	s.WindowProbes += o.WindowProbes
	s.RTOExpire += o.RTOExpire
	s.Gaps = append(s.Gaps, o.Gaps...)
	s.RetxLog = append(s.RetxLog, o.RetxLog...)
	if o.RTTEwms > s.RTTEwms {
		s.RTTEwms = o.RTTEwms
	}
	if o.RTTVarms > s.RTTVarms {
		s.RTTVarms = o.RTTVarms
	}
	if o.RTOms > s.RTOms {
		s.RTOms = o.RTOms
	}
	if o.Cwnd > s.Cwnd {
		s.Cwnd = o.Cwnd
	}
	if o.InFlight > s.InFlight {
		s.InFlight = o.InFlight
	}
	if o.PeerWindow > s.PeerWindow {
		s.PeerWindow = o.PeerWindow
	}
	if o.AdvWindow > s.AdvWindow {
		s.AdvWindow = o.AdvWindow
	}
	if o.Hist != nil && (s.Hist == nil || o.Hist.Count > s.Hist.Count) {
		s.Hist = o.Hist
	}
	if o.AvgMbpsSent > s.AvgMbpsSent {
		s.AvgMbpsSent = o.AvgMbpsSent
	}
	if o.AvgMbpsRecv > s.AvgMbpsRecv {
		s.AvgMbpsRecv = o.AvgMbpsRecv
	}
	if s.LocalEP == "" {
		s.LocalEP = o.LocalEP
	}
	if s.RemoteEP == "" {
		s.RemoteEP = o.RemoteEP
	}
	if s.Iface == "" {
		s.Iface = o.Iface
	}
	// Handshake-derived fields are not counters. They must still survive the
	// merge: flow.LocalSnapshot starts from an empty snapshot and folds the raw
	// connection's snapshot in through this function. Dropping these booleans
	// made an established SACK-negotiated connection look like it never saw a
	// peer SYN at all.
	if o.SawPeerSyn {
		s.SawPeerSyn = true
	}
	if o.PeerSACK {
		s.PeerSACK = true
	}
	if s.PeerSynOpts == "" {
		s.PeerSynOpts = o.PeerSynOpts
	}
	if s.State == "" {
		s.State = o.State
	}
	s.Notes = append(s.Notes, o.Notes...)
}

// Capture summarises what a raw packet engine observed. Keeping the type here
// lets the capture layer, the report and the dashboard all agree on it.
type Capture struct {
	Engine    string `json:"engine,omitempty"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
	TCP       uint64 `json:"tcp"`
	UDP       uint64 `json:"udp"`
	DiagTCP   uint64 `json:"diag_tcp"`
	DiagUDP   uint64 `json:"diag_udp"`
	ICMP      uint64 `json:"icmp"`
	Other     uint64 `json:"other"`
	Oversized uint64 `json:"oversized"`
	Control   uint64 `json:"control"`
	MaxBytes  int    `json:"max_bytes"`
	Injected  uint64 `json:"injected"`
	TxBytes   uint64 `json:"tx_bytes"`
	PCAP      string `json:"pcap,omitempty"`
	// PCAP* fields describe the file that was written, not the engine's total
	// view. Filtering is on by default so one host's unrelated connections do
	// not drown the tcpdiag session in Wireshark.
	PCAPFiltered  uint64 `json:"pcap_filtered,omitempty"`
	PCAPSynthetic uint64 `json:"pcap_synthetic,omitempty"`
	PCAPDuplicate uint64 `json:"pcap_duplicate,omitempty"`
	PCAPAll       bool   `json:"pcap_all,omitempty"`
}
