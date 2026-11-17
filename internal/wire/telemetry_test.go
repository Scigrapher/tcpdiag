package wire

import "testing"

// A flow snapshot starts empty and folds in the transport stack's snapshot.
// Handshake-derived fields are not counters, so they have to be copied
// explicitly; losing them made an established connection report that no peer
// SYN had ever been seen.
func TestSnapshotAddKeepsHandshakeFields(t *testing.T) {
	var s Snapshot
	s.Add(&Snapshot{
		Stack:       "raw",
		PeerID:      "peer-1",
		PeerName:    "node-b",
		BlocksLate:  3,
		SawPeerSyn:  true,
		PeerSACK:    true,
		PeerSynOpts: "MSS=1400, SACK-Permitted",
		State:       "ESTABLISHED",
	})
	if !s.SawPeerSyn {
		t.Fatal("SawPeerSyn was dropped by Add")
	}
	if !s.PeerSACK {
		t.Fatal("PeerSACK was dropped by Add")
	}
	if s.PeerSynOpts == "" || s.State != "ESTABLISHED" {
		t.Fatalf("handshake metadata was dropped: opts=%q state=%q", s.PeerSynOpts, s.State)
	}
	if s.BlocksLate != 3 {
		t.Fatalf("BlocksLate was dropped: %d", s.BlocksLate)
	}
	if s.Stack != "raw" || s.PeerID != "peer-1" || s.PeerName != "node-b" {
		t.Fatalf("identity was dropped: %+v", s)
	}
}
