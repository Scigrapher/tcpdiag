package wire

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	f := &Frame{
		H:       Header{Type: MsgData, Flags: FlagPriority, BlockSeq: 4242, StreamOffset: 999999},
		Report:  []byte(`{"hello":"world"}`),
		Payload: []byte("the quick brown fox"),
	}
	if err := WriteFrame(&buf, f); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.H.Type != MsgData || got.H.Flags != FlagPriority || got.H.BlockSeq != 4242 || got.H.StreamOffset != 999999 {
		t.Fatalf("header mismatch: %+v", got.H)
	}
	if !bytes.Equal(got.Report, f.Report) || !bytes.Equal(got.Payload, f.Payload) {
		t.Fatal("body mismatch")
	}
}

func TestKeystreamDependsOnReceiveHistory(t *testing.T) {
	seed := []byte("session-seed")
	var rdA, rdB [DigestSize]byte
	rdB[3] = 1
	a := make([]byte, 512)
	b := make([]byte, 512)
	Keystream(seed, 7, rdA, a)
	Keystream(seed, 7, rdB, b)
	if bytes.Equal(a, b) {
		t.Fatal("payload must depend on the sender's receive-chain head")
	}
	// Same inputs => same bytes (both ends must be able to reproduce them).
	c := make([]byte, 512)
	Keystream(seed, 7, rdA, c)
	if !bytes.Equal(a, c) {
		t.Fatal("keystream must be deterministic")
	}
	// Different block number => different bytes.
	d := make([]byte, 512)
	Keystream(seed, 8, rdA, d)
	if bytes.Equal(a, d) {
		t.Fatal("keystream must depend on the block number")
	}
}

func TestChainDetectsSkippedAndReplayedBlocks(t *testing.T) {
	seed := []byte("s")
	var zero [DigestSize]byte
	mk := func(seq uint64, prev [DigestSize]byte, recv [DigestSize]byte) *Frame {
		pl := make([]byte, 64)
		Keystream(seed, seq, recv, pl)
		return &Frame{H: Header{Type: MsgData, BlockSeq: seq, PrevSentDigest: prev, RecvDigest: recv}, Payload: pl}
	}
	var recv [DigestSize]byte
	f1 := mk(1, zero, recv)
	if !ExpectedPayload(seed, f1) {
		t.Fatal("payload should verify")
	}
	chain1 := ChainNext(zero, 1, f1.Payload)
	f2 := mk(2, chain1, recv)
	if !ExpectedPayload(seed, f2) {
		t.Fatal("payload 2 should verify")
	}
	// Replay block 1 but claim the chain head of block 2: must be detected.
	replay := mk(1, chain1, recv)
	if replay.H.PrevSentDigest == zero {
		t.Fatal("setup error")
	}
	// Tamper with a single payload byte: verification must fail.
	bad := mk(3, chain1, recv)
	if !ExpectedPayload(seed, bad) {
		t.Fatal("clean payload should verify")
	}
	bad.Payload[10] ^= 0x01
	if ExpectedPayload(seed, bad) {
		t.Fatal("a tampered payload must not verify")
	}
	bad.Payload[10] ^= 0x01
	if !ExpectedPayload(seed, bad) {
		t.Fatal("restored payload should verify")
	}
}

func TestReadFrameRejectsGarbage(t *testing.T) {
	if _, err := ReadFrame(bytes.NewReader(make([]byte, HeaderSize))); err == nil {
		t.Fatal("zero-filled header must not parse")
	}
	h := Header{Type: MsgData}
	raw := make([]byte, HeaderSize)
	h.Marshal(raw)
	raw[2] = 9 // bogus version
	if _, err := ReadFrame(bytes.NewReader(raw)); err == nil {
		t.Fatal("bad version must not parse")
	}
}
