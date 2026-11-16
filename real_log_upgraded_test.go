package main

// The same real-log run after its receipts were upgraded, later on 16
// November 2026 (testdata/real-log-run-2026-11-16-upgraded-export.json).
// Two calendars' receipts for every checkpoint reach two different
// Bitcoin blocks; the third calendar's are still pending. The block
// roots and mined times below are the real ones, read from
// blockstream.info/api the same evening.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mesedi-ai/mesedi/backend/attest"
)

type realBlocks map[uint64]struct {
	root  string
	mined time.Time
}

func (b realBlocks) merkleRoot(_ context.Context, h uint64) (string, time.Time, error) {
	blk, ok := b[h]
	if !ok {
		return "", time.Time{}, logUnreachable{errors.New("explorer down")}
	}
	return blk.root, blk.mined, nil
}

func upgradedRealExport(t *testing.T) attest.ChainExport {
	t.Helper()
	raw, err := os.ReadFile("testdata/real-log-run-2026-11-16-upgraded-export.json")
	if err != nil {
		t.Fatal(err)
	}
	var export attest.ChainExport
	if err := json.Unmarshal(raw, &export); err != nil {
		t.Fatal(err)
	}
	return export
}

func blocks976183And976185() realBlocks {
	return realBlocks{
		976183: {"3f502e93b96383e16a6528802baf88f85a61778dffb8460f7444e06fcfb00fb3",
			time.Date(2026, 11, 16, 20, 47, 59, 0, time.UTC)},
		976185: {"6a2ef0c6f69233ce6cd25b1184888398224a48aa375f8b4b68e575786cf3c1d7",
			time.Date(2026, 11, 16, 21, 3, 49, 0, time.UTC)},
	}
}

// The earliest block is what the receipts prove, so the report names it,
// whichever calendar's receipt happens to be checked last.
func TestTheEarliestBitcoinBlockIsTheOneReported(t *testing.T) {
	checks := checkTimestamps(context.Background(), upgradedRealExport(t), blocks976183And976185())
	if len(checks) != 4 {
		t.Fatalf("%d checks, want 4", len(checks))
	}
	for _, c := range checks {
		if c.Status != StatusVerified ||
			!strings.Contains(c.Detail, "block 976183, mined 2026-11-16T20:47:59Z") ||
			!strings.Contains(c.Detail, "the earliest of 2 blocks") {
			t.Errorf("checkpoint %d: %s: %s", c.Seq, c.Status, c.Detail)
		}
	}
}

// An earlier block that checks out does not excuse a later false one.
func TestAFalseLaterReceiptStillFailsTheCheckpoint(t *testing.T) {
	blocks := blocks976183And976185()
	bad := blocks[976185]
	bad.root = strings.Repeat("ab", 32)
	blocks[976185] = bad
	for _, c := range checkTimestamps(context.Background(), upgradedRealExport(t), blocks) {
		if c.Status != StatusFailed || !strings.Contains(c.Detail, "block 976185") {
			t.Errorf("checkpoint %d: %s: %s", c.Seq, c.Status, c.Detail)
		}
	}
}

// These hours were published on 16 November 2026 and carry no growth
// proof. The note must not give them a reason that is false for them.
func TestTheMissingGrowthProofNoteDoesNotMisdateTheHours(t *testing.T) {
	res := checkLogGrowth(upgradedRealExport(t).Intervals)
	if res.Unproven != 3 || res.Proven != 0 || len(res.Failures) != 0 {
		t.Fatalf("%+v, want 3 unproven", res)
	}
	note := unprovenGrowthNote(res.Unproven)
	if strings.Contains(note, "carry none") || !strings.Contains(note, "for a later hour it means none was saved") {
		t.Errorf("note: %s", note)
	}
}
