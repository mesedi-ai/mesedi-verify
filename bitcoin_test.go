package main

// Bitcoin timestamps, checked with the reference client's own published
// proofs (testdata/OTS-SOURCES.md) and a stand-in block source.

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mesedi-ai/mesedi/backend/attest"
)

const realBlockRoot = "936131994129988e1932d8c1c6a9780fd42ae4c87204cfb0ac852be1250039ae"

type fixedBlocks map[uint64]string

func (f fixedBlocks) merkleRoot(_ context.Context, h uint64) (string, time.Time, error) {
	r, ok := f[h]
	if !ok {
		return "", time.Time{}, logUnreachable{errors.New("explorer down")}
	}
	return r, time.Date(2025, 8, 28, 13, 11, 10, 0, time.UTC), nil
}

// realInterval wraps a published .ots file as a checkpoint whose hash is
// the file's digest and whose receipt is the file's timestamp.
func realInterval(t *testing.T, name string) attest.ExportedInterval {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	digest, ts, err := attest.ParseOTSFile(raw)
	if err != nil {
		t.Fatal(err)
	}
	return attest.ExportedInterval{
		Checkpoint: attest.Checkpoint{Seq: 9, Hash: hex.EncodeToString(digest)},
		Timestamps: []attest.ExportedTimestamp{{Calendar: "https://alice.example", Receipt: ts.Serialize(), Complete: true}},
	}
}

func TestARealBitcoinTimestampVerifiesAgainstItsBlock(t *testing.T) {
	got := checkIntervalTimestamps(context.Background(), realInterval(t, "ots-bitcoin-912095.ots"), fixedBlocks{912095: realBlockRoot})
	if got.Status != StatusVerified || !strings.Contains(got.Detail, "Bitcoin block 912095") {
		t.Fatalf("%+v", got)
	}
}

func TestAReceiptThatLeadsElsewhereFails(t *testing.T) {
	got := checkIntervalTimestamps(context.Background(), realInterval(t, "ots-bitcoin-912095.ots"), fixedBlocks{912095: strings.Repeat("ab", 32)})
	if got.Status != StatusFailed {
		t.Fatalf("a receipt that does not match its block: %+v", got)
	}
	iv := realInterval(t, "ots-bitcoin-912095.ots")
	iv.Checkpoint.Hash = strings.Repeat("00", 32) // the receipt is for another hash
	if got := checkIntervalTimestamps(context.Background(), iv, fixedBlocks{912095: realBlockRoot}); got.Status != StatusFailed {
		t.Fatalf("a receipt for another checkpoint verified: %+v", got)
	}
	iv = realInterval(t, "ots-bitcoin-912095.ots")
	iv.Timestamps[0].Receipt = []byte{0x42}
	if got := checkIntervalTimestamps(context.Background(), iv, nil); got.Status != StatusFailed {
		t.Fatalf("an unreadable receipt: %+v", got)
	}
}

func TestOfflinePendingAndAbsentAreNotFailures(t *testing.T) {
	ctx := context.Background()
	off := checkIntervalTimestamps(ctx, realInterval(t, "ots-bitcoin-912095.ots"), nil)
	if off.Status != StatusUnverifiable || !strings.Contains(off.Detail, "block 912095, Merkle root "+realBlockRoot) {
		t.Fatalf("offline: %+v", off)
	}
	down := checkIntervalTimestamps(ctx, realInterval(t, "ots-bitcoin-912095.ots"), fixedBlocks{})
	if down.Status != StatusUnverifiable {
		t.Fatalf("explorer down: %+v", down)
	}
	pending := checkIntervalTimestamps(ctx, realInterval(t, "ots-two-calendars.ots"), nil)
	if pending.Status != "pending" {
		t.Fatalf("pending: %+v", pending)
	}
	none := checkIntervalTimestamps(ctx, attest.ExportedInterval{Checkpoint: attest.Checkpoint{Seq: 2}}, nil)
	if none.Status != "none" {
		t.Fatalf("none: %+v", none)
	}
	est, caveat, failed := timestampNotes([]timestampCheck{off, pending, none, {Seq: 9, Status: StatusVerified}}, true)
	if failed || !strings.Contains(est, "[9] are also in Bitcoin") || !strings.Contains(caveat, "offline run cannot compare") {
		t.Fatalf("notes: %q / %q / %v", est, caveat, failed)
	}
	if _, _, failed := timestampNotes([]timestampCheck{{Status: StatusFailed}}, false); !failed {
		t.Fatal("a false receipt did not fail the report")
	}
}

func TestTheExplorerClientReadsTheBlockAndNamesFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/block-height/912095":
			_, _ = w.Write([]byte("000000000000000000007f0753c6209263c7072e51b725e89e75a0c708b90345"))
		case "/block/000000000000000000007f0753c6209263c7072e51b725e89e75a0c708b90345":
			_, _ = w.Write([]byte(`{"merkle_root":"` + strings.ToUpper(realBlockRoot) + `","timestamp":1756386670}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	root, mined, err := newEsplora(srv.URL+"/").merkleRoot(context.Background(), 912095)
	if err != nil || root != realBlockRoot || mined.Unix() != 1756386670 {
		t.Fatalf("root %s, mined %s, err %v", root, mined, err)
	}
	_, _, err = newEsplora(srv.URL).merkleRoot(context.Background(), 1)
	var down logUnreachable
	if !errors.As(err, &down) {
		t.Fatalf("a missing block is reported as %v; want unreachable, not a finding", err)
	}
}
