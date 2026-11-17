package main

// The smaller fixes from the outside review's round 2 (17 November 2026):
// every delay shown and an auditor-set maximum, growth tree heads read
// from Sigstore's signed text, an unreadable Bitcoin attestation failing,
// and runs with events after anchoring named in the report.

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mesedi-ai/mesedi/backend/attest"
)

func TestEveryDelayIsShownAndTheAuditorSetsTheLimits(t *testing.T) {
	iv := timedInterval(1, "7", hourStart)
	at := iv.Checkpoint.IntervalEnd.Add(101 * time.Minute) // 1 hour 41 minutes late

	got := LogEntryCheck{Status: StatusVerified}
	applyPublicationTime(&got, at, iv)
	if got.LateBy != 0 || got.TooLate || !strings.Contains(got.Detail, "published 1 hour 41 minutes after this hour ended") {
		t.Fatalf("defaults: late %s, too late %v, detail %q", got.LateBy, got.TooLate, got.Detail)
	}

	defer func(a, m time.Duration) { lateAfter, maxLate = a, m }(lateAfter, maxLate)
	lateAfter, maxLate = 15*time.Minute, time.Hour
	got = LogEntryCheck{Status: StatusVerified}
	applyPublicationTime(&got, at, iv)
	if got.LateBy != 101*time.Minute || !got.TooLate || !strings.Contains(got.Detail, "the most this run was told to accept") {
		t.Fatalf("an auditor's 15-minute late point and 1-hour maximum: late %s, too late %v, detail %q",
			got.LateBy, got.TooLate, got.Detail)
	}
	rep := sampleReport(true, true)
	rep.LogEntries[0] = got
	if v := decideVerdict(rep); v.Kind != verdictIncomplete || !strings.Contains(sentence(v.Gaps), "1 hour") {
		t.Fatalf("an hour past the maximum gave %s: %v", v.Kind, v.Gaps)
	}
}

func TestGrowthTreeHeadsComeFromSigstoresSignedText(t *testing.T) {
	// The unsigned fields claim another size and root; the signed
	// checkpoint wins.
	iv := intervalWith(t, 24, live27Size, strings.Repeat("ab", 32), "")
	var env map[string]json.RawMessage
	_ = json.Unmarshal(iv.AnchorProof, &env)
	var inc map[string]any
	_ = json.Unmarshal(env["inclusion_proof"], &inc)
	inc["Checkpoint"] = liveCheckpoints[live24Size]
	env["inclusion_proof"], _ = json.Marshal(inc)
	iv.AnchorProof, _ = json.Marshal(env)
	size, root, ok := treeHeadOf(iv)
	if !ok || size != live24Size || hex.EncodeToString(root) != live24Root {
		t.Fatalf("tree head %d %x (ok %v), want the signed %d %s", size, root, ok, live24Size, live24Root)
	}

	// A checkpoint whose signature does not verify gives no tree head.
	inc["Checkpoint"] = strings.Replace(liveCheckpoints[live24Size], "2603896653", "2603896654", 1)
	env["inclusion_proof"], _ = json.Marshal(inc)
	iv.AnchorProof, _ = json.Marshal(env)
	if _, _, ok := treeHeadOf(iv); ok {
		t.Fatal("a checkpoint with a broken signature gave a tree head")
	}
}

func TestAnUnreadableBitcoinAttestationFailsTheReceipt(t *testing.T) {
	e := readRealExport(t, "real-log-run-2026-11-16-upgraded-export.json")
	digest, _ := hex.DecodeString(e.Intervals[0].Checkpoint.Hash)
	ts, err := attest.ParseOTSTimestamp(digest, e.Intervals[0].Timestamps[0].Receipt)
	if err != nil {
		t.Fatal(err)
	}
	var corrupt func(n *attest.OTSTimestamp)
	corrupt = func(n *attest.OTSTimestamp) {
		for i := range n.Attestations {
			if n.Attestations[i].Tag == attest.OTSTagBitcoin {
				n.Attestations[i].Payload = append(n.Attestations[i].Payload, 0xff)
			}
		}
		for _, op := range n.Ops {
			corrupt(op.Next)
		}
	}
	corrupt(ts)
	e.Intervals[0].Timestamps[0].Receipt = ts.Serialize()
	got := checkIntervalTimestamps(t.Context(), e.Intervals[0], nil)
	if got.Status != StatusFailed || !strings.Contains(got.Detail, "does not read as a block") {
		t.Fatalf("an unreadable attestation gave %s: %s; it must fail, not wait as pending", got.Status, got.Detail)
	}
}

func TestRunsWithEventsAfterAnchoringAreNamed(t *testing.T) {
	e := readRealExport(t, "real-log-run-2026-11-16-upgraded-export.json")
	if note := eventsAfterAnchoringNote(e); note != "" {
		t.Fatalf("an export with no late events gave a note: %s", note)
	}
	for i := range e.Intervals {
		if len(e.Intervals[i].Executions) > 0 {
			e.Intervals[i].Executions[0].EventsAfterAnchoring = 2
			break
		}
	}
	rep := run(t, e, runOptions{Offline: true, TrustedKeys: []string{realLogKey}})
	found := false
	for _, u := range rep.Structural.Unverified {
		found = found || strings.Contains(u, "1 agent run in checkpoints [2] received 2 events after their hour was anchored")
	}
	if !found {
		t.Fatalf("the report does not name the run with late events: %v", rep.Structural.Unverified)
	}
}
