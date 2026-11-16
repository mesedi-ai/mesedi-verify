package main

// Fixes of 2026-11-16 (the outside review of 2026-11-15).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mesedi-ai/mesedi/backend/attest"
)

func timedInterval(seq uint64, entryID string, start time.Time) attest.ExportedInterval {
	iv := anchored(seq, testHash, entryID)
	iv.Checkpoint.IntervalStart = start
	iv.Checkpoint.IntervalEnd = start.Add(time.Hour)
	return iv
}

func timedEntry(t *testing.T, integrated time.Time) map[string]any {
	_, logValue := leafFor(testHash)
	e := map[string]any{"body": rekorBody(t, "hashedrekord", "sha256", logValue), "logIndex": 7}
	if !integrated.IsZero() {
		e["integratedTime"] = integrated.Unix()
	}
	return e
}

var hourStart = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

// E6: a log that cannot be asked is not a log that disagrees.
func TestUnreachableLogIsUnverifiableNotFailed(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("maintenance"))
	}))
	t.Cleanup(down.Close)
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()

	for name, url := range map[string]string{"503": down.URL, "connection refused": closedURL} {
		export := attest.ChainExport{Intervals: []attest.ExportedInterval{timedInterval(1, "7", hourStart)}}
		got := resolveLogEntries(export, url, false)[0]
		if got.Status != StatusUnverifiable {
			t.Errorf("%s: status %q, want %q (detail: %s)", name, got.Status, StatusUnverifiable, got.Detail)
		}
		if !strings.Contains(got.Detail, "not a finding against the record") {
			t.Errorf("%s: detail does not say this is not a finding: %s", name, got.Detail)
		}
	}
}

func TestMissingEntryIsStillAFailure(t *testing.T) {
	srv := fakeRekor(t, map[string]map[string]any{})
	export := attest.ChainExport{Intervals: []attest.ExportedInterval{timedInterval(1, "7", hourStart)}}
	if got := resolveLogEntries(export, srv.URL, false)[0]; got.Status != StatusFailed {
		t.Fatalf("a log with no such entry gave %q; it must fail", got.Status)
	}
}

// E5: when, not only where.
func TestOnTimeAnchorVerifiesWithoutANote(t *testing.T) {
	srv := fakeRekor(t, map[string]map[string]any{"7": timedEntry(t, hourStart.Add(65*time.Minute))})
	got := resolveLogEntries(attest.ChainExport{Intervals: []attest.ExportedInterval{timedInterval(1, "7", hourStart)}}, srv.URL, false)[0]
	if !got.verified() || got.LateBy != 0 || strings.Contains(got.Detail, "after this hour ended") {
		t.Fatalf("an on-time anchor: status %q, late %s, detail %s", got.Status, got.LateBy, got.Detail)
	}
}

func TestLateAnchorVerifiesAndSaysHowLate(t *testing.T) {
	srv := fakeRekor(t, map[string]map[string]any{"7": timedEntry(t, hourStart.Add(6*time.Hour))})
	got := resolveLogEntries(attest.ChainExport{Intervals: []attest.ExportedInterval{timedInterval(1, "7", hourStart)}}, srv.URL, false)[0]
	if !got.verified() {
		t.Fatalf("a late anchor must still verify (catch-up after downtime): %s", got.Detail)
	}
	if got.LateBy != 5*time.Hour || !strings.Contains(got.Detail, "published 5 hours after this hour ended") {
		t.Fatalf("late by %s, detail %q", got.LateBy, got.Detail)
	}
	note, _ := publicationTimingNotes([]LogEntryCheck{got}, false)
	if !strings.Contains(note, "Checkpoints [1] were published more than 2 hours after their hour ended") {
		t.Errorf("summary note = %q", note)
	}
}

func TestAnchorRecordedBeforeItsHourFails(t *testing.T) {
	srv := fakeRekor(t, map[string]map[string]any{"7": timedEntry(t, hourStart.Add(-time.Hour))})
	got := resolveLogEntries(attest.ChainExport{Intervals: []attest.ExportedInterval{timedInterval(1, "7", hourStart)}}, srv.URL, false)[0]
	if got.Status != StatusFailed || !strings.Contains(got.Detail, "before the hour it covers began") {
		t.Fatalf("status %q, detail %q", got.Status, got.Detail)
	}
}

func TestAnchorWithoutALogTimeSaysSo(t *testing.T) {
	srv := fakeRekor(t, map[string]map[string]any{"7": timedEntry(t, time.Time{})})
	got := resolveLogEntries(attest.ChainExport{Intervals: []attest.ExportedInterval{timedInterval(1, "7", hourStart)}}, srv.URL, false)[0]
	if !got.verified() || !strings.Contains(got.Detail, "gave no time") {
		t.Fatalf("status %q, detail %q", got.Status, got.Detail)
	}
}

func TestOfflineVerificationCarriesATimeCaveat(t *testing.T) {
	offlineOK := LogEntryCheck{Seq: 3, Status: StatusVerified, Method: MethodOfflineProof}
	_, caveat := publicationTimingNotes([]LogEntryCheck{offlineOK}, true)
	if !strings.Contains(caveat, "inclusion proof carries no time") {
		t.Fatalf("caveat = %q", caveat)
	}
	timed := LogEntryCheck{Seq: 3, Status: StatusVerified, Method: MethodLogLookup, TimeChecked: true}
	if _, c := publicationTimingNotes([]LogEntryCheck{timed}, false); c != "" {
		t.Errorf("a checkpoint whose time was checked produced a caveat: %q", c)
	}
}

// An online run must never tell the reader to run online. Before the fix
// of 2026-11-16 it did, for every checkpoint with a stored proof.
func TestOnlineRunNamesTheCheckpointsWhoseTimeWasNotChecked(t *testing.T) {
	untimed := LogEntryCheck{Seq: 4, Status: StatusVerified, Method: MethodOfflineProof}
	_, caveat := publicationTimingNotes([]LogEntryCheck{untimed}, false)
	if !strings.Contains(caveat, "checkpoints [4] were published was NOT checked") {
		t.Fatalf("caveat = %q", caveat)
	}
	if strings.Contains(caveat, "without --offline") {
		t.Errorf("an online run told the reader to run without --offline: %q", caveat)
	}
}

// A stored proof decides WHERE; an online run still asks the log WHEN.
func proofVerified(seq uint64) LogEntryCheck {
	return LogEntryCheck{Seq: seq, Status: StatusVerified, Method: MethodOfflineProof,
		Detail: "verified offline against the log's signed tree head"}
}

func TestProofVerifiedCheckpointGetsItsTimeFromTheLog(t *testing.T) {
	cases := map[string]struct {
		at         time.Time
		wantStatus string
		wantLate   time.Duration
		wantText   string
	}{
		"on time":         {hourStart.Add(65 * time.Minute), StatusVerified, 0, ""},
		"late":            {hourStart.Add(6 * time.Hour), StatusVerified, 5 * time.Hour, "published 5 hours after this hour ended"},
		"before its hour": {hourStart.Add(-time.Hour), StatusFailed, 0, "before the hour it covers began"},
	}
	for name, tc := range cases {
		srv := fakeRekor(t, map[string]map[string]any{"7": timedEntry(t, tc.at)})
		iv := timedInterval(1, "7", hourStart)
		got := proofVerified(1)
		addTimeFromLog(t.Context(), newRekorClient(srv.URL), iv, &got)
		if got.Status != tc.wantStatus || got.LateBy != tc.wantLate || !got.TimeChecked ||
			!strings.Contains(got.Detail, tc.wantText) {
			t.Errorf("%s: status %q, late %s, timeChecked %v, detail %q",
				name, got.Status, got.LateBy, got.TimeChecked, got.Detail)
		}
	}
}

func TestProofVerifiedCheckpointStaysVerifiedWhenTheLogCannotGiveATime(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(down.Close)
	other := fakeRekor(t, map[string]map[string]any{"7": func() map[string]any {
		_, v := leafFor("someone else's checkpoint")
		return map[string]any{"body": rekorBody(t, "hashedrekord", "sha256", v), "logIndex": 7,
			"integratedTime": hourStart.Add(-time.Hour).Unix()}
	}()})
	for name, url := range map[string]string{"log down": down.URL, "answer disagrees with proof": other.URL} {
		got := proofVerified(1)
		addTimeFromLog(t.Context(), newRekorClient(url), timedInterval(1, "7", hourStart), &got)
		if got.Status != StatusVerified || got.TimeChecked ||
			!strings.Contains(got.Detail, "When it was published was not checked") {
			t.Errorf("%s: status %q, timeChecked %v, detail %q", name, got.Status, got.TimeChecked, got.Detail)
		}
	}
}

// E23: offline edge cases.
func TestOfflineProofNamingNoLogFallsThrough(t *testing.T) {
	proof := proofEnvelope(t, "", rekorEntryBodyFor(testPreimage), map[string]any{
		"LogIndex": 1, "TreeSize": 2, "RootHash": strings.Repeat("dd", 32), "Hashes": []string{}, "Checkpoint": "x",
	})
	res := verifyAnchorOffline(intervalWithProof(testPreimage, proof))
	if res.Decided || !strings.Contains(res.Note, "names no log") {
		t.Fatalf("an offline proof with no log id was decided (%+v); it must fall through with a note", res)
	}
}

func TestOfflineEntryOfAnotherKindFails(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{"apiVersion": "0.0.1", "kind": "intoto",
		"spec": map[string]any{"data": map[string]any{"hash": map[string]any{"algorithm": "sha256", "value": leafHashOf(testPreimage)}}}})
	res, ok := bindEntryToLeaf(base64.StdEncoding.EncodeToString(raw), testPreimage)
	if ok || !res.Decided || res.Status != StatusFailed || !strings.Contains(res.Detail, "not a hashedrekord") {
		t.Fatalf("an entry of another kind was accepted offline: ok=%v %+v", ok, res)
	}
}

// The wiring: resolveOne must ask the log for the time after a stored
// proof verifies, online only.
func TestOnlineRunChecksTheTimeOfAProofVerifiedCheckpoint(t *testing.T) {
	real := checkStoredProof
	checkStoredProof = func(attest.ExportedInterval) offlineResult {
		return offlineResult{Decided: true, Status: StatusVerified, Detail: "verified offline"}
	}
	t.Cleanup(func() { checkStoredProof = real })

	srv := fakeRekor(t, map[string]map[string]any{"7": timedEntry(t, hourStart.Add(6*time.Hour))})
	export := attest.ChainExport{Intervals: []attest.ExportedInterval{timedInterval(1, "7", hourStart)}}
	got := resolveLogEntries(export, srv.URL, false)[0]
	if got.Method != MethodOfflineProof || !got.TimeChecked || got.LateBy != 5*time.Hour {
		t.Fatalf("online, proof-verified: method %q, timeChecked %v, late %s, detail %q",
			got.Method, got.TimeChecked, got.LateBy, got.Detail)
	}
	if off := resolveLogEntries(export, srv.URL, true)[0]; off.TimeChecked {
		t.Fatal("an offline run reported a checked publication time")
	}
}

// The underlying network error stays reachable through Unwrap, so a
// caller can still ask what went wrong (a timeout, a refused connection).
func TestLogUnreachableUnwrapsToTheNetworkError(t *testing.T) {
	cause := context.DeadlineExceeded
	err := error(logUnreachable{err: fmt.Errorf("asking the log: %w", cause)})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("errors.Is lost the cause through Unwrap: %v", err)
	}
	var u logUnreachable
	if !errors.As(err, &u) || u.Unwrap() == nil {
		t.Fatalf("errors.As or Unwrap failed: %v", err)
	}
}
