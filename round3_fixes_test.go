package main

// Fixes from the outside review's round 3 (17 November 2026), each the
// owner's decision of the same day: a maximum lateness that cannot be
// applied is reported (M1), INCOMPLETE has its own exit code (L1), and a
// maximum below the late point lists its hours as late (L3).

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// L3: an hour past the maximum is always also listed as late, even when
// the maximum is below the "late" point. Until then the run was
// INCOMPLETE with an empty late list.
func TestAnHourPastTheMaximumIsAlsoListedAsLate(t *testing.T) {
	defer func(a, m time.Duration) { lateAfter, maxLate = a, m }(lateAfter, maxLate)
	lateAfter, maxLate = 2*time.Hour, 30*time.Minute

	iv := timedInterval(1, "7", hourStart)
	got := LogEntryCheck{Status: StatusVerified}
	applyPublicationTime(&got, iv.Checkpoint.IntervalEnd.Add(time.Hour), iv)
	if !got.TooLate || got.LateBy != time.Hour || !strings.Contains(got.Detail, "but published 1 hour after") {
		t.Fatalf("too late %v, late by %s, detail %q", got.TooLate, got.LateBy, got.Detail)
	}
	if late := lateSeqs([]LogEntryCheck{got}); len(late) != 1 {
		t.Fatalf("the hour past the maximum is missing from the late list")
	}
	note, _ := publicationTimingNotes([]LogEntryCheck{got}, false)
	if !strings.Contains(note, "more than 30 minutes after") {
		t.Errorf("the late note names the wrong threshold: %q", note)
	}
	// Under the maximum and the late point: neither.
	onTime := LogEntryCheck{Status: StatusVerified}
	applyPublicationTime(&onTime, iv.Checkpoint.IntervalEnd.Add(10*time.Minute), iv)
	if onTime.TooLate || onTime.LateBy != 0 {
		t.Errorf("an on-time hour was marked late: %+v", onTime)
	}
}

// M1: with --max-late, an hour whose publication time is unknown makes
// the run INCOMPLETE, unless the auditor accepts unknown times.
func TestAMaximumThatCannotBeAppliedIsNeverReportedAsApplied(t *testing.T) {
	defer func(m time.Duration, a bool) { maxLate, acceptUnknownTime = m, a }(maxLate, acceptUnknownTime)
	e := readRealExport(t, "real-log-run-2026-11-16-upgraded-export.json")

	maxLate, acceptUnknownTime = 0, false
	if rep := run(t, e, runOptions{Offline: true, TrustedKeys: []string{realLogKey}}); rep.Verdict != verdictVerified {
		t.Fatalf("control: offline run with no maximum is %s: %v", rep.Verdict, rep.VerdictReasons)
	}

	maxLate = time.Minute
	rep := run(t, e, runOptions{Offline: true, TrustedKeys: []string{realLogKey}})
	if rep.Verdict != verdictIncomplete || rep.OK {
		t.Fatalf("offline run with --max-late is %s; want INCOMPLETE", rep.Verdict)
	}
	if !strings.Contains(strings.Join(rep.VerdictReasons, " "), "could not be compared with --max-late") ||
		!strings.Contains(strings.Join(rep.VerdictReasons, " "), "this run was offline") {
		t.Errorf("reasons do not say why: %v", rep.VerdictReasons)
	}
	if len(rep.Notices) != 1 || !strings.Contains(rep.Notices[0], "--max-late cannot be checked offline") {
		t.Errorf("no notice at the top: %v", rep.Notices)
	}

	acceptUnknownTime = true
	rep = run(t, e, runOptions{Offline: true, TrustedKeys: []string{realLogKey}})
	if rep.Verdict != verdictVerified {
		t.Fatalf("with --accept-unknown-time the run is %s: %v", rep.Verdict, rep.VerdictReasons)
	}
	if !strings.Contains(strings.Join(rep.Structural.Unverified, " "), "--max-late was NOT applied to checkpoints") {
		t.Errorf("accepted unknown times carry no caveat: %v", rep.Structural.Unverified)
	}
}

func TestExitCodes(t *testing.T) {
	for _, c := range []struct {
		verdict string
		single  bool
		want    int
	}{
		{verdictVerified, false, 0}, {verdictFailed, false, 1}, {verdictIncomplete, false, 3},
		{verdictVerified, true, 0}, {verdictFailed, true, 1}, {verdictIncomplete, true, 1},
	} {
		if got := exitCode(c.verdict, c.single); got != c.want {
			t.Errorf("%s, single %v: exit %d, want %d", c.verdict, c.single, got, c.want)
		}
	}
}

// The reviewer's own reproduction, against the built binary: the exit
// code and the RESULT line agree with the decision.
func TestTheReviewersM1ReproductionAgainstTheBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binary")
	}
	bin := filepath.Join(t.TempDir(), "mesedi-verify")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	export := filepath.Join("testdata", "real-log-run-2026-11-16-upgraded-export.json")
	for _, c := range []struct {
		args []string
		exit int
		says string
	}{
		{[]string{"--offline", "--trusted-key", realLogKey, export}, 0, "RESULT: every check that ran passed"},
		{[]string{"--offline", "--trusted-key", realLogKey, "--max-late", "1m", export}, 3, "RESULT: INCOMPLETE"},
		{[]string{"--offline", "--trusted-key", realLogKey, "--max-late", "1m", "--single-failure-code", export}, 1, "RESULT: INCOMPLETE"},
		{[]string{"--offline", "--trusted-key", realLogKey, "--max-late", "1m", "--accept-unknown-time", export}, 0, "RESULT: every check that ran passed"},
		{[]string{"--offline", "no-such-file.json"}, 2, ""},
	} {
		cmd := exec.Command(bin, c.args...)
		out, _ := cmd.CombinedOutput()
		code := cmd.ProcessState.ExitCode()
		if code != c.exit || !strings.Contains(string(out), c.says) {
			t.Errorf("%v: exit %d, want %d; output lacks %q:\n%s", c.args, code, c.exit, c.says, out)
		}
	}
}
