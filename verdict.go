package main

// One verdict for every output (the outside review's round 2, 17 November
// 2026).
//
// Until then the exit code, the JSON "ok", the text RESULT line and the
// PDF verdict were each decided in their own place. A false Bitcoin
// receipt or a broken growth proof failed the exit code and the JSON, but
// the text still ended "every check that ran passed" and the PDF said
// VERIFIED: the outputs disagreed, and the PDF, written for the reader
// who never sees an exit code, said the wrong thing. Every output now
// reads this one function, so they cannot disagree.

import (
	"fmt"
	"strings"
)

const (
	verdictVerified   = "VERIFIED"
	verdictIncomplete = "INCOMPLETE"
	verdictFailed     = "FAILED"
)

// verdict is the run's single result and the reasons for it.
type verdict struct {
	Kind string
	// Failures say why the run FAILED: something was checked and did not
	// hold. Each is one plain sentence.
	Failures []string
	// Gaps say why the run is INCOMPLETE: something that had to be
	// established was not, without anything being found wrong.
	Gaps []string
	// Unchecked is how many checkpoints could not be checked against the
	// public log at all.
	Unchecked int
}

// decideVerdict reads the whole report. FAILED when anything checked did
// not hold: the record's structure, a checkpoint against the public log,
// the log's growth, or a Bitcoin receipt. INCOMPLETE when nothing failed
// but something was not established: a checkpoint that could not be
// checked, or one published later than the run allows. VERIFIED only
// when neither.
func decideVerdict(rep report) verdict {
	var failedSeqs, uncheckedSeqs, tooLate, btcFailed []uint64
	for _, e := range rep.LogEntries {
		switch {
		case e.failed():
			failedSeqs = append(failedSeqs, e.Seq)
		case e.unverifiable():
			uncheckedSeqs = append(uncheckedSeqs, e.Seq)
		}
		if e.TooLate {
			tooLate = append(tooLate, e.Seq)
		}
	}
	for _, b := range rep.Bitcoin {
		if b.Status == StatusFailed {
			btcFailed = append(btcFailed, b.Seq)
		}
	}

	v := verdict{Unchecked: len(uncheckedSeqs)}
	if !rep.Structural.OK {
		v.Failures = append(v.Failures, "the record's own structure does not hold")
	}
	if len(failedSeqs) > 0 {
		v.Failures = append(v.Failures,
			fmt.Sprintf("checkpoints %v did not check out against the public log", failedSeqs))
	}
	if rep.LogGrowthFailed {
		v.Failures = append(v.Failures,
			"the public log did not only grow between the hours this record was published")
	}
	if len(btcFailed) > 0 {
		v.Failures = append(v.Failures,
			fmt.Sprintf("the Bitcoin receipts of checkpoints %v are false", btcFailed))
	}
	if len(uncheckedSeqs) > 0 {
		v.Gaps = append(v.Gaps,
			fmt.Sprintf("checkpoints %v could not be checked against the public log", uncheckedSeqs))
	}
	if len(tooLate) > 0 {
		v.Gaps = append(v.Gaps, fmt.Sprintf("checkpoints %v were published more than %s "+
			"after their hour ended, the most this run was told to accept", tooLate,
			humanDuration(maxLate)))
	}
	// A maximum that could not be applied is never reported as applied
	// (round 3, finding M1): with --max-late set, an hour whose
	// publication time is unknown makes the run INCOMPLETE, unless the
	// auditor accepts unknown times with --accept-unknown-time.
	if unknown := timeUnknownSeqs(rep.LogEntries); maxLate > 0 && len(unknown) > 0 && !acceptUnknownTime {
		why := "the log did not give their time"
		if !rep.Online {
			why = "this run was offline, and an inclusion proof carries no time"
		}
		v.Gaps = append(v.Gaps, fmt.Sprintf("checkpoints %v could not be compared with "+
			"--max-late, because when they were published is not known (%s)", unknown, why))
	}

	// Runs opened with --run add their own findings, named by run.
	runFailures, runGaps := runReasons(rep.Runs)
	v.Failures = append(v.Failures, runFailures...)
	v.Gaps = append(v.Gaps, runGaps...)

	switch {
	case len(v.Failures) > 0:
		v.Kind = verdictFailed
	case len(v.Gaps) > 0:
		v.Kind = verdictIncomplete
	default:
		v.Kind = verdictVerified
	}
	return v
}

// sentence joins reasons into one sentence body: "a, b and c".
func sentence(reasons []string) string {
	switch len(reasons) {
	case 0:
		return ""
	case 1:
		return reasons[0]
	}
	return strings.Join(reasons[:len(reasons)-1], ", ") + " and " + reasons[len(reasons)-1]
}

// upperFirst capitalises a sentence's first letter.
func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// lateSeqs lists the checkpoints published after the "late" point.
func lateSeqs(entries []LogEntryCheck) []uint64 {
	var out []uint64
	for _, e := range entries {
		if e.LateBy > 0 {
			out = append(out, e.Seq)
		}
	}
	return out
}
