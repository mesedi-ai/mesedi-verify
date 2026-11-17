package main

// When each hour was published (the outside review of 2026-11-15): comparing the
// time the log recorded an entry with the hour its checkpoint covers.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/mesedi-ai/mesedi/backend/attest"
)

// addTimeFromLog asks the log when it recorded an entry a stored proof
// has already verified. The proof stays the verdict: if the log cannot be
// asked, or its answer does not match the proof, the check stays
// verified and says that its time was not checked.
func addTimeFromLog(
	ctx context.Context, client *rekorClient, iv attest.ExportedInterval, check *LogEntryCheck,
) {
	recorded, integrated, err := client.lookup(ctx, iv.LogEntryID)
	if err != nil {
		check.Detail += ". When it was published was not checked, because asking the log " +
			"for its time failed: " + err.Error()
		return
	}
	sum := sha256.Sum256([]byte(iv.LeafPreimage))
	if !strings.EqualFold(recorded, hex.EncodeToString(sum[:])) {
		check.Detail += ". When it was published was not checked, because the log's " +
			"answer for this position does not match the signed proof, so its time was " +
			"not used. The proof, which the log signed, is the stronger evidence"
		return
	}
	check.Integrated = integrated
	applyPublicationTime(check, integrated, iv)
}

// applyPublicationTime compares when the log recorded an entry with the
// hour its checkpoint covers. WHEN, not only WHERE: until 2026-11-16 the
// log's time was fetched and never compared, so a history made up and
// anchored today verified clean (the outside review of 2026-11-15).
func applyPublicationTime(check *LogEntryCheck, integrated time.Time, iv attest.ExportedInterval) {
	if integrated.IsZero() {
		check.Detail += ". The log gave no time for the entry, so when it was " +
			"published was not checked"
		return
	}
	check.TimeChecked = true
	if integrated.Before(iv.Checkpoint.IntervalStart) {
		check.Status = StatusFailed
		check.Detail = fmt.Sprintf("the log recorded this entry at %s, before the hour it "+
			"covers began (%s). No honest chain can publish an hour before it happens",
			integrated.Format(time.RFC3339), iv.Checkpoint.IntervalStart.UTC().Format(time.RFC3339))
		return
	}
	// Every hour's delay is shown, not only the late ones: a delay under
	// the "late" point used to be silent, which hid an hour published 1
	// hour 41 minutes after it ended (the outside review's round 2,
	// 17 November 2026; owner decision the same day).
	after := integrated.Sub(iv.Checkpoint.IntervalEnd)
	if after < 0 {
		after = 0
	}
	check.PublishedAfter = after
	if after > lateAfter {
		check.LateBy = after
		check.Detail += fmt.Sprintf(", but published %s after this hour ended. A late "+
			"anchor proves the record existed when it was published, not when its hour "+
			"ended", humanDuration(after))
	} else {
		check.Detail += fmt.Sprintf(", published %s after this hour ended", humanDuration(after))
	}
	if maxLate > 0 && after > maxLate {
		check.TooLate = true
		check.Detail += fmt.Sprintf(". That is more than %s, the most this run was told to "+
			"accept (--max-late)", humanDuration(maxLate))
	}
}

// When an hour counts as late, and the most lateness a run accepts. Both
// are the auditor's policy, set with --late-after and --max-late (owner
// decision, 17 November 2026). The defaults keep what the report did
// before: late after 2 hours, and no maximum, because a caught-up hour
// after an outage is published late by design, and it is honestly what
// it says it is.
var (
	lateAfter = lateAnchorTolerance
	maxLate   time.Duration // zero: no maximum
)

// humanDuration renders a delay for a reader: minutes under an hour,
// hours and minutes under two days, whole days after that.
func humanDuration(d time.Duration) string {
	unit := func(n int, one string) string {
		if n == 1 {
			return "1 " + one
		}
		return fmt.Sprintf("%d %ss", n, one)
	}
	switch {
	case d < time.Minute:
		return "under a minute"
	case d < time.Hour:
		return unit(int(d.Minutes()), "minute")
	case d < 48*time.Hour:
		out := unit(int(d.Hours()), "hour")
		if m := int(d.Minutes()) % 60; m > 0 {
			out += " " + unit(m, "minute")
		}
		return out
	}
	return unit(int(d.Hours())/24, "day")
}

// publicationTimingNotes returns the sentence added to the log summary when
// any checkpoint was published late, and the caveat for checkpoints that
// were verified offline, where no publication time is available (added
// 2026-11-16, the outside review of 2026-11-15).
func publicationTimingNotes(entries []LogEntryCheck, offline bool) (lateNote, timeCaveat string) {
	var late, unchecked []uint64
	for _, e := range entries {
		if e.LateBy > 0 {
			late = append(late, e.Seq)
		}
		if e.verified() && !e.TimeChecked {
			unchecked = append(unchecked, e.Seq)
		}
	}
	if len(late) > 0 {
		lateNote = fmt.Sprintf(" Checkpoints %v were published more than %s after "+
			"their hour ended; each says how late above. A late anchor proves the record "+
			"existed when it was published, not when its hour ended.",
			late, humanDuration(lateAfter))
	}
	switch {
	case len(unchecked) == 0:
	case offline:
		timeCaveat = "When each checkpoint was published was NOT checked for the ones " +
			"verified offline: an inclusion proof carries no time. Run again without " +
			"--offline to compare each hour with when the log recorded it."
	default:
		timeCaveat = fmt.Sprintf("When checkpoints %v were published was NOT checked; "+
			"each line above says why.", unchecked)
	}
	return lateNote, timeCaveat
}
