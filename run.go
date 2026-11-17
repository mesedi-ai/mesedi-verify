package main

// verifyExport runs every check on one export and returns the report,
// verdict included. It is main without the flags and the printing, so a
// test can run the whole verifier on a real or forged file and assert
// what every output says (the outside review's round 2, 17 November 2026).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/mesedi-ai/mesedi/backend/attest"
)

// runOptions are the flags that change what a run checks.
type runOptions struct {
	Offline     bool
	RekorURL    string
	BitcoinAPI  string
	TrustedKeys []string
	Version     string
}

func verifyExport(raw []byte, export attest.ChainExport, o runOptions) (report, error) {
	sum := sha256.Sum256(raw)

	rep := report{
		Format:       export.Format,
		ProjectID:    export.ProjectID,
		ExportSHA256: hex.EncodeToString(sum[:]),

		GeneratedAt: export.GeneratedAt,
		VerifiedAt:  time.Now().UTC(),
		Verifier:    o.Version,
		Online:      !o.Offline,
		Structural:  attest.VerifyChainExport(export),
	}

	// A limit on the REPORT rather than on the chain, and one the reader
	// cannot discover for themselves. If the verifier's own source is not
	// identifiable, "rebuild this and reproduce the result" is an
	// instruction nobody can follow, and the report should say so instead
	// of implying an auditability it does not have.
	// Runs that received events after their hour was anchored. The events
	// are kept, but the anchored digest does not cover them, and until 17
	// November 2026 only the dashboard said so; the auditor holding the
	// export was told the set of runs was complete (the outside review's
	// round 2).
	if note := eventsAfterAnchoringNote(export); note != "" {
		rep.Structural.Unverified = append(rep.Structural.Unverified, note)
	}

	if !versionIsReproducible(o.Version) {
		rep.Structural.Unverified = append(rep.Structural.Unverified,
			"This report was produced by a verifier build that cannot be tied to a "+
				"published commit ("+o.Version+"). The result above is therefore not "+
				"independently reproducible. Use a released binary, or one built from a "+
				"clean checkout, for anything that will be relied on.")
	}

	{
		// Run for both modes. An offline run now checks every stored
		// inclusion proof rather than skipping the anchors entirely, so
		// the old "offline shows only internal consistency" branch would
		// understate what happened, which is a falsehood in the safe
		// direction, but still a falsehood in a report whose job is to
		// say precisely what was established.
		rep.LogEntries = resolveLogEntries(export, o.RekorURL, o.Offline)

		// Who signed each entry (the outside review of 2026-11-15). Before the verdict below, so
		// a direct anchor signed by the wrong key fails the report.
		trusted, err := loadTrustedKeys(o.TrustedKeys)
		if err != nil {
			return report{}, err
		}
		checkSigners(export, rep.LogEntries, trusted)

		// A failed entry is a finding. An unverifiable one is not, but
		// it still means this report does not establish what it set out
		// to, so neither may leave rep.OK true. Exit 0 on a chain nobody
		// can check would be the single most misleading thing this tool
		// could do.
		var unverifiable []uint64
		for _, e := range rep.LogEntries {
			if e.unverifiable() {
				unverifiable = append(unverifiable, e.Seq)
			}
		}
		if len(unverifiable) > 0 {
			// No cause is asserted here. This used to name one, "anchored
			// before the leaf preimage was retained", which was the only
			// cause that existed when it was written and is now one of
			// several: a mock ledger, a missing preimage, or an offline run
			// against a checkpoint that carries no inclusion proof. Printing
			// a confident wrong reason next to a correct verdict is how a
			// reader stops believing the correct parts, so the reasons stay
			// where they are individually true, per checkpoint, above.
			rep.Structural.Unverified = append(rep.Structural.Unverified, fmt.Sprintf(
				"Checkpoints %v could NOT be checked. That is not a finding against "+
					"the record. Nothing here says they are wrong, but nothing here "+
					"says they are right either. The reason differs per checkpoint and "+
					"is given against each one in the PUBLIC TRANSPARENCY LOG section.",
				unverifiable))
		}
		// Replace the library's standing caveat, which is written for the
		// offline case, with one that describes what THIS run actually
		// did.
		//
		// The replacement must be driven by the counts, and it was not.
		// An earlier version substituted "Each checkpoint hash was
		// confirmed PRESENT in the public log" whenever the run was
		// online, regardless of whether a single entry had been resolved
		//, so a run in which nothing could be checked printed a claim of
		// verification directly above a RESULT line saying the opposite.
		// A false claim of verification inside the section whose entire
		// job is to prevent overclaiming is the worst place in the report
		// for one, and it survived because the substitution was written
		// at a moment when every run happened to resolve everything.
		// What was established goes to the results; what was not stays in
		// the caveats. Same entries drive both, so they cannot disagree.
		rep.LogSummary = logConfirmation(rep.LogEntries)
		lateNote, timeCaveat := publicationTimingNotes(rep.LogEntries, o.Offline)
		rep.LogSummary += lateNote
		signedBy, signerCaveat := signerNotes(rep.LogEntries)
		rep.LogSummary += signedBy
		if signerCaveat != "" {
			rep.Structural.Unverified = append(rep.Structural.Unverified, signerCaveat)
		}
		if timeCaveat != "" {
			rep.Structural.Unverified = append(rep.Structural.Unverified, timeCaveat)
		}
		rep.Structural.Unverified = replacePrefix(
			rep.Structural.Unverified,
			"Transparency log entries were NOT resolved",
			logResolutionCaveat(rep.LogEntries, o.Offline))

		// An anchor proof that was present and unusable must not vanish.
		// Reported separately from the verdict, because it describes what
		// was OFFERED, and the verdict describes what was established.
		for _, e := range rep.LogEntries {
			if e.ProofNote != "" {
				rep.Structural.Unverified = append(rep.Structural.Unverified,
					fmt.Sprintf("Checkpoint %d: %s.", e.Seq, e.ProofNote))
			}
		}

		// Did the log only grow, or is it a different log wearing the
		// same name? Nothing above can tell, because every check above
		// is satisfied by a rewritten tree.
		//
		// A broken growth proof FAILS the report: it is a positive
		// finding about the log, not a gap in our evidence. An absent
		// one does not, and lands in the caveats instead.
		growth := checkLogGrowth(export.Intervals)
		rep.LogGrowth = growthSummary(growth)

		// The second anchor. Offline, no block explorer is asked.
		var src blockSource
		if !o.Offline {
			src = newEsplora(o.BitcoinAPI)
		}
		rep.Bitcoin = checkTimestamps(context.Background(), export, src)
		btcEstablished, btcCaveat, _ := timestampNotes(rep.Bitcoin, o.Offline)
		rep.BitcoinSummary = strings.TrimSpace(btcEstablished)
		if btcCaveat != "" {
			rep.Structural.Unverified = append(rep.Structural.Unverified, btcCaveat)
		}

		// The caveat above says the log's history was not checked. Once
		// every step IS checked that sentence becomes false, and a false
		// sentence in the section whose whole job is honesty is the
		// worst place in the report for one. Narrow it to what actually
		// remains: the split view, which no consistency proof addresses
		// and which needs witnesses Sigstore does not yet publish.
		if growth.Proven > 0 && growth.Unproven == 0 && len(growth.Failures) == 0 {
			rep.Structural.Unverified = replacePrefix(
				rep.Structural.Unverified,
				"Sigstore's signature was checked, but not the log's history",
				"Sigstore's signature and its growth were both checked, but not whether "+
					"it showed the same log to everyone. A log that served one version of "+
					"itself to us and another to somebody else would satisfy everything "+
					"here. Catching that needs independent observers co-signing the same "+
					"summaries, and Sigstore's summaries today carry only its own "+
					"signature. This guards against Sigstore, not against Mesedi.")
		}
		if len(growth.Failures) > 0 {
			rep.LogGrowthFailed = true
		}
		if growth.Unproven > 0 {
			rep.Structural.Unverified = append(rep.Structural.Unverified,
				unprovenGrowthNote(growth.Unproven))
		}
	}

	// One verdict, decided once, for every output and the exit code.
	v := decideVerdict(rep)
	rep.Verdict = v.Kind
	rep.VerdictReasons = append(append([]string(nil), v.Failures...), v.Gaps...)
	rep.OK = v.Kind == verdictVerified
	return rep, nil
}

// eventsAfterAnchoringNote says which runs received events after their
// hour was anchored, or nothing when none did.
func eventsAfterAnchoringNote(export attest.ChainExport) string {
	runs, events := 0, 0
	var seqs []uint64
	for _, iv := range export.Intervals {
		hit := false
		for _, x := range iv.Executions {
			if x.EventsAfterAnchoring > 0 {
				runs++
				events += x.EventsAfterAnchoring
				hit = true
			}
		}
		if hit {
			seqs = append(seqs, iv.Checkpoint.Seq)
		}
	}
	if runs == 0 {
		return ""
	}
	return fmt.Sprintf("%s in checkpoints %v received %s after their hour was "+
		"anchored. Those events are kept, but the anchor does not cover them, so this "+
		"report says nothing about them.",
		countOf(runs, "agent run", "agent runs"), seqs, countOf(events, "event", "events"))
}
