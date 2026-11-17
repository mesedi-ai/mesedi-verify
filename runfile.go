package main

// Opening single agent runs (--run), the check of one run's reports,
// chain and signatures against the hourly export (owner decision, 17
// November 2026). The checking itself is attest.VerifyRunExport, shared
// with the backend's own tests; this file reads the files and keys and
// folds the result into the one verdict.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/mesedi-ai/mesedi/backend/attest"
)

// reportKeyFlags collects repeated --report-key key_id=PUBLIC flags,
// where PUBLIC is a base64 Ed25519 public key or a file holding one.
type reportKeyFlags []string

func (k *reportKeyFlags) String() string     { return strings.Join(*k, ",") }
func (k *reportKeyFlags) Set(v string) error { *k = append(*k, v); return nil }

// parseReportKeys reads --report-key values into keys by id.
func parseReportKeys(values []string) (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	for _, v := range values {
		id, pub, ok := strings.Cut(v, "=")
		id, pub = strings.TrimSpace(id), strings.TrimSpace(pub)
		if !ok || id == "" || pub == "" {
			return nil, fmt.Errorf("--report-key %q: want key_id=BASE64_PUBLIC_KEY or key_id=FILE", v)
		}
		if b, err := os.ReadFile(pub); err == nil {
			pub = strings.TrimSpace(string(b))
		}
		raw, err := base64.StdEncoding.DecodeString(pub)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("--report-key %s: not a base64 Ed25519 public key (32 bytes)", id)
		}
		out[id] = ed25519.PublicKey(raw)
	}
	return out, nil
}

// readRunFile reads one single-run file.
func readRunFile(path string) (attest.RunExport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return attest.RunExport{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var r attest.RunExport
	if err := json.Unmarshal(raw, &r); err != nil {
		return attest.RunExport{}, fmt.Errorf("%s is not a single-run file: %w", path, err)
	}
	return r, nil
}

// anchoredRootFor finds the digest the hourly export anchored for a run.
func anchoredRootFor(export attest.ChainExport, executionID string) string {
	for _, iv := range export.Intervals {
		for _, x := range iv.Executions {
			if x.ExecutionID == executionID {
				return x.DigestRoot
			}
		}
	}
	return ""
}

// checkRuns checks every --run file against the hourly export. Keys
// from --report-key are used when given; otherwise each file's own copy,
// and the result says so.
func checkRuns(export attest.ChainExport, runs []attest.RunExport, readerKeys map[string]ed25519.PublicKey) []attest.RunVerification {
	out := make([]attest.RunVerification, 0, len(runs))
	for _, r := range runs {
		keys := attest.RunKeys{Keys: readerKeys, FromReader: true}
		if len(readerKeys) == 0 {
			fileKeys, err := attest.KeysFromRunExport(r)
			if err != nil {
				out = append(out, attest.RunVerification{ExecutionID: r.ExecutionID,
					Failures: []string{"the run file's signing keys are unreadable: " + err.Error()}})
				continue
			}
			keys = fileKeys
		}
		root := ""
		if r.ProjectID == "" || r.ProjectID == export.ProjectID {
			root = anchoredRootFor(export, r.ExecutionID)
		}
		v := attest.VerifyRunExport(r, root, keys)
		if r.ProjectID != "" && r.ProjectID != export.ProjectID {
			v.Failures = append(v.Failures, fmt.Sprintf("the run file is for project %s, the hourly file for %s",
				r.ProjectID, export.ProjectID))
		}
		out = append(out, v)
	}
	return out
}

// runReasons gives each opened run's failures and gaps, named by run,
// for the one verdict.
func runReasons(runs []attest.RunVerification) (failures, gaps []string) {
	for _, v := range runs {
		for _, f := range v.Failures {
			failures = append(failures, fmt.Sprintf("in run %s, %s", v.ExecutionID, f))
		}
		for _, g := range v.Gaps {
			gaps = append(gaps, fmt.Sprintf("in run %s, %s", v.ExecutionID, g))
		}
	}
	return failures, gaps
}

// reportChainSummary counts the runs in the hourly export by Mesedi's
// recorded chain verdict, or says nothing when none carries one.
func reportChainSummary(export attest.ChainExport) string {
	counts := map[string]int{}
	var broken []string
	for _, iv := range export.Intervals {
		for _, x := range iv.Executions {
			if x.ReportChain == "" {
				continue
			}
			counts[x.ReportChain]++
			if x.ReportChain == "broken" {
				broken = append(broken, x.ExecutionID)
			}
		}
	}
	if len(counts) == 0 {
		return ""
	}
	s := fmt.Sprintf("Report chains as Mesedi recorded them: %d signed, %d chained, %d unchained, %d broken.",
		counts["signed"], counts["chained"], counts["unchained"], counts["broken"])
	if len(broken) > 0 {
		s += fmt.Sprintf(" Broken: %s.", strings.Join(broken, ", "))
	}
	return s + " These are Mesedi's statements; open a run with --run to check one yourself."
}
