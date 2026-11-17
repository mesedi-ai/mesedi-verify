package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mesedi-ai/mesedi/backend/attest"
	"github.com/mesedi-ai/mesedi/backend/attest/events"
)

// signedRun builds a single-run file the way ingest records one, and the
// digest the hour would have anchored for it.
func signedRun(t *testing.T, project, exec string) (attest.RunExport, string, ed25519.PrivateKey) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(nil)
	r := attest.RunExport{Format: attest.RunExportFormatV1, ProjectID: project, ExecutionID: exec,
		ReportChainStatus: "signed",
		SigningKeys:       []attest.RunExportKey{{KeyID: "k1", PublicKey: base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))}}}
	prev := attest.ReportChainGenesis(exec)
	var anchored []*events.Event
	for i := 1; i <= 2; i++ {
		payload := []byte(fmt.Sprintf(`{"tool_name":"t%d"}`, i))
		e := &events.Event{EventID: fmt.Sprintf("e%d", i), ExecutionID: exec, EventType: "tool_call", Sequence: i,
			Timestamp: time.Date(2026, 11, 17, 12, 0, i, 0, time.UTC), Payload: payload, ChainPrev: prev}
		h := attest.ReportChainHash(e, "")
		msg, _ := hex.DecodeString(h)
		sum := sha256.Sum256(payload)
		r.ReportChain = append(r.ReportChain, attest.RunExportLink{EventID: e.EventID, Prev: prev, Hash: h,
			PayloadSHA256: hex.EncodeToString(sum[:]), KeyID: "k1",
			Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))})
		r.Events = append(r.Events, attest.RunExportEvent{EventID: e.EventID, EventType: "tool_call", Sequence: i,
			Timestamp: e.Timestamp, PayloadB64: base64.StdEncoding.EncodeToString(payload)})
		anchored = append(anchored, e)
		prev = h
	}
	// The end the SDK declares when the run finishes, signed over its
	// own message.
	r.ReportChainEnd = &attest.RunExportEnd{Hash: prev, KeyID: "k1",
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, attest.ReportChainEndMessage(exec, prev)))}
	d, err := attest.Compute(exec, anchored)
	if err != nil {
		t.Fatal(err)
	}
	return r, d.Root, priv
}

func hourlyWith(project, exec, root, chain string) attest.ChainExport {
	return attest.ChainExport{ProjectID: project, Intervals: []attest.ExportedInterval{{
		Executions: []attest.ExportedExecution{{ExecutionID: exec, DigestRoot: root, ReportChain: chain}},
	}}}
}

func TestOpeningASignedRun(t *testing.T) {
	r, root, priv := signedRun(t, "p1", "exec-1")
	export := hourlyWith("p1", "exec-1", root, "signed")
	reader := map[string]ed25519.PublicKey{"k1": priv.Public().(ed25519.PublicKey)}

	got := checkRuns(export, []attest.RunExport{r}, reader)
	if len(got) != 1 || got[0].ChainStatus != "signed" || len(got[0].Failures)+len(got[0].Gaps) != 0 {
		t.Fatalf("%+v", got)
	}

	// A different key, as an auditor's own copy would be if Mesedi had
	// swapped the key in the file: every signature fails.
	_, other, _ := ed25519.GenerateKey(nil)
	got = checkRuns(export, []attest.RunExport{r}, map[string]ed25519.PublicKey{"k1": other.Public().(ed25519.PublicKey)})
	if f, _ := runReasons(got); len(f) == 0 || !strings.Contains(f[0], "in run exec-1") {
		t.Fatalf("a wrong key verified: %v", f)
	}

	// The run is not in this hourly file.
	got = checkRuns(hourlyWith("p1", "exec-other", root, ""), []attest.RunExport{r}, reader)
	if _, g := runReasons(got); len(g) == 0 || !strings.Contains(strings.Join(g, " "), "not in the hourly file") {
		t.Fatalf("gaps %v", g)
	}

	// A run file from another project.
	got = checkRuns(hourlyWith("p2", "exec-1", root, ""), []attest.RunExport{r}, reader)
	if f, _ := runReasons(got); !strings.Contains(strings.Join(f, " "), "is for project p1") {
		t.Fatalf("failures %v", f)
	}
}

func TestRunsDecideTheVerdictAndAreShown(t *testing.T) {
	r, root, priv := signedRun(t, "p1", "exec-1")
	export := hourlyWith("p1", "exec-1", root, "signed")
	rep := sampleReport(true, true)
	rep.Runs = checkRuns(export, []attest.RunExport{r}, map[string]ed25519.PublicKey{"k1": priv.Public().(ed25519.PublicKey)})
	rep.ReportChains = reportChainSummary(export)
	if v := decideVerdict(rep); v.Kind != verdictVerified {
		t.Fatalf("an intact signed run gave %s: %v %v", v.Kind, v.Failures, v.Gaps)
	}
	var out bytes.Buffer
	printReport(&out, rep)
	if !strings.Contains(out.String(), "AGENT RUNS") || !strings.Contains(out.String(), "run exec-1: chain signed") ||
		!strings.Contains(out.String(), "1 signed, 0 chained") {
		t.Fatalf("text report:\n%s", out.String())
	}
	doc := buildPDFDoc(rep, "x")
	found := false
	for _, s := range doc.Sections {
		found = found || s.Title == "AGENT RUNS"
	}
	if !found {
		t.Error("the PDF has no AGENT RUNS section")
	}

	r.Events[1].PayloadB64 = base64.StdEncoding.EncodeToString([]byte(`{"tool_name":"forged"}`))
	rep.Runs = checkRuns(export, []attest.RunExport{r}, map[string]ed25519.PublicKey{"k1": priv.Public().(ed25519.PublicKey)})
	if v := decideVerdict(rep); v.Kind != verdictFailed {
		t.Fatalf("a changed report gave %s", v.Kind)
	}
}

func TestParseReportKeys(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	b64 := base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	file := filepath.Join(t.TempDir(), "k.pub")
	if err := os.WriteFile(file, []byte(b64+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := parseReportKeys([]string{"a=" + b64, "b=" + file})
	if err != nil || len(keys) != 2 {
		t.Fatalf("%v %v", keys, err)
	}
	for _, bad := range []string{"novalue", "a=", "a=bm90IGEga2V5"} {
		if _, err := parseReportKeys([]string{bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

func TestReportChainSummaryIsSilentWithoutStatuses(t *testing.T) {
	if s := reportChainSummary(hourlyWith("p", "e", "r", "")); s != "" {
		t.Fatalf("summary %q for an export with no statuses", s)
	}
	s := reportChainSummary(hourlyWith("p", "e9", "r", "broken"))
	if !strings.Contains(s, "1 broken") || !strings.Contains(s, "Broken: e9") {
		t.Fatalf("%q", s)
	}
}

func TestOpenedRunsAreNotCalledUnopened(t *testing.T) {
	e := readRealExport(t, "real-log-run-2026-11-16-upgraded-export.json")
	r, _, priv := signedRun(t, e.ProjectID, "exec-not-in-this-file")
	rep := run(t, e, runOptions{Offline: true, TrustedKeys: []string{realLogKey}, Runs: []attest.RunExport{r},
		ReportKeys: map[string]ed25519.PublicKey{"k1": priv.Public().(ed25519.PublicKey)}})
	joined := strings.Join(rep.Structural.Unverified, " | ")
	if strings.Contains(joined, "The agent runs themselves were not opened") ||
		!strings.Contains(joined, "Only 1 run listed under AGENT RUNS was opened. For the rest: this shows") {
		t.Fatalf("caveats: %s", joined)
	}
	if rep.Verdict != verdictIncomplete || !strings.Contains(strings.Join(rep.VerdictReasons, " "), "not in the hourly file") {
		t.Fatalf("a run missing from the hourly file gave %s: %v", rep.Verdict, rep.VerdictReasons)
	}
}
