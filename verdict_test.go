package main

// One verdict for every output (the outside review's round 2, 17 November
// 2026). The reviewer's forged files are rebuilt here from the real-log
// run's exports, and each must fail the exit code, the JSON, the text
// RESULT line and the PDF together.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/mesedi-ai/mesedi/backend/attest"
)

const realLogKey = "testdata/real-log-run-2026-11-16-key.pub.pem"

func readRealExport(t *testing.T, name string) attest.ChainExport {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var e attest.ChainExport
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func run(t *testing.T, e attest.ChainExport, o runOptions) report {
	t.Helper()
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if o.Version == "" {
		o.Version = "test"
	}
	rep, err := verifyExport(raw, e, o)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

// outputs renders the four outputs a reader can see.
func outputs(rep report) (ok bool, jsonVerdict, textResult, pdfVerdict string) {
	var buf bytes.Buffer
	printReport(&buf, rep)
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(line, "RESULT:") {
			textResult = line
		}
	}
	d := buildPDFDoc(rep, rep.ExportSHA256)
	pdfVerdict = d.Verdict
	if d.Failed != (d.Verdict == verdictFailed) {
		pdfVerdict += " (but its failure flag disagrees)"
	}
	return rep.OK, rep.Verdict, textResult, pdfVerdict
}

func wantEveryOutput(t *testing.T, name string, rep report, want string) {
	t.Helper()
	ok, j, text, pdf := outputs(rep)
	wantText := map[string]string{
		verdictVerified:   "RESULT: every check that ran passed.",
		verdictFailed:     "RESULT: FAILED.",
		verdictIncomplete: "RESULT: INCOMPLETE.",
	}[want]
	if ok != (want == verdictVerified) || j != want || !strings.HasPrefix(text, wantText) || pdf != want {
		t.Errorf("%s: ok=%v json=%q text=%q pdf=%q; want every output to say %s",
			name, ok, j, text, pdf, want)
	}
}

func TestTheRealLogRunPassesEveryOutput(t *testing.T) {
	e := readRealExport(t, "real-log-run-2026-11-16-with-growth-proofs.json")
	rep := run(t, e, runOptions{Offline: true, TrustedKeys: []string{realLogKey}})
	wantEveryOutput(t, "the honest export with growth proofs", rep, verdictVerified)
}

// The reviewer's g1: one growth proof names the wrong earlier tree size.
func TestABrokenGrowthProofFailsEveryOutput(t *testing.T) {
	e := readRealExport(t, "real-log-run-2026-11-16-with-growth-proofs.json")
	var proof map[string]json.RawMessage
	if err := json.Unmarshal(e.Intervals[2].AnchorProof, &proof); err != nil {
		t.Fatal(err)
	}
	var cons map[string]any
	if err := json.Unmarshal(proof["consistency_proof"], &cons); err != nil {
		t.Fatal(err)
	}
	cons["FirstSize"] = cons["FirstSize"].(float64) + 1
	proof["consistency_proof"], _ = json.Marshal(cons)
	e.Intervals[2].AnchorProof, _ = json.Marshal(proof)

	rep := run(t, e, runOptions{Offline: true, TrustedKeys: []string{realLogKey}})
	if !rep.LogGrowthFailed {
		t.Fatal("the forged growth proof was not caught at all")
	}
	wantEveryOutput(t, "a forged growth proof", rep, verdictFailed)
}

// fakeEsplora serves real Bitcoin block roots, as blockstream.info gave
// them on 16 November 2026, including block 976184, which no receipt of
// the real-log run reaches.
func fakeEsplora(t *testing.T) string {
	roots := map[string]string{
		"976183": "3f502e93b96383e16a6528802baf88f85a61778dffb8460f7444e06fcfb00fb3",
		"976184": "44a53e38" + strings.Repeat("00", 28),
		"976185": "6a2ef0c6f69233ce6cd25b1184888398224a48aa375f8b4b68e575786cf3c1d7",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/block-height/"):
			fmt.Fprint(w, "hash-"+strings.TrimPrefix(r.URL.Path, "/block-height/"))
		case strings.HasPrefix(r.URL.Path, "/block/hash-"):
			h := strings.TrimPrefix(r.URL.Path, "/block/hash-")
			fmt.Fprintf(w, `{"merkle_root":%q,"timestamp":1794862079}`, roots[h])
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// repointBlock rewrites every Bitcoin attestation in a receipt to height.
func repointBlock(n *attest.OTSTimestamp, height uint64) {
	for i := range n.Attestations {
		if n.Attestations[i].Tag == attest.OTSTagBitcoin {
			var b []byte
			for v := height; ; v >>= 7 {
				if v < 0x80 {
					b = append(b, byte(v))
					break
				}
				b = append(b, byte(v&0x7f)|0x80)
			}
			n.Attestations[i].Payload = b
		}
	}
	for _, op := range n.Ops {
		repointBlock(op.Next, height)
	}
}

// The reviewer's b1: checkpoint 1's receipts are re-pointed to a block
// they do not lead to. The log is unreachable, as in the reviewer's run,
// so only the Bitcoin check can fail it.
func TestAFalseBitcoinReceiptFailsEveryOutput(t *testing.T) {
	e := readRealExport(t, "real-log-run-2026-11-16-upgraded-export.json")
	digest, _ := hex.DecodeString(e.Intervals[0].Checkpoint.Hash)
	for i, r := range e.Intervals[0].Timestamps {
		ts, err := attest.ParseOTSTimestamp(digest, r.Receipt)
		if err != nil {
			t.Fatal(err)
		}
		repointBlock(ts, 976184)
		e.Intervals[0].Timestamps[i].Receipt = ts.Serialize()
	}
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	rep := run(t, e, runOptions{RekorURL: closed.URL, BitcoinAPI: fakeEsplora(t),
		TrustedKeys: []string{realLogKey}})
	if rep.Bitcoin[0].Status != StatusFailed {
		t.Fatalf("the false receipt was not caught: %+v", rep.Bitcoin[0])
	}
	wantEveryOutput(t, "a false Bitcoin receipt", rep, verdictFailed)

	honest := run(t, readRealExport(t, "real-log-run-2026-11-16-upgraded-export.json"),
		runOptions{RekorURL: closed.URL, BitcoinAPI: fakeEsplora(t), TrustedKeys: []string{realLogKey}})
	if honest.Bitcoin[0].Status != StatusVerified {
		t.Fatalf("the honest receipt did not verify against the same explorer: %+v", honest.Bitcoin[0])
	}
}

// Every other reason reaches every output too.
func TestEveryVerdictReasonReachesEveryOutput(t *testing.T) {
	cases := map[string]struct {
		edit func(*report)
		want string
	}{
		"clean":            {func(*report) {}, verdictVerified},
		"structure":        {func(r *report) { r.Structural.OK = false }, verdictFailed},
		"entry failed":     {func(r *report) { r.LogEntries[0].Status = StatusFailed }, verdictFailed},
		"growth failed":    {func(r *report) { r.LogGrowthFailed = true }, verdictFailed},
		"bitcoin failed":   {func(r *report) { r.Bitcoin = []timestampCheck{{Seq: 1, Status: StatusFailed}} }, verdictFailed},
		"entry unchecked":  {func(r *report) { r.LogEntries[0].Status = StatusUnverifiable }, verdictIncomplete},
		"beyond max late":  {func(r *report) { r.LogEntries[0].TooLate = true }, verdictIncomplete},
		"failure and late": {func(r *report) { r.LogGrowthFailed = true; r.LogEntries[0].TooLate = true }, verdictFailed},
	}
	for name, tc := range cases {
		rep := sampleReport(true, true)
		tc.edit(&rep)
		v := decideVerdict(rep)
		rep.Verdict, rep.OK = v.Kind, v.Kind == verdictVerified
		wantEveryOutput(t, name, rep, tc.want)
	}
}
