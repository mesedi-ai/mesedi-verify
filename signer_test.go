package main

// Who signed each log entry (the outside review of 2026-11-15).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mesedi-ai/mesedi/backend/attest"
)

func newSignerKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return k, path
}

// directInterval builds an interval anchored the way Mesedi anchors since
// 2026-11-16: preimage mesedi.anchor.v1.<seq>.<hash>, its SHA-256 signed
// by key, carried in a hashedrekord entry body.
func directInterval(t *testing.T, key *ecdsa.PrivateKey, seq uint64, mutate func(preimage *string, recorded *[]byte, signed *[]byte)) attest.ExportedInterval {
	t.Helper()
	cpHash := fmt.Sprintf("%064x", seq*104729)
	preimage := fmt.Sprintf("mesedi.anchor.v1.%d.%s", seq, cpHash)
	sum := sha256.Sum256([]byte(preimage))
	recorded, signed := sum[:], sum[:]
	stored := preimage
	if mutate != nil {
		mutate(&stored, &recorded, &signed)
	}
	sig, err := ecdsa.SignASN1(rand.Reader, key, signed)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	body := fmt.Sprintf(`{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{"signature":{"content":%q,"publicKey":{"content":%q}},"data":{"hash":{"algorithm":"sha256","value":%q}}}}`,
		base64.StdEncoding.EncodeToString(sig), base64.StdEncoding.EncodeToString(pubPEM), hex.EncodeToString(recorded))
	proof, _ := json.Marshal(map[string]string{"entry_body": base64.StdEncoding.EncodeToString([]byte(body))})
	return attest.ExportedInterval{
		Checkpoint:   attest.Checkpoint{Seq: seq, Hash: cpHash},
		LeafPreimage: stored,
		AnchorProof:  proof,
		AnchorKind:   anchorKindDirect,
	}
}

func runSigners(t *testing.T, ivs []attest.ExportedInterval, keyPaths ...string) []LogEntryCheck {
	t.Helper()
	trusted, err := loadTrustedKeys(keyPaths)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]LogEntryCheck, len(ivs))
	for i, iv := range ivs {
		entries[i] = LogEntryCheck{Seq: iv.Checkpoint.Seq, Status: StatusVerified, Detail: "found in the log"}
	}
	checkSigners(attest.ChainExport{Intervals: ivs}, entries, trusted)
	return entries
}

func TestADirectAnchorSignedByATrustedKeyVerifiesAndNamesItsSigner(t *testing.T) {
	key, path := newSignerKey(t)
	got := runSigners(t, []attest.ExportedInterval{directInterval(t, key, 7, nil)}, path)[0]
	fp, _ := keyFingerprint(&key.PublicKey)
	if !got.verified() || got.Signer != "key "+fp+", a key passed with --trusted-key" ||
		strings.Contains(got.Signer, path) {
		t.Fatalf("status %q, signer %q", got.Status, got.Signer)
	}
	if !strings.Contains(got.Detail, "Signed by key "+fp) {
		t.Errorf("the entry's line does not name its signer: %s", got.Detail)
	}
	established, notChecked := signerNotes([]LogEntryCheck{got})
	if !strings.Contains(established, "Checkpoints [7] were signed by key "+fp) || notChecked != "" {
		t.Errorf("summary %q, caveat %q", established, notChecked)
	}
}

func TestADirectAnchorThatIsWrongInAnyWayFails(t *testing.T) {
	key, path := newSignerKey(t)
	stranger, _ := newSignerKey(t)
	cases := map[string]attest.ExportedInterval{
		"signed by an untrusted key": directInterval(t, stranger, 7, nil),
		"a signature over another hash": directInterval(t, key, 7, func(_ *string, _ *[]byte, signed *[]byte) {
			other := sha256.Sum256([]byte("other"))
			*signed = other[:]
		}),
		"a record of another hash": directInterval(t, key, 7, func(_ *string, recorded *[]byte, signed *[]byte) {
			other := sha256.Sum256([]byte("other"))
			*recorded, *signed = other[:], other[:]
		}),
		"the anchored text for another hour": directInterval(t, key, 7, func(p *string, _ *[]byte, _ *[]byte) {
			*p = strings.Replace(*p, "v1.7.", "v1.8.", 1)
		}),
		"another format of anchored text": directInterval(t, key, 7, func(p *string, _ *[]byte, _ *[]byte) {
			*p = strings.Replace(*p, "mesedi.anchor.v1.", "mesedi.anchor.v2.", 1)
		}),
	}
	noBody := directInterval(t, key, 7, nil)
	noBody.AnchorProof = nil
	cases["no log entry in the export"] = noBody
	for name, iv := range cases {
		got := runSigners(t, []attest.ExportedInterval{iv}, path)[0]
		if !got.failed() || !strings.HasPrefix(got.Signer, "FAILED") {
			t.Errorf("%s: status %q, signer %q", name, got.Status, got.Signer)
		}
	}
}

// An hour Sigstore's own data places before the switch point is reported
// as "signer not checked", whatever its label. Position, not label: two
// real September 2026 positions, one from a log lookup and one from a
// stored proof on the same tree.
func preSwitchProof(t *testing.T, treeIndex int64, origin string) []byte {
	t.Helper()
	inc, _ := json.Marshal(map[string]any{"LogIndex": treeIndex, "Checkpoint": origin + "\n1\nAA==\n"})
	raw, _ := json.Marshal(map[string]json.RawMessage{"inclusion_proof": inc})
	return raw
}

func TestAnchorsMadeBeforeTheSwitchAreReportedAsNotChecked(t *testing.T) {
	ivs := []attest.ExportedInterval{
		{Checkpoint: attest.Checkpoint{Seq: 3}, AnchorKind: anchorKindThirdParty, LogEntryID: "2725800899"},
		{Checkpoint: attest.Checkpoint{Seq: 4}, LogEntryID: "2728213534"}, // exports made before the kind existed
		{Checkpoint: attest.Checkpoint{Seq: 5}, AnchorProof: preSwitchProof(t, 2603896637, switchTreeOrigin)},
	}
	entries := runSigners(t, ivs)
	entries = append(entries[:2], runSignersByProof(t, ivs[2:])...)
	for _, e := range entries {
		if !e.verified() || !strings.HasPrefix(e.Signer, "not checked") {
			t.Errorf("checkpoint %d: status %q, signer %q", e.Seq, e.Status, e.Signer)
		}
	}
	_, notChecked := signerNotes(entries)
	if !strings.Contains(notChecked, "checkpoints [3 4 5] is NOT checked") || !strings.Contains(notChecked, "third-party service") {
		t.Errorf("caveat %q", notChecked)
	}
}

func runSignersByProof(t *testing.T, ivs []attest.ExportedInterval, keyPaths ...string) []LogEntryCheck {
	t.Helper()
	trusted, err := loadTrustedKeys(keyPaths)
	if err != nil {
		t.Fatal(err)
	}
	entries := make([]LogEntryCheck, len(ivs))
	for i, iv := range ivs {
		entries[i] = LogEntryCheck{Seq: iv.Checkpoint.Seq, Status: StatusVerified,
			Method: MethodOfflineProof, Detail: "proven offline"}
	}
	checkSigners(attest.ChainExport{Intervals: ivs}, entries, trusted)
	return entries
}

// The export cannot choose to skip the check (the outside review's round
// 2, 17 November 2026): an hour at or past the switch point, on another
// tree, or with no readable position must be signed by a trusted key,
// whatever its label says, and so must every hour under
// --require-signer-all.
func TestTheExportsLabelCannotSkipTheSignerCheck(t *testing.T) {
	cases := map[string]struct {
		iv     attest.ExportedInterval
		method string
	}{
		"label removed, after the switch (lookup)": {attest.ExportedInterval{LogEntryID: "3933210126"}, MethodLogLookup},
		"labelled third party, after the switch":   {attest.ExportedInterval{LogEntryID: "3933219019", AnchorKind: anchorKindThirdParty}, MethodLogLookup},
		"any other label":                          {attest.ExportedInterval{LogEntryID: "3999999999", AnchorKind: "mesedi-direct-v2"}, MethodLogLookup},
		"no readable position":                     {attest.ExportedInterval{LogEntryID: "not-a-number"}, MethodLogLookup},
		"stored proof past the switch":             {attest.ExportedInterval{AnchorProof: preSwitchProof(t, switchTreeIndex, switchTreeOrigin)}, MethodOfflineProof},
		"stored proof on another tree":             {attest.ExportedInterval{AnchorProof: preSwitchProof(t, 5, "rekor.sigstore.dev - 42")}, MethodOfflineProof},
		"stored proof that does not read":          {attest.ExportedInterval{AnchorProof: []byte(`{"inclusion_proof":"x"}`)}, MethodOfflineProof},
	}
	for name, tc := range cases {
		tc.iv.Checkpoint = attest.Checkpoint{Seq: 9}
		entries := []LogEntryCheck{{Seq: 9, Status: StatusVerified, Method: tc.method}}
		trusted, _ := loadTrustedKeys(nil)
		checkSigners(attest.ChainExport{Intervals: []attest.ExportedInterval{tc.iv}}, entries, trusted)
		if !entries[0].failed() || !strings.HasPrefix(entries[0].Signer, "FAILED") {
			t.Errorf("%s: status %q, signer %q; the export chose to skip the signer check",
				name, entries[0].Status, entries[0].Signer)
		}
	}

	requireSignerAll = true
	defer func() { requireSignerAll = false }()
	pre := runSigners(t, []attest.ExportedInterval{{Checkpoint: attest.Checkpoint{Seq: 3}, LogEntryID: "2725800899"}})[0]
	if !pre.failed() {
		t.Errorf("--require-signer-all let an unsigned pre-switch hour pass: %q", pre.Signer)
	}
}

// The reviewer's three relabelled copies of the real-log export, rebuilt
// here: without the throwaway key trusted, each must fail.
func TestTheRealLogRunCannotBeRelabelledPastTheSignerCheck(t *testing.T) {
	for _, label := range []string{"", anchorKindThirdParty, "mesedi-direct-v2"} {
		e := readRealExport(t, "real-log-run-2026-11-16-upgraded-export.json")
		for i := range e.Intervals {
			e.Intervals[i].AnchorKind = label
		}
		rep := run(t, e, runOptions{Offline: true})
		if rep.OK || rep.Verdict != verdictFailed {
			t.Errorf("label %q: verdict %s; a relabelled export skipped the signer check", label, rep.Verdict)
		}
	}
}

func TestAnUnreadableTrustedKeyStopsTheRun(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(bad, []byte("not a key"), 0o600)
	for _, p := range []string{bad, filepath.Join(t.TempDir(), "missing.pem")} {
		if _, err := loadTrustedKeys([]string{p}); err == nil {
			t.Errorf("%s: accepted", p)
		}
	}
}
