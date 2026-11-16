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
	if !got.verified() || got.Signer != "key "+fp+", --trusted-key "+path {
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

func TestAnchorsMadeBeforeTheSwitchAreReportedAsNotChecked(t *testing.T) {
	ivs := []attest.ExportedInterval{
		{Checkpoint: attest.Checkpoint{Seq: 3}, AnchorKind: anchorKindThirdParty},
		{Checkpoint: attest.Checkpoint{Seq: 4}}, // exports made before the kind existed
	}
	entries := runSigners(t, ivs)
	for _, e := range entries {
		if !e.verified() || !strings.HasPrefix(e.Signer, "not checked") {
			t.Errorf("checkpoint %d: status %q, signer %q", e.Seq, e.Status, e.Signer)
		}
	}
	_, notChecked := signerNotes(entries)
	if !strings.Contains(notChecked, "checkpoints [3 4] is NOT checked") || !strings.Contains(notChecked, "third-party service") {
		t.Errorf("caveat %q", notChecked)
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
