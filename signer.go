package main

// Who signed each log entry (the outside review of 2026-11-15).
//
// Until 2026-11-16 nothing checked it. The entry at a checkpoint's log
// index was confirmed to record the right hash, but any key could have
// submitted it. Since then Mesedi signs every anchor with its own key and
// publishes the public key, so for those anchors ("mesedi-direct") this
// verifier requires all three:
//
//  1. the entry names a trusted public key: one of Mesedi's published
//     keys below, or one the user passes with --trusted-key (a self-hosted
//     deployment signs with its own);
//  2. the entry's signature over its recorded hash verifies with that key;
//  3. the anchored text is exactly mesedi.anchor.v1.<seq>.<checkpoint hash>.
//
// Anchors made before 2026-11-16 went through a third-party service whose
// key signed them. Owner decision, 16 November 2026: their signer is
// reported as not checked, and this verifier carries no other company's
// key. Their content and time stay proven by Sigstore's own signature.
//
// WHICH hours count as "before" is decided from Sigstore's signed data,
// never from the export (owner decision, 17 November 2026). Until then the
// export's own anchor_kind label decided it, and the export is written by
// the party being checked: deleting the label made a forged hour, signed
// by any key, pass as an old one (the outside review's round 2).

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/mesedi-ai/mesedi/backend/attest"
)

// Anchor kinds, as the export names them.
const (
	anchorKindDirect     = "mesedi-direct"
	anchorKindThirdParty = "verdifax-attest"
)

// The switch point: the first anchor Mesedi signed itself, the real-log
// run's first entry on 16 November 2026 (rekor.sigstore.dev, read back from
// the log). Every Mesedi anchor before it went through the third-party
// service; none came after. An entry at or past this point, or on any
// other tree of the log, must be signed by a trusted key whatever the
// export says. Stated twice because a stored proof gives the position on
// one tree, signed by Sigstore, and a log lookup gives the position across
// every tree.
const (
	switchTreeOrigin = "rekor.sigstore.dev - 1193050959916656506"
	switchTreeIndex  = 3811305864
	switchLogIndex   = 3933210126
)

// requireSignerAll is the auditor's option to require a trusted signature
// on every hour, including those published before the switch point
// (--require-signer-all).
var requireSignerAll bool

// mesediAnchorKeysPEM are the public halves of Mesedi's anchor signing
// keys, created on 16 November 2026 and published on mesedi.ai/docs/evidence
// and in the mesedi repository (backend/docs/ANCHOR-SIGNING-KEYS.md): key 1
// signs, key 2 is its published replacement. A change here changes what
// the verifier trusts; TestMesediPublishedKeysArePinned holds both.
var mesediAnchorKeysPEM = []string{
	// Key 1, SHA-256 eccad116fe144bd3ca0da53453eac1180d0981e0833ff756b18580c3648e5247
	`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEVfEcOm4AzR+9YWvm13txE1cboCHX
+3/s/pX29Vidph2AJnjyXbgWVRbnByk0WVIdxL5GaRFH1fmLt5uYJMM9eQ==
-----END PUBLIC KEY-----`,
	// Key 2, SHA-256 f7ad3f9ce0b4e55ae144ed574944b9b1854cd8b0c7461f1941484a191a041e44
	`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEACCZ7nAkkogbezTSvyg1Ec3VJI/
YTnvCpiPJfa7jgbrAZxhiwI9xfDmAA8gwNeZjYizLwSqgji/+bB5VmahFQ==
-----END PUBLIC KEY-----`,
}

// trustedKey is one key an entry may be signed with.
type trustedKey struct {
	key         *ecdsa.PublicKey
	fingerprint string
	source      string
}

func keyFingerprint(k *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

func parsePublicKeyPEM(raw []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("not a PEM public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not a public key: %w", err)
	}
	k, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}
	return k, nil
}

// loadTrustedKeys returns Mesedi's published keys plus each PEM file the
// user named with --trusted-key.
func loadTrustedKeys(paths []string) ([]trustedKey, error) {
	var out []trustedKey
	add := func(raw []byte, source string) error {
		k, err := parsePublicKeyPEM(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", source, err)
		}
		fp, err := keyFingerprint(k)
		if err != nil {
			return err
		}
		out = append(out, trustedKey{key: k, fingerprint: fp, source: source})
		return nil
	}
	for i, p := range mesediAnchorKeysPEM {
		if err := add([]byte(p), fmt.Sprintf("Mesedi published key %d", i+1)); err != nil {
			return nil, err
		}
	}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("--trusted-key %s: %w", p, err)
		}
		// Named by what it is, not where it sat: the signer line already
		// gives the key's fingerprint, and a path on the operator's machine
		// means nothing to the report's reader (the outside review's round
		// 2, 17 November 2026).
		if err := add(raw, "a key passed with --trusted-key"); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// checkSigners sets each entry's Signer and fails a direct anchor whose
// signer is wrong. Entries already failed keep their first finding.
func checkSigners(export attest.ChainExport, entries []LogEntryCheck, trusted []trustedKey) {
	for i := range entries {
		if i >= len(export.Intervals) {
			return
		}
		iv := export.Intervals[i]
		required := iv.AnchorKind == anchorKindDirect || requireSignerAll ||
			(entries[i].verified() && publishedAfterSwitch(iv, entries[i]))
		if !required {
			entries[i].Signer = "not checked: anchored before 16 November 2026 through a third-party service"
			continue
		}
		signer, err := checkDirectSigner(iv, trusted)
		if err != nil {
			entries[i].Signer = "FAILED: " + err.Error()
			if !entries[i].failed() {
				entries[i].Status = StatusFailed
				entries[i].Detail = "the log entry was not signed as Mesedi signs its anchors: " + err.Error()
			}
			continue
		}
		entries[i].Signer = signer
		if entries[i].verified() {
			entries[i].Detail += ". Signed by " + signer
		}
	}
}

// publishedAfterSwitch says whether an entry the run has verified sits at
// or past the switch point, judged only from what the run verified: the
// position and tree in a stored proof Sigstore signed, or the position the
// log itself answered for. Anything that cannot be read counts as after,
// so a missing fact can only make the check stricter.
func publishedAfterSwitch(iv attest.ExportedInterval, e LogEntryCheck) bool {
	if e.Method == MethodOfflineProof {
		var env anchorProof
		var p wireInclusionProof
		if json.Unmarshal(iv.AnchorProof, &env) != nil || json.Unmarshal(env.InclusionProof, &p) != nil {
			return true
		}
		origin, _, _ := strings.Cut(p.Checkpoint, "\n")
		return origin != switchTreeOrigin || p.LogIndex >= switchTreeIndex
	}
	idx, err := strconv.ParseInt(iv.LogEntryID, 10, 64)
	return err != nil || idx >= switchLogIndex
}

// keyPaths collects repeated --trusted-key flags.
type keyPaths []string

func (k *keyPaths) String() string     { return strings.Join(*k, ",") }
func (k *keyPaths) Set(v string) error { *k = append(*k, v); return nil }

// checkDirectSigner names the trusted key that signed a direct anchor
// ("key <fingerprint>, <where it is trusted from>"), or says why the
// anchor cannot be accepted.
func checkDirectSigner(iv attest.ExportedInterval, trusted []trustedKey) (string, error) {
	want := fmt.Sprintf("mesedi.anchor.v1.%d.%s", iv.Checkpoint.Seq, iv.Checkpoint.Hash)
	if iv.LeafPreimage != want {
		return "", fmt.Errorf("the anchored text is %q, not %q", iv.LeafPreimage, want)
	}
	var env anchorProof
	if len(iv.AnchorProof) == 0 || json.Unmarshal(iv.AnchorProof, &env) != nil || env.EntryBody == "" {
		return "", errors.New("the export carries no log entry to read the signer from")
	}
	bodyRaw, err := base64.StdEncoding.DecodeString(env.EntryBody)
	if err != nil {
		return "", errors.New("the stored log entry is not base64")
	}
	var body hashedRekordBody
	if err := json.Unmarshal(bodyRaw, &body); err != nil || body.Kind != "hashedrekord" {
		return "", errors.New("the stored log entry is not a hashedrekord")
	}
	pemRaw, err := base64.StdEncoding.DecodeString(body.Spec.Signature.PublicKey.Content)
	if err != nil {
		return "", errors.New("the entry's public key is not base64")
	}
	key, err := parsePublicKeyPEM(pemRaw)
	if err != nil {
		return "", fmt.Errorf("the entry's public key: %w", err)
	}
	fp, err := keyFingerprint(key)
	if err != nil {
		return "", err
	}
	var match *trustedKey
	for i := range trusted {
		if trusted[i].fingerprint == fp {
			match = &trusted[i]
		}
	}
	if match == nil {
		return "", fmt.Errorf("signed by key %s, which is not a trusted key", fp)
	}
	digest, err := hex.DecodeString(body.Spec.Data.Hash.Value)
	if err != nil || len(digest) != sha256.Size || !strings.EqualFold(body.Spec.Data.Hash.Algorithm, "sha256") {
		return "", errors.New("the entry's recorded hash is not a SHA-256")
	}
	if sum := sha256.Sum256([]byte(want)); !strings.EqualFold(hex.EncodeToString(sum[:]), body.Spec.Data.Hash.Value) {
		return "", errors.New("the entry records a hash other than this checkpoint's anchored text")
	}
	sig, err := base64.StdEncoding.DecodeString(body.Spec.Signature.Content)
	if err != nil || !ecdsa.VerifyASN1(match.key, digest, sig) {
		return "", fmt.Errorf("the signature does not verify with key %s", fp)
	}
	return fmt.Sprintf("key %s, %s", fp, match.source), nil
}

// signerNotes summarises who signed, for the report: what was
// established, and what was not.
func signerNotes(entries []LogEntryCheck) (established, notChecked string) {
	byKey := map[string][]uint64{} // max: one entry per trusted key
	var third []uint64
	for _, e := range entries {
		switch {
		case strings.HasPrefix(e.Signer, "not checked"):
			third = append(third, e.Seq)
		case e.Signer != "" && !strings.HasPrefix(e.Signer, "FAILED"):
			byKey[e.Signer] = append(byKey[e.Signer], e.Seq)
		}
	}
	signers := make([]string, 0, len(byKey))
	for s := range byKey {
		signers = append(signers, s)
	}
	sort.Strings(signers)
	for _, signer := range signers {
		seqs := byKey[signer]
		established += fmt.Sprintf(" Checkpoints %v were signed by %s, and the signature "+
			"on each verified.", seqs, signer)
	}
	if len(third) > 0 {
		notChecked = fmt.Sprintf("Who signed the log entries of checkpoints %v is NOT checked: "+
			"they were anchored before 16 November 2026 through a third-party service. "+
			"Their content and the time the log recorded them are still proven by "+
			"Sigstore's own signature.", third)
	}
	return established, notChecked
}
