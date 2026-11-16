package main

// Offline verification of an entry on Sigstore's Rekor log, written on
// 2026-11-16 from the public standards it implements (owner decision B,
// 21 October 2026). It replaces a version adapted from another company's
// codebase; nothing here was carried over from that version, and the
// existing tests, plus a real entry read from the public log
// (testdata/rekor-entry-1000000000.json), are what judge it.
//
// Two independent questions, both of which must be answered yes:
//
//  1. Is this entry at this position in a tree with this root? The
//     inclusion proof check of RFC 9162 section 2.1.3.2, over the tree
//     hashing of RFC 6962 section 2.1: a leaf is SHA-256(0x00 || entry),
//     an interior node SHA-256(0x01 || left || right).
//
//  2. Did the log sign that root at that tree size? A checkpoint in the
//     c2sp.org/tlog-checkpoint format (origin, size and base64 root, one
//     per line) wrapped in a c2sp.org/signed-note: the note text, a blank
//     line, then signature lines of the form
//
//     U+2014 EM DASH, space, key name, space, base64(key ID || signature)
//
//     For an ECDSA key the signature is over SHA-256 of the note text, and
//     the 4-byte key ID is the first 4 bytes of SHA-256 of the key's PKIX
//     DER encoding, the same hash as the log ID.
//
// No network: the proof and the signed checkpoint travel in the export,
// and the log's key is compiled in (rekorproof_pubkey.go).

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// AnchorInput is one entry to verify offline.
type AnchorInput struct {
	// LeafHashHex is the RFC 6962 leaf hash, used only when EntryBody is
	// empty. With EntryBody set the leaf is computed from it, and a
	// supplied LeafHashHex must agree.
	LeafHashHex string
	// EntryBody is the entry as the log stores it, base64.
	EntryBody string
	// LogIndex is the entry's index in the tree the proof is about.
	LogIndex int64
	// TreeSize and RootHashHex are the tree head the proof leads to.
	TreeSize    int64
	RootHashHex string
	// InclusionPath is the proof's hashes, leaf to root, hex.
	InclusionPath []string
	// Checkpoint is the signed note over that tree head.
	Checkpoint string
	// LogID, when set, must be the embedded key's log ID.
	LogID string
}

// sigLinePrefix starts every signature line of a signed note: U+2014 EM
// DASH then a space, as c2sp.org/signed-note specifies. This literal is
// the one place the em dash belongs; the working rules forbid it in prose
// and TestTheCheckpointSignaturePrefixIsLeftAlone guards it against being
// "fixed", which would make every checkpoint fail to parse.
const sigLinePrefix = "— "

// VerifyAnchor answers both questions for one entry, or says which failed.
func VerifyAnchor(in AnchorInput) error {
	if err := checkAnchorInput(in); err != nil {
		return err
	}
	leaf, err := anchorLeafHash(in)
	if err != nil {
		return err
	}
	path, err := decodeHexHashes(in.InclusionPath)
	if err != nil {
		return fmt.Errorf("inclusion proof: %w", err)
	}
	root, err := recomputeRootRFC6962(leaf, in.LogIndex, in.TreeSize, path)
	if err != nil {
		return fmt.Errorf("inclusion proof: %w", err)
	}
	claimed, err := hex.DecodeString(in.RootHashHex)
	if err != nil || len(claimed) != sha256.Size {
		return errors.New("inclusion proof: the root hash is not 32 bytes of hex")
	}
	if !bytes.Equal(root, claimed) {
		return errors.New("inclusion proof: the path does not lead from this entry to the claimed root")
	}
	key, err := loadRekorPublicKey()
	if err != nil {
		return err
	}
	if err := verifySignedCheckpoint(in.Checkpoint, in.RootHashHex, in.TreeSize, key); err != nil {
		return fmt.Errorf("signed checkpoint: %w", err)
	}
	if in.LogID != "" {
		want, err := computeRekorLogID(key)
		if err != nil {
			return err
		}
		if !strings.EqualFold(in.LogID, want) {
			return fmt.Errorf("the proof names log %s, but the embedded key is log %s", in.LogID, want)
		}
	}
	return nil
}

func checkAnchorInput(in AnchorInput) error {
	switch {
	case in.TreeSize <= 0:
		return errors.New("inclusion proof: tree size must be positive")
	case in.LogIndex < 0 || in.LogIndex >= in.TreeSize:
		return fmt.Errorf("inclusion proof: index %d is outside a tree of %d", in.LogIndex, in.TreeSize)
	case in.RootHashHex == "":
		return errors.New("inclusion proof: no root hash")
	case in.Checkpoint == "":
		return errors.New("no signed checkpoint")
	case in.EntryBody == "" && in.LeafHashHex == "":
		return errors.New("neither an entry body nor a leaf hash")
	}
	return nil
}

// anchorLeafHash is SHA-256(0x00 || entry body), or the supplied leaf hash
// when there is no body. Both supplied must agree.
func anchorLeafHash(in AnchorInput) ([]byte, error) {
	var fromBody []byte
	if in.EntryBody != "" {
		body, err := base64.StdEncoding.DecodeString(in.EntryBody)
		if err != nil {
			return nil, errors.New("the entry body is not base64")
		}
		sum := sha256.Sum256(append([]byte{0x00}, body...))
		fromBody = sum[:]
	}
	if in.LeafHashHex == "" {
		return fromBody, nil
	}
	given, err := hex.DecodeString(in.LeafHashHex)
	if err != nil || len(given) != sha256.Size {
		return nil, errors.New("the leaf hash is not 32 bytes of hex")
	}
	if fromBody != nil && !bytes.Equal(given, fromBody) {
		return nil, errors.New("the leaf hash does not match the entry body")
	}
	return given, nil
}

func decodeHexHashes(in []string) ([][]byte, error) {
	out := make([][]byte, len(in))
	for i, h := range in {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != sha256.Size {
			return nil, fmt.Errorf("hash %d is not 32 bytes of hex", i)
		}
		out[i] = b
	}
	return out, nil
}

// recomputeRootRFC6962 walks an inclusion proof from a leaf hash to the
// root it implies, per RFC 9162 section 2.1.3.2. An index outside the
// tree, or a path too long or too short for the tree, is an error; a
// path of the right shape that leads elsewhere returns that other root,
// for the caller to compare.
func recomputeRootRFC6962(leafHash []byte, index, size int64, path [][]byte) ([]byte, error) {
	if size <= 0 || index < 0 || index >= size {
		return nil, fmt.Errorf("index %d is outside a tree of %d", index, size)
	}
	fn, sn := index, size-1
	r := append([]byte(nil), leafHash...)
	for _, p := range path {
		if sn == 0 {
			return nil, errors.New("the path is longer than the tree is deep")
		}
		if fn&1 == 1 || fn == sn {
			r = hashChildren(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = hashChildren(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return nil, errors.New("the path is shorter than the tree is deep")
	}
	return r, nil
}

// hashChildren is an RFC 6962 interior node: SHA-256(0x01 || left || right).
func hashChildren(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

func bytesEqual(a, b []byte) bool { return bytes.Equal(a, b) }

// verifySignedCheckpoint confirms the note is signed by key and that its
// checkpoint states exactly this tree size and root.
func verifySignedCheckpoint(note, rootHex string, size int64, key *ecdsa.PublicKey) error {
	text, sigLines, err := splitSignedNote(note)
	if err != nil {
		return err
	}
	if err := checkCheckpointText(text, rootHex, size); err != nil {
		return err
	}
	keyID, err := rekorKeyHint(key)
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(text))
	for _, line := range sigLines {
		sig, ok := signatureForKey(line, keyID)
		if ok && ecdsa.VerifyASN1(key, digest[:], sig) {
			return nil
		}
	}
	return errors.New("no signature on the checkpoint verifies against the log's key")
}

// splitSignedNote separates the note text (ending in its last newline)
// from the signature lines after the blank line.
func splitSignedNote(note string) (string, []string, error) {
	i := strings.Index(note, "\n\n")
	if i < 0 {
		return "", nil, errors.New("not a signed note: no blank line before the signatures")
	}
	text := note[:i+1]
	rest := strings.TrimSuffix(note[i+2:], "\n")
	if rest == "" {
		return "", nil, errors.New("the note has no signatures")
	}
	var lines []string
	for _, l := range strings.Split(rest, "\n") {
		if !strings.HasPrefix(l, sigLinePrefix) {
			return "", nil, errors.New("a signature line does not start with the signed-note prefix")
		}
		lines = append(lines, l)
	}
	return text, lines, nil
}

// checkCheckpointText checks the checkpoint's second and third lines:
// the tree size in decimal and the root hash in base64.
func checkCheckpointText(text, rootHex string, size int64) error {
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 || lines[0] == "" {
		return errors.New("the checkpoint lacks an origin, a size or a root")
	}
	got, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || got != size {
		return fmt.Errorf("the checkpoint is for a tree of %q, not %d", lines[1], size)
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return errors.New("the checkpoint's root is not base64")
	}
	want, err := hex.DecodeString(rootHex)
	if err != nil || !bytes.Equal(root, want) {
		return errors.New("the checkpoint signs a different root")
	}
	return nil
}

// signatureForKey returns the signature on a line whose key ID matches.
func signatureForKey(line string, keyID []byte) ([]byte, bool) {
	rest := strings.TrimPrefix(line, sigLinePrefix)
	sp := strings.LastIndexByte(rest, ' ')
	if sp <= 0 {
		return nil, false
	}
	raw, err := base64.StdEncoding.DecodeString(rest[sp+1:])
	if err != nil || len(raw) <= 4 || !bytes.Equal(raw[:4], keyID) {
		return nil, false
	}
	return raw[4:], true
}

// rekorKeyHint is a signed note's 4-byte key ID for an ECDSA key: the
// first 4 bytes of SHA-256 of its PKIX DER encoding.
func rekorKeyHint(key *ecdsa.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	return sum[:4], nil
}

// computeRekorLogID is the log's ID: SHA-256 of its key's PKIX DER, hex.
func computeRekorLogID(key *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// EmbeddedLogID is the log ID of the compiled-in Rekor key.
func EmbeddedLogID() (string, error) {
	key, err := loadRekorPublicKey()
	if err != nil {
		return "", err
	}
	return computeRekorLogID(key)
}

func loadRekorPublicKey() (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(RekorPublicKeyPEM))
	if block == nil {
		return nil, errors.New("the embedded Rekor key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the embedded Rekor key does not parse: %w", err)
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("the embedded Rekor key is not an ECDSA key")
	}
	return key, nil
}
