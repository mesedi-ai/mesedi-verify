package main

// The inclusion proof walk, checked against RFC 6962's own definitions.
//
// Written on 2026-11-16 with the checker it tests (owner decision B, 21
// October 2026). The reference below is the RFC's recursive definition
// of a tree head (MTH, section 2.1) and of an audit path (PATH, section
// 2.1.1), deliberately a different algorithm from the iterative walk
// under test (RFC 9162 section 2.1.3.2), so the two can only agree if
// both are right.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func refLeaf(data []byte) []byte {
	h := sha256.Sum256(append([]byte{0x00}, data...))
	return h[:]
}

// refSplit is the largest power of two smaller than n (RFC 6962 2.1).
func refSplit(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// refMTH is the Merkle Tree Hash of a list of leaf hashes.
func refMTH(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := refSplit(len(leaves))
	return hashChildren(refMTH(leaves[:k]), refMTH(leaves[k:]))
}

// refPATH is the audit path for leaf m.
func refPATH(m int, leaves [][]byte) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := refSplit(len(leaves))
	if m < k {
		return append(refPATH(m, leaves[:k]), refMTH(leaves[k:]))
	}
	return append(refPATH(m-k, leaves[k:]), refMTH(leaves[:k]))
}

func refTree(n int) [][]byte {
	leaves := make([][]byte, n)
	for i := range leaves {
		leaves[i] = refLeaf([]byte{byte(i), byte(i >> 8), 'x'})
	}
	return leaves
}

func TestTheWalkAgreesWithTheRFCForEveryLeafOfEveryTreeUpTo64(t *testing.T) {
	for n := 1; n <= 64; n++ {
		leaves := refTree(n)
		root := refMTH(leaves)
		for m := 0; m < n; m++ {
			got, err := recomputeRootRFC6962(leaves[m], int64(m), int64(n), refPATH(m, leaves))
			if err != nil {
				t.Fatalf("tree %d, leaf %d: %v", n, m, err)
			}
			if !bytesEqual(got, root) {
				t.Fatalf("tree %d, leaf %d: walked to %x, the tree's root is %x", n, m, got, root)
			}
		}
	}
}

func TestAnyChangedPathHashChangesTheRoot(t *testing.T) {
	leaves := refTree(13)
	root := refMTH(leaves)
	path := refPATH(6, leaves)
	for i := range path {
		bad := append([][]byte(nil), path...)
		bad[i] = append([]byte(nil), path[i]...)
		bad[i][0] ^= 1
		got, err := recomputeRootRFC6962(leaves[6], 6, 13, bad)
		if err != nil {
			t.Fatalf("hash %d: a path of the right shape was refused: %v", i, err)
		}
		if bytesEqual(got, root) {
			t.Fatalf("changing path hash %d still reached the root", i)
		}
	}
}

func TestAnIndexOutsideTheTreeIsAnError(t *testing.T) {
	leaf := refLeaf([]byte("a"))
	for _, c := range []struct{ index, size int64 }{{4, 4}, {-1, 4}, {0, 0}} {
		if _, err := recomputeRootRFC6962(leaf, c.index, c.size, nil); err == nil {
			t.Errorf("index %d in a tree of %d accepted", c.index, c.size)
		}
	}
}

func TestVerifyAnchor_RejectsACheckpointNotSignedByTheEmbeddedKey(t *testing.T) {
	// The tree, the path and the checkpoint text are all correct, and the
	// checkpoint IS validly signed, by a key that is not Sigstore's, with
	// that key's own ID. The signature check against the embedded key is
	// the only thing that can refuse it.
	leaves := refTree(2)
	root := refMTH(leaves)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	text := "rekor.sigstore.dev - 1\n2\n" + base64.StdEncoding.EncodeToString(root) + "\n"
	digest := sha256.Sum256([]byte(text))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	id, _ := rekorKeyHint(&key.PublicKey)
	note := text + "\n" + sigLinePrefix + "rekor.sigstore.dev " + base64.StdEncoding.EncodeToString(append(id, sig...)) + "\n"
	if err := verifySignedCheckpoint(note, hex.EncodeToString(root), 2, &key.PublicKey); err != nil {
		t.Fatalf("the note does not verify against its own key, so this test proves nothing: %v", err)
	}
	in := AnchorInput{
		LeafHashHex:   hex.EncodeToString(leaves[0]),
		LogIndex:      0,
		TreeSize:      2,
		RootHashHex:   hex.EncodeToString(root),
		InclusionPath: []string{hex.EncodeToString(leaves[1])},
		Checkpoint:    note,
	}
	if err := VerifyAnchor(in); err == nil || !strings.Contains(err.Error(), "log's key") {
		t.Fatalf("a checkpoint signed by another key verified: %v", err)
	}
}
