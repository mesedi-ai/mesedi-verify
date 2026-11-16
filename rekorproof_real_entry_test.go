package main

// A real entry from Sigstore's public log, verified offline end to end:
// the leaf from its body, the inclusion path to the root, and Sigstore's
// own signature on that root. Until 2026-11-16 nothing tested the passing
// case, on the belief that only a production checkpoint could; any public
// entry carries a genuine signed checkpoint. testdata/rekor-entry-1000000000.json
// was read from https://rekor.sigstore.dev/api/v1/log/entries?logIndex=1000000000
// on 2026-11-16.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func realRekorAnchor(t *testing.T) AnchorInput {
	t.Helper()
	raw, err := os.ReadFile("testdata/rekor-entry-1000000000.json")
	if err != nil {
		t.Fatal(err)
	}
	var byUUID map[string]struct {
		LogID        string
		Body         string
		Verification struct {
			InclusionProof wireInclusionProof
		}
	}
	if err := json.Unmarshal(raw, &byUUID); err != nil || len(byUUID) != 1 {
		t.Fatalf("fixture: %v", err)
	}
	for _, e := range byUUID {
		p := e.Verification.InclusionProof
		return AnchorInput{EntryBody: e.Body, LogIndex: p.LogIndex, TreeSize: p.TreeSize,
			RootHashHex: p.RootHash, InclusionPath: p.Hashes, Checkpoint: p.Checkpoint, LogID: e.LogID}
	}
	return AnchorInput{}
}

func TestARealSigstoreEntryVerifiesOffline(t *testing.T) {
	if err := VerifyAnchor(realRekorAnchor(t)); err != nil {
		t.Fatalf("a genuine Sigstore entry failed offline verification: %v", err)
	}
}

func TestEveryPartOfTheRealEntryIsLoadBearing(t *testing.T) {
	flip := func(s string) string {
		if s[0] == 'A' {
			return "B" + s[1:]
		}
		return "A" + s[1:]
	}
	cases := map[string]func(in *AnchorInput){
		"another body":        func(in *AnchorInput) { in.EntryBody = flip(in.EntryBody) },
		"another index":       func(in *AnchorInput) { in.LogIndex++ },
		"another root":        func(in *AnchorInput) { in.RootHashHex = strings.Repeat("0", 64) },
		"a path hash":         func(in *AnchorInput) { in.InclusionPath[3] = strings.Repeat("ab", 32) },
		"a missing path hash": func(in *AnchorInput) { in.InclusionPath = in.InclusionPath[1:] },
		"another tree size":   func(in *AnchorInput) { in.TreeSize-- },
		"the signature": func(in *AnchorInput) {
			i := strings.LastIndex(in.Checkpoint, " ")
			sig := in.Checkpoint[i+1:]
			in.Checkpoint = in.Checkpoint[:i+1] + sig[:20] + flip(sig[20:])
		},
		"the signed root": func(in *AnchorInput) {
			lines := strings.SplitN(in.Checkpoint, "\n", 4)
			lines[2] = flip(lines[2])
			in.Checkpoint = strings.Join(lines, "\n")
		},
		"another log":        func(in *AnchorInput) { in.LogID = strings.Repeat("ab", 32) },
		"a dash-free prefix": func(in *AnchorInput) { in.Checkpoint = strings.Replace(in.Checkpoint, sigLinePrefix, "- ", 1) },
	}
	for name, mutate := range cases {
		in := realRekorAnchor(t)
		mutate(&in)
		if err := VerifyAnchor(in); err == nil {
			t.Errorf("%s: a mutated entry still verified", name)
		}
	}
}

// A path that stops early would make an interior node pass as the root,
// if the claimed root were chosen to match. It must be an error, not a
// root to compare.
func TestRecomputeRootRFC6962_AShortPathIsAnError(t *testing.T) {
	leaf := make([]byte, 32)
	if _, err := recomputeRootRFC6962(leaf, 0, 2, nil); err == nil {
		t.Fatal("an empty path for a tree of two was accepted; the leaf would pass as the root")
	}
	if _, err := recomputeRootRFC6962(leaf, 5, 8, [][]byte{leaf, leaf}); err == nil {
		t.Fatal("a two-hash path for a tree of eight was accepted")
	}
}
