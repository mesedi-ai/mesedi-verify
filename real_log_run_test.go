package main

// The export of the real-log run of 16 November 2026: four hours anchored
// by Mesedi's direct anchorer on Sigstore's real public log, signed by a
// throwaway key (testdata/real-log-run-2026-11-16-key.pub.pem), with
// pending OpenTimestamps receipts from the three public calendars. It is
// the first export this verifier saw from the real log after the direct
// anchorer was written, and it caught a fault every synthetic test had
// missed. Offline, every hour must verify: its proof against Sigstore's
// key, and its signer against the trusted key.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/mesedi-ai/mesedi/backend/attest"
)

func TestTheRealLogRunVerifiesOffline(t *testing.T) {
	raw, err := os.ReadFile("testdata/real-log-run-2026-11-16-export.json")
	if err != nil {
		t.Fatal(err)
	}
	var export attest.ChainExport
	if err := json.Unmarshal(raw, &export); err != nil {
		t.Fatal(err)
	}
	if v := attest.VerifyChainExport(export); !v.OK {
		t.Fatalf("structure: %+v", v.Checks)
	}
	entries := resolveLogEntries(export, "", true)
	trusted, err := loadTrustedKeys([]string{"testdata/real-log-run-2026-11-16-key.pub.pem"})
	if err != nil {
		t.Fatal(err)
	}
	checkSigners(export, entries, trusted)
	if len(entries) != 4 {
		t.Fatalf("%d entries, want 4", len(entries))
	}
	for _, e := range entries {
		if !e.verified() || e.Method != MethodOfflineProof {
			t.Errorf("checkpoint %d: %s by %q: %s", e.Seq, e.Status, e.Method, e.Detail)
		}
		if !strings.HasPrefix(e.Signer, "key b5c65acac932d784") {
			t.Errorf("checkpoint %d signer %q", e.Seq, e.Signer)
		}
	}
	// Without the throwaway key trusted, the same hours must fail: the
	// signer check, not the proof, is what stops them.
	untrusted := resolveLogEntries(export, "", true)
	checkSigners(export, untrusted, nil)
	for _, e := range untrusted {
		if !e.failed() || !strings.Contains(e.Signer, "not a trusted key") {
			t.Errorf("checkpoint %d verified with no key trusted: %s", e.Seq, e.Signer)
		}
	}
}
