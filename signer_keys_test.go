package main

import "testing"

// The verifier trusts exactly Mesedi's two published keys, by these
// fingerprints (as published on mesedi.ai/docs/evidence). A changed or
// added key fails here, so what the verifier trusts never changes by
// accident.
func TestMesediPublishedKeysArePinned(t *testing.T) {
	want := []string{
		"eccad116fe144bd3ca0da53453eac1180d0981e0833ff756b18580c3648e5247",
		"f7ad3f9ce0b4e55ae144ed574944b9b1854cd8b0c7461f1941484a191a041e44",
	}
	keys, err := loadTrustedKeys(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != len(want) {
		t.Fatalf("%d published keys pinned, want %d", len(keys), len(want))
	}
	for i, k := range keys {
		if k.fingerprint != want[i] {
			t.Errorf("published key %d has fingerprint %s, want %s", i+1, k.fingerprint, want[i])
		}
	}
}
