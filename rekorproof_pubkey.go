package main

// RekorPublicKeyPEM is Sigstore's production Rekor public key, the key
// that signs every checkpoint of the public log at rekor.sigstore.dev.
// It is the one trusted root of offline verification: a checkpoint whose
// signature verifies against it is the log's own statement of its tree.
//
// Source: https://rekor.sigstore.dev/api/v1/log/publicKey, first pinned
// 2026-05-29 and re-read and confirmed identical on 2026-11-16.
//
// To check it yourself, compute its log ID and compare it with the logID
// field of any recent entry on the public log (also shown at
// https://search.sigstore.dev/?logIndex=<any index>):
//
//	openssl pkey -pubin -in key.pem -outform DER | shasum -a 256
//
// It must be c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d.
// TestEmbeddedKeyIsTheProductionRekorKey pins that value. A change to this
// constant changes what the verifier trusts, and deserves the scrutiny of
// a change to a system's certificate store. If Sigstore rotates its key,
// the old key stays valid for entries it signed; this would then become a
// list tried in turn.
const RekorPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr
kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==
-----END PUBLIC KEY-----
`
