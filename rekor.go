package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Resolving checkpoints against the public transparency log.
//
// This is the file that makes the report evidence rather than
// self-assessment. Everything else in this binary checks that Mesedi's
// export is internally consistent, which a Mesedi that lied consistently
// would also pass. Only asking a log Mesedi does not control whether a given hash is actually in it breaks that circle.
//
// WHAT IS CHECKED: that the entry at the claimed log index is a
// hashedrekord whose recorded sha256 is the checkpoint's hash.
//
// Since 2026-11-16, also WHEN: the log's recorded time is compared with
// the hour the checkpoint covers, and a late anchor is named.
//
// This lookup does not check the log's signed tree head. The offline path
// does (offline.go and rekorproof.go): the inclusion proof stored with each
// checkpoint at anchor time is checked against Rekor's public key embedded
// in rekorproof_pubkey.go, so a checkpoint still verifies when the log is
// unreachable or retired. Neither path yet checks WHO signed the entry;
// that comes with Mesedi's own anchoring key. (This comment said the tree
// head was never checked and that proofs were discarded at anchor time;
// both stopped being true when the offline path shipped, outside review
// the outside review of 2026-11-15.)

// DefaultRekorURL is Sigstore's public good instance, free, with a 99.5%
// availability SLO, and operated by neither party to this transaction,
// which is the entire reason it is worth anchoring to.
const DefaultRekorURL = "https://rekor.sigstore.dev"

// Three outcomes, not two.
//
// A checkpoint that cannot be checked is not a checkpoint that failed,
// and a verifier with only pass/fail is forced to lie about one of them.
// Reporting an uncheckable anchor as tampering accuses Mesedi of
// something it is not known to have done; reporting it as a pass tells
// the reader a check happened that did not. Both are falsehoods, in
// opposite directions, and the honest answer needs its own word.
const (
	// StatusVerified: the log holds this checkpoint's leaf at the index
	// it claims, and the leaf commits to this checkpoint's hash.
	StatusVerified = "verified"

	// StatusFailed: the log disagrees with the export. A finding.
	StatusFailed = "failed"

	// StatusUnverifiable: the export does not carry what is needed to
	// check this entry, or no public-log claim was made for it. NOT a
	// finding against the record, an absence of evidence either way.
	StatusUnverifiable = "unverifiable"
)

// LogEntryCheck is the outcome of resolving one checkpoint.
type LogEntryCheck struct {
	Seq      uint64
	LogIndex string
	Status   string

	// Signer says who signed the log entry: the fingerprint of a trusted
	// key for an anchor Mesedi made itself, or why it was not checked.
	// Filled by checkSigners after the entry is resolved.
	Signer string
	Detail string

	// Integrated is when the log says it incorporated the entry. Zero
	// unless the entry was actually retrieved.
	Integrated time.Time

	// LateBy is how long after its hour ended the log recorded the entry,
	// when that exceeds lateAnchorTolerance. Zero when on time or when no
	// time was available.
	LateBy time.Duration

	// TimeChecked is true when the log's recorded time was compared with
	// the hour the checkpoint covers. A stored inclusion proof carries no
	// time, so an offline run never sets it, and an online run sets it
	// only when the log answered with a time.
	TimeChecked bool

	// Method names which check produced Status. Empty when the entry was
	// settled before either ran, a mock ledger, say, or a missing
	// preimage.
	Method string

	// ProofNote records that an anchor proof was present but could not be
	// used, and why. Kept separate from Detail because the outcome
	// belongs to whichever check did decide; this says what was offered
	// and declined. Without it an unusable proof vanishes from the
	// report, which reads exactly like none having been offered.
	ProofNote string
}

// How a checkpoint's anchor was checked. The two are not equally strong
// and a reader must not have to guess which one produced a given line.
//
// MethodOfflineProof is the stronger. A log lookup asks the log what it
// holds TODAY and believes the answer, so it trusts whoever is serving
// that endpoint. An inclusion proof carries Sigstore's own signature
// over a tree head: it cannot be forged by whoever answers the request,
// and it remains valid after the log itself is retired.
const (
	MethodOfflineProof = "inclusion proof, offline"
	MethodLogLookup    = "log lookup, network"
)

func (c LogEntryCheck) verified() bool     { return c.Status == StatusVerified }
func (c LogEntryCheck) failed() bool       { return c.Status == StatusFailed }
func (c LogEntryCheck) unverifiable() bool { return c.Status == StatusUnverifiable }

type rekorClient struct {
	baseURL string
	http    *http.Client
}

func newRekorClient(baseURL string) *rekorClient {
	return &rekorClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		// A generous but finite timeout. An auditor running this against a
		// month of checkpoints makes hundreds of calls; hanging on one is
		// worse than failing it, because a hang looks like a broken tool
		// rather than a reachability problem.
		http: &http.Client{Timeout: 20 * time.Second},
	}
}

// rekorEntry is the subset of Rekor's response this needs.
//
// The json tags are camelCase because they are REKOR'S wire names, not
// ours. They cannot be renamed to match this repo's snake_case convention
// without simply failing to parse the log's responses. The audit's E13
// check assumes every struct describes something we control; this one
// describes somebody else's API, and the foreign format wins.
//
// The API returns an object keyed by entry UUID, so the shape is
// map[string]rekorEntry with exactly one member. Body is base64 of the
// canonicalised entry JSON.
type rekorEntry struct {
	Body           string `json:"body"`
	LogIndex       int64  `json:"logIndex"`
	IntegratedTime int64  `json:"integratedTime"`
	LogID          string `json:"logID"`
}

// hashedRekordBody is the decoded Body: the recorded digest, and the
// signature and public key that say who submitted it (checked in
// signer.go for anchors Mesedi signs itself).
type hashedRekordBody struct {
	Kind string `json:"kind"`
	Spec struct {
		Signature struct {
			Content string `json:"content"`
			// Untagged: Sigstore names it publicKey, and encoding/json
			// matches an untagged field case-insensitively.
			PublicKey struct {
				Content string `json:"content"`
			}
		} `json:"signature"`
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
	} `json:"spec"`
}

// lookup fetches the entry at a log index and returns the sha256 it records.
func (c *rekorClient) lookup(ctx context.Context, logIndex string) (string, time.Time, error) {
	idx, err := strconv.ParseInt(logIndex, 10, 64)
	if err != nil || idx < 0 {
		return "", time.Time{}, fmt.Errorf(
			"log entry id %q is not a log index; this verifier expects the decimal "+
				"index Rekor returns on submission", logIndex)
	}

	endpoint := fmt.Sprintf("%s/api/v1/log/entries?logIndex=%s",
		c.baseURL, url.QueryEscape(logIndex))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", time.Time{}, logUnreachable{fmt.Errorf("could not reach the transparency log: %w", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// The sharpest possible finding: a checkpoint claiming an entry
		// the log does not have. Named explicitly rather than folded into
		// a generic HTTP error, because this is the one result that means
		// the record was never published.
		return "", time.Time{}, fmt.Errorf(
			"the log has no entry at index %s. The checkpoint claims to have been "+
				"published there and it was not", logIndex)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", time.Time{}, logUnreachable{fmt.Errorf("transparency log returned %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))}
	}

	// 4 MiB is far more than an entry needs and bounds a hostile or broken
	// endpoint; without it a malicious response could exhaust memory on the
	// auditor's machine.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", time.Time{}, err
	}

	var entries map[string]rekorEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return "", time.Time{}, fmt.Errorf("could not parse the log's response: %w", err)
	}
	if len(entries) != 1 {
		return "", time.Time{}, fmt.Errorf(
			"expected exactly one entry at index %s, the log returned %d",
			logIndex, len(entries))
	}

	var entry rekorEntry
	for _, e := range entries {
		entry = e
	}

	// The log must agree about which index this is. A response for a
	// different index would mean a redirect, a proxy, or a substitution.
	if entry.LogIndex != idx {
		return "", time.Time{}, fmt.Errorf(
			"asked the log for index %d and it answered with index %d",
			idx, entry.LogIndex)
	}

	bodyJSON, err := base64.StdEncoding.DecodeString(entry.Body)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("entry body is not valid base64: %w", err)
	}
	var decoded hashedRekordBody
	if err := json.Unmarshal(bodyJSON, &decoded); err != nil {
		return "", time.Time{}, fmt.Errorf("entry body is not valid JSON: %w", err)
	}
	if decoded.Kind != "hashedrekord" {
		return "", time.Time{}, fmt.Errorf(
			"entry at index %s is a %q, not a hashedrekord", logIndex, decoded.Kind)
	}
	if alg := decoded.Spec.Data.Hash.Algorithm; alg != "sha256" {
		return "", time.Time{}, fmt.Errorf(
			"entry at index %s records a %s digest; this chain uses sha256", logIndex, alg)
	}

	var integrated time.Time
	if entry.IntegratedTime > 0 {
		integrated = time.Unix(entry.IntegratedTime, 0).UTC()
	}
	return strings.ToLower(decoded.Spec.Data.Hash.Value), integrated, nil
}

// logUnreachable marks a lookup that could not get an answer from the log:
// a network error, a timeout, or any response other than 200 or 404. The
// record may be fine; the log could not be asked. Reported UNVERIFIABLE.
// Until 2026-11-16 these were reported FAILED, the word reserved for "the
// log disagrees with the export", contradicting the three-outcome rule
// above (the outside review of 2026-11-15). A 404 stays a failure: it means the
// log answered and has no such entry.
type logUnreachable struct{ err error }

func (u logUnreachable) Error() string { return u.err.Error() }
func (u logUnreachable) Unwrap() error { return u.err }

// lateAnchorTolerance is how long after its hour ends a checkpoint may be
// published and still count as on time. The scheduler publishes within
// minutes; anything later is catch-up after downtime, or backdating, and
// the report names it (Robert's decision, 2026-11-16; the outside review of 2026-11-15).
const lateAnchorTolerance = 2 * time.Hour
