# mesedi-verify

Standalone, independent verifier for a Mesedi chain export. It exists
so an auditor never has to take Mesedi's word for anything: given an
export file, it recomputes every hash from the export's own contents,
then resolves each checkpoint against a public transparency log
(Sigstore Rekor) that Mesedi does not control. Mesedi is
not contacted and no Mesedi credential is used.

## Build it yourself

A verdict from a program the audited party gave you is that party
speaking again. Build from source:

    git clone https://github.com/mesedi-ai/mesedi-verify
    cd mesedi-verify
    go build .

To reproduce the verifier named in a Mesedi verification report, check
out the version the report states before building.

## Usage

    mesedi-verify export.json               verify, print a human report
    cat export.json | mesedi-verify         verify from stdin
    mesedi-verify --json export.json        machine-readable
    mesedi-verify --pdf out.pdf export.json also write a PDF report
    mesedi-verify --offline export.json     no network; checks the stored proofs
                                            against Sigstore's key, but not WHEN
                                            each hour was published
    mesedi-verify --rekor <url> export.json
    mesedi-verify --trusted-key key.pem export.json
                                            also trust anchors signed by this
                                            public key (a self-hosted
                                            deployment's own); may be repeated
    mesedi-verify --bitcoin-api <url> export.json
                                            the block explorer used to read
                                            Bitcoin blocks (default
                                            https://blockstream.info/api)
    mesedi-verify --late-after 30m export.json
                                            call an hour late once it was
                                            published more than this after it
                                            ended (default 2h)
    mesedi-verify --max-late 24h export.json
                                            an hour published more than this
                                            after it ended makes the run
                                            INCOMPLETE (default: no maximum)
    mesedi-verify --require-signer-all export.json
                                            require a trusted signature on
                                            every hour, including hours
                                            published before 16 November 2026

## What a run checks

- Every hash in the export, recomputed from the export's own contents.
- That each checkpoint is in the public log, and **when** the log
  recorded it. Every hour's delay is shown. One published more than 2
  hours after its hour ended (`--late-after`) is called late, and the
  result line names it: a late anchor proves the record existed when it
  was published, not when its hour ended. An auditor can set a maximum
  with `--max-late`; hours beyond it make the run INCOMPLETE. Offline
  runs cannot check timing; the report says so.
- **Who signed** each log entry. Since 16 November 2026 Mesedi signs
  every anchor with its own key. The entry must name one of Mesedi's
  published keys (or one passed with `--trusted-key`), its signature
  must verify, and the anchored text must be exactly this hour's.
  Hours anchored before then went through a third-party service; the
  report says their signer is not checked. Which hours count as
  "before" is decided from Sigstore's own signed data (the hour's
  position in the log), never from the export, so an export cannot
  switch the check off. `--require-signer-all` requires a trusted
  signature on every hour.
- **Bitcoin timestamps.** Each hour since 16 November 2026 is also
  timestamped in Bitcoin through OpenTimestamps, independently of
  Sigstore. A complete receipt must lead to its block's real Merkle
  root. Offline, the report names the block and the value, which any
  Bitcoin node can confirm. A pending receipt is not a failure; a false
  one is.
- A log that cannot be reached, or answers with a server error, makes a
  checkpoint UNVERIFIABLE, never FAILED: the record is not known to be
  wrong, it just could not be checked.
- Agent runs that received events after their hour was anchored are
  named: those events are kept, but the anchor does not cover them.
- **One verdict.** The exit code, the JSON (`verdict` and `ok`), the
  text RESULT line and the PDF all read the same result: FAILED if any
  check failed (the record, a checkpoint, the log's growth or a Bitcoin
  receipt), INCOMPLETE if something could not be established, and
  VERIFIED only otherwise.
- Exports in format v2 (Mesedi from 16 November 2026) may mark agent
  runs whose records were deleted under retention, and hours recorded
  before Mesedi stored each run's fingerprint. Both are reported as
  limits of what can be checked, not as failures.

## Exit codes

    0  Every check passed and every checkpoint was actually checked.
    1  A check failed, or a checkpoint could not be checked at all.
       Both are non-zero on purpose: a pipeline gating on exit 0 must
       not go green for a chain nobody was able to verify.
    2  The export could not be read or parsed, or a requested report
       could not be written. Separate from 1 on purpose: "we could not
       run the check" and "the check failed" must not look alike.

## History

This tool lived at backend/cmd/mesedi-verify in
https://github.com/mesedi-ai/mesedi until 2026-09-28 and was extracted
here so it stands alone from the system it verifies. Verification
reports issued before the extraction pin a mesedi commit; those
instructions remain valid, because the pinned commits still contain
the tool. The extraction commit in this repository names the exact
mesedi commit the files came from.

## License

MIT. See LICENSE.
