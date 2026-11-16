# mesedi-verify

Standalone, independent verifier for a Mesedi chain export. It exists
so an auditor never has to take Mesedi's word for anything: given an
export file, it recomputes every hash from the export's own contents,
then resolves each checkpoint against a public transparency log
(Sigstore Rekor) that neither Mesedi nor Verdifax controls. Mesedi is
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

## What a run checks

- Every hash in the export, recomputed from the export's own contents.
- That each checkpoint is in the public log, and **when** the log
  recorded it. A checkpoint published more than 2 hours after its hour
  ended still verifies, but the report says how late: a late anchor
  proves the record existed when it was published, not when its hour
  ended. Offline runs cannot check this; the report says so.
- A log that cannot be reached, or answers with a server error, makes a
  checkpoint UNVERIFIABLE, never FAILED: the record is not known to be
  wrong, it just could not be checked.
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
here so it stands alone from the system it verifies, the same way
verdifax-verify stands alone from verdifax-orchestrator. Verification
reports issued before the extraction pin a mesedi commit; those
instructions remain valid, because the pinned commits still contain
the tool. The extraction commit in this repository names the exact
mesedi commit the files came from.

## License

MIT. See LICENSE.
