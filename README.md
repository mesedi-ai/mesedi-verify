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
    mesedi-verify --offline export.json     no network; the stronger check
    mesedi-verify --rekor <url> export.json

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
