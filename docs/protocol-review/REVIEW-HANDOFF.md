# Review handoff procedure

This package is ready to be given to an external independent cryptographic
reviewer. It is not a request to implement or release the overlay.

## Send exactly these artifacts

1. `../secure-overlay-protocol-v1.md`
2. `README.md`
3. `REVIEW-REQUEST.md`
4. `REVIEW-CHECKLIST.md`
5. `FIXTURE-COVERAGE.md`
6. `test-vectors.json`
7. `negative-fixtures.json`
8. `OPEN-ISSUES.md`
9. `REVIEW-DECISION.md`

Before sending, create and retain a checksum manifest from the Telegram fork
root. This pins the reviewed bytes without treating a mutable branch name as
the reviewed revision:

```sh
cd docs/protocol-review
sha256sum ../secure-overlay-protocol-v1.md README.md REVIEW-REQUEST.md \
  REVIEW-CHECKLIST.md FIXTURE-COVERAGE.md test-vectors.json \
  negative-fixtures.json OPEN-ISSUES.md REVIEW-DECISION.md \
  > REVIEW-ARTIFACTS.sha256
```

Give the resulting `REVIEW-ARTIFACTS.sha256` to the reviewer with the package.
If any listed file changes, generate a new manifest and request review of the
new revision; do not carry an approval forward by implication.

Before accepting a returned decision, verify the received package from
`docs/protocol-review`:

```sh
sha256sum -c REVIEW-ARTIFACTS.sha256
```

The manifest deliberately does not hash itself. Record the manifest SHA-256
and the Git commit containing it in the review record. A changed artifact
requires a new manifest, a new recorded scope, and a new decision.

## Required return

The reviewer must complete `REVIEW-DECISION.md` or provide a signed document
containing the same fields. The project owner records the reviewer’s decision,
findings, scope, artifact-manifest digest and disposition in the repository.
Only an explicit `APPROVED` decision that closes the blocking issues permits
the isolated SecureOverlay implementation phase.

## Current stop condition

The decision is currently `CHANGES REQUIRED`. The package identifies missing
ratchet-backend selection and complete, independently reproduced
interoperability vectors as blockers. No production handshake, ratchet,
carrier parser, persistence, Telegram adapter or secure UI may be added while
that state remains.
