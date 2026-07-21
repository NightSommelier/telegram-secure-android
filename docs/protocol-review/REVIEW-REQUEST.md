# Request for independent cryptographic review

## Requested decision

Please review **Telegram Secure overlay protocol v1, revision 1** and issue one written decision:

- **APPROVED** — the protocol specification is suitable to authorize the isolated implementation phase, subject to recorded conditions; or
- **CHANGES REQUIRED** — list findings, severity and required disposition.

A review of source code is not requested at this stage. No production handshake, ratchet, carrier parser or Telegram integration is authorized yet.

## In-scope artifact set

1. `../secure-overlay-protocol-v1.md`
2. `test-vectors.json`
3. `negative-fixtures.json`
4. `REVIEW-CHECKLIST.md`
5. `FIXTURE-COVERAGE.md`
6. `OPEN-ISSUES.md`

## Review questions

1. Is CFS canonical and resource-bounded enough for hostile Telegram text carriers?
2. Does the identity bundle and Telegram adapter boundary provide the claimed peer/device binding?
3. Is the signed X25519 handshake, transcript, HKDF domain separation and confirmation ordering sound?
4. Is the selected ratchet boundary sufficient to avoid a custom ratchet implementation?
5. Does authenticated envelope metadata/AD prevent cross-peer, cross-device, cross-session and downgrade substitution?
6. Do replay, out-of-order, transaction, uncertain-send, Keystore-reset and corruption rules fail closed?
7. Are security claims and exclusions correctly scoped?

## Required reviewer output

Record reviewer name/organization, date, reviewed revisions, scope, findings and final decision in `REVIEW-DECISION.md`. An approval must explicitly resolve or accept each item in `OPEN-ISSUES.md`; it is invalid if it merely approves a different future implementation.
