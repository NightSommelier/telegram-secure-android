# Revision 2 evidence package

This is a separate, implementation-blocked review package for revision 2 of
the secure-overlay proposal. It does not modify, supersede, or authorize the
revision-1 package. `../REVIEW-DECISION.md` remains **CHANGES REQUIRED**.

The package deliberately contains no production Android, Telegram, Keystore,
ratchet, or UI integration. Test-only consumers are under `consumers/` and
are restricted to fixture reproduction.

## Contents

- `RATCHET-BACKEND-DOSSIER.md` — selection gate; no backend is selected.
- `PROTOCOL-CLARIFICATIONS-r2.md` — only previously underspecified rules.
- `fixtures.json` and `negative-fixtures.json` — normative deterministic data.
- `STATE-AND-TRANSPORT-PACKETS.md` — owner-assigned external decision packets.
- `EXTERNAL-DECISION-RECORDS.md` — fill-in evidence records for IR1/3/4/6.
- `REVIEW-RECORD-r2.md` — IR/open-issue closure mapping.
- `consumers/kotlin` and `consumers/go` — independently written test-only
  fixture consumers; neither is application code.
- `R2-ARTIFACTS.sha256` — manifest generated from this directory.

All private keys and symmetric material in fixtures are public test material.
They MUST NOT be imported into an application.
