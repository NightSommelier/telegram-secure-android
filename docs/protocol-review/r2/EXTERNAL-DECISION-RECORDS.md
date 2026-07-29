# External decision records — revision 2

These records are intentionally blank. A completed record needs a named owner,
date, evidence location, and explicit accept/reject outcome. A checkbox or
candidate name alone does not close an issue.

## IR1 — ratchet backend, security and legal approval

| Field | Required entry |
|---|---|
| Candidate repository, immutable revision, Android artifact and ABI set | |
| Required Android minSdk/target APIs and device evidence | |
| License, redistribution/NOTICE obligations and legal decision | |
| Maintenance channel, CVE feed, response SLA and named security owner | |
| Deterministic vector/interoperability evidence | |
| Adapter audit report and reviewer | |
| Rejection criteria checked | |
| Decision (`APPROVE` / `REJECT`) | |
| Security owner / legal owner / date | |

Approval is invalid unless every row has evidence and the candidate is pinned
by immutable source and artifact digests in a subsequent approved revision.

## IR3 — Telegram provenance and durable send

| Field | Required entry |
|---|---|
| TDLib version and Android integration boundary tested | |
| Test-account identifiers (redacted) and account-directory isolation proof | |
| Inbound account/chat/sender/message/update provenance evidence | |
| Update ordering/deduplication evidence | |
| Durable send receipt fields and correlation method | |
| Timeout, process death, callback loss, and unknown-outcome captures | |
| Logout/deletion evidence | |
| Telegram policy/API decision for `TGS1:` carrier | |
| Decision (`FEASIBLE` / `NOT FEASIBLE`) and owner/date | |

Only `FEASIBLE` plus every evidence item permits a later integration proposal.
Any ambiguous send remains `SEND_OUTCOME_UNKNOWN`.

## IR4 — Android Keystore and storage policy

| Field | Required entry |
|---|---|
| Supported device/API matrix and hardware-backed requirement | |
| Key algorithm, wrapping hierarchy and user-auth policy | |
| Chosen authenticated transactional store and schema version | |
| Backup/export policy and restore behavior | |
| Invalidation, biometric/PIN change, reinstall and corruption results | |
| Rollback and crash-at-transaction-boundary results | |
| Reset-marker format, retention and user-visible recovery flow | |
| Owner/date and decision | |

The decision must demonstrate monotonic generation handling and no silent
recreation of secure state.

## IR6 — carrier and secure/fallback UX approval

| Field | Required entry |
|---|---|
| Jurisdiction/policy review and legal decision | |
| Product owner decision for reserved carrier marker | |
| Rejected-carrier, unsupported-version and auth-failure screenshots | |
| Explicit leave-secure warning and draft-discard copy | |
| Proof that a secure draft cannot auto-send as plaintext | |
| Accessibility and notification-copy review | |
| Usability-test evidence and known limitations | |
| Product owner / legal owner / date | |

Neither an ordinary text message nor a malformed marked carrier may perform a
security-state transition.
