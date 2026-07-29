# Ratchet backend selection dossier

**Status:** TECHNICAL INTEGRATION IN PROGRESS — `org.signal:libsignal-android`
`0.86.6` is selected for private-group MVP evaluation. This is not an
independent cryptographic approval and does not close the review blockers.

Signal's [`libsignal`](https://github.com/signalapp/libsignal) is an
evaluation candidate only. Mentioning it here is not integration approval.

## Screening log — 2026-07-22

The product is a privately shared APK for the owner and friends. On
2026-07-22, the product owner chose to provide corresponding source and notices
to every APK recipient, allowing an AGPLv3 dependency for this MVP. This does
not relax cryptographic, maintenance, or state-transaction requirements.

| Candidate | Result | Evidence and reason |
|---|---|---|
| Signal `libsignal` `0.86.6` | Selected for technical MVP evaluation | The upstream README licenses it under AGPLv3 and says use outside Signal is unsupported and its APIs/implementations may change without notice. `0.98.0` was rejected for this AGP 8.6 fork because D8 cannot dex its Java 21 Record bytecode; `0.86.6` exposes the required 1:1/PQ API as Java 17 bytecode. Source and notices must accompany every shared APK; the project owns compatibility testing and upgrades. Android ABI/API packaging and a session-adapter proof remain mandatory before any secure feature is enabled. |
| Matrix Rust Components Kotlin `crypto` AAR | Rejected | The wrapper is active, Android-capable and Apache-2.0, but it distributes Matrix Rust SDK crypto. Its documented state machine takes Matrix user/device IDs, receives homeserver sync changes and emits homeserver requests. It cannot satisfy the required transport-free Telegram adapter boundary without embedding Matrix protocol/state semantics or writing a new ratchet integration. |
| Android Olm SDK wrapper | Rejected | Its Android wrapper release line is stale and lacks the required current maintenance/CVE ownership evidence. Apache-2.0 alone is not sufficient. |

**Result:** no permissive candidate passed the shortlist. `libsignal` is used
under the accepted AGPLv3 distribution condition; do not implement a substitute
Double Ratchet. Its adapter must still prove isolated 1:1 operation and atomic
application-controlled storage before any secure feature is enabled.

## Candidate approval record

The named **security owner** and **legal owner** must complete and sign this
record for a specific candidate before code is added.

| Required decision | Required evidence | Owner | Status |
|---|---|---|---|
| Android API/minSdk/ABI support | Reproducible Android build and device test for every supported ABI/API | Android security owner (unassigned) | Open |
| License and redistribution | License text, dependency tree, NOTICE obligations, legal approval | Legal owner (unassigned) | Open |
| Maintenance and CVE ownership | Upstream support statement, update SLA, CVE monitoring inbox and named responder | Security owner (unassigned) | Open |
| Test-vector capability | Backend-specific known-answer/interoperability evidence and deterministic test seam | Security owner (unassigned) | Open |
| Adapter boundary | Independent audit of root-key input, peer binding, skipped-key bound, commit ordering and errors | Protocol reviewer (unassigned) | Open |

## Non-negotiable adapter contract

Only a narrow adapter may call the selected backend. It receives a 32-byte
handshake root key, fixed initiator/responder role, 16-byte session ID, and
verified owner/device binding. It returns an opaque AEAD message-key operation
and public ratchet header fields. It must enforce a 256-key/gap limit and
stage, then atomically commit, receive state only after AEAD success.

Application code MUST NOT implement ratchet DH, chain KDFs, skipped keys,
header cryptography, or backend persistence formats. The adapter MUST expose
typed `REPLAY`, `OUT_OF_ORDER_LIMIT`, `AUTH_FAILED`, `STORAGE_FAILED`, and
`SEND_OUTCOME_UNKNOWN` outcomes.

## Rejection criteria

Reject a candidate if any supported Android target cannot build reproducibly;
the license is not approved; a named party does not own CVE response; vectors
cannot be reproduced; the adapter requires exporting ratchet secrets into app
logic; or its state cannot be transactionally staged/committed with the
required failure semantics.
