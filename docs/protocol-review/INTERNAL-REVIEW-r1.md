# Internal protocol review r1

**Status:** INTERNAL, NON-INDEPENDENT, NON-APPROVAL — **CHANGES REQUIRED**

**Date:** 2026-07-21
**Reviewer:** Codex-assisted internal review (no named independent cryptographic reviewer)
**Scope:** `secure-overlay-protocol-v1`, revision 1; the protocol-review
package; and the present `SecureOverlay` Kotlin placeholder as implementation
boundary evidence only.

This record is not an independent cryptographic audit, does not amend the
normative specification or its revision-1 handoff package, and cannot produce
an `APPROVED` decision. `REVIEW-DECISION.md` remains authoritative and remains
unchanged at **CHANGES REQUIRED**. No implementation is authorized.

## Exact inputs and integrity checks

The reviewed checkout was clean at commit
`4dd98e6fc6a4de2423ad828c277b54bb689f2219`
(`docs(security): establish protocol review gate`).  The configured `upstream`
remote is `https://github.com/DrKLO/Telegram.git`; the recorded baseline
`9bcf3d2769c6d3f07105a992e5d9493e33ac3348` resolves locally as a commit.
Remote reachability was not asserted by this review.

The manifest was verified from its required working directory:

```sh
cd telegram-secure-android/docs/protocol-review
sha256sum -c REVIEW-ARTIFACTS.sha256
```

Result: all ten manifest entries reported `OK`: the specification plus the
nine revision-1 review-package artifacts. The manifest SHA-256 for the
specification is
`de86abfe69993608d92286565a026e09f734efe9b061d8a7d861ec83559a5745`.
The earlier invocation from the repository root failed solely because the
manifest intentionally uses relative paths; it is not an artifact mismatch.

Reviewed primary inputs:

- `../secure-overlay-protocol-v1.md`, sections 1–8.
- `REVIEW-REQUEST.md`, `REVIEW-CHECKLIST.md`, `FIXTURE-COVERAGE.md`,
  `test-vectors.json`, `negative-fixtures.json`, `OPEN-ISSUES.md`, and
  `REVIEW-DECISION.md`.
- `SecureOverlay/README.md`, `SecureOverlay/build.gradle`, and
  `SecureOverlayBoundary.kt`.

## Method and review limits

This was an adversarial document-and-boundary review. It traced canonical CFS
and resource limits; identity/trust and Telegram provenance; the signed 4-DH
handshake, transcript, HKDF and confirmations; envelope AD; replay,
out-of-order and uncertain-send behavior; durable state and Keystore reset
behavior. It also compared the declared implementation boundary with the
Kotlin source and dependency declaration.

The review did not claim formal verification, primitive correctness,
implementation interoperability, Android/Telegram runtime behavior, or legal
approval. Static search and Gradle output are corroborating signals only, not
security evidence.

## Findings

| ID | Severity | Finding and evidence | Required remediation |
|---|---|---|---|
| IR1 | Critical | No maintained Signal Double Ratchet backend, Android binding, version/license, vulnerability owner, known-answer evidence, or adapter-audit scope is selected. Spec §6 expressly makes this reviewer-approved and `OPEN-ISSUES.md` item 1 blocking. | Select and pin a maintained reviewed backend; record its Android integration, license and CVE response owner; define a narrow adapter with no application ratchet implementation; audit it and add adapter vectors before review r2. |
| IR2 | High | CFS/handshake evidence is insufficient to independently establish the stated canonical parsing and four-DH construction. Although spec §§1–5 defines ordering, bounds, labels, transcript, confirmation order and all-zero rejection, `FIXTURE-COVERAGE.md` records absent dedicated X25519, full init/response CFS, four-DH, transcript and confirmation vectors. `OPEN-ISSUES.md` item 2 remains open. | Add exhaustive positive and negative CFS boundary fixtures (including nested objects and allocation limits), and a complete deterministic handshake fixture with private/public inputs, every DH output, IKM, salt, PRK, expanded keys, transcript and both confirmations. Have independent consumers reproduce it. |
| IR3 | High | Peer/chat provenance and durable-send semantics are specified as requirements, not demonstrated capabilities. Spec §§4 and 6 require an authenticated adapter and pre-submit durable send transition. `SecureOverlay` has no `TMessagesProj`, TDLib/MTProto, transport, crypto or key-material dependency and source parses no carrier; therefore it neither contradicts the gate nor supplies this evidence. `OPEN-ISSUES.md` item 3 remains open. | Produce a Telegram integration design and test plan that proves authenticated inbound sender/chat binding and identifies the exact durable-send/uncertain-submission boundary without altering TDLib or MTProto semantics. Do not wire it before approval. |
| IR4 | High | Spec §7 requires Keystore-wrapped state authentication and blocking reset on invalidation, corruption or rollback, but does not select the Android hardware/authentication policy or define the required invalidation, reinstall, rollback and corruption matrix. `OPEN-ISSUES.md` item 4 remains open. | Specify supported API/device classes, StrongBox/hardware-backed and user-auth requirements, key-generation parameters, invalidation/reinstall behavior, authenticated storage format, rollback detection and recovery UX; validate with crash and state-transition tests. |
| IR5 | High | Normative fixtures are deliberately incomplete and have not been reproduced by two independently written consumers. `FIXTURE-COVERAGE.md` explicitly identifies missing bundle/control-signature, complete handshake/confirmation, full envelope/AD/decrypt and later ratchet/storage fixtures. This blocks the interoperability claim in `OPEN-ISSUES.md` item 5. | Supply every listed fixture with exact expected bytes/errors/state mutation result and require two separately written consumers to reproduce and verify each before any interoperability or approval claim. |
| IR6 | High | The reserved `TGS1:` carrier marker and visible malformed-carrier, secure/fallback and downgrade behavior have no recorded legal/product decision. Spec §§2 and 7 reserve the marker and require visible failure/no automatic plaintext fallback; `OPEN-ISSUES.md` item 6 remains open. | Obtain and record product/legal approval for marker collision handling, user-visible secure/non-secure states, fallback warning and draft-discard UX; include acceptance tests that no marked malformed text becomes ordinary plaintext. |

## Additional observations

The specification has useful fail-closed intentions: fixed v1 suite/version,
marked-carrier handling, explicit bounds, transcript labels, authenticated
cleartext envelope fields, atomic receive-before-display behavior and blocked
uncertain sends. These are design statements, not validation of a future
implementation. In particular, no review finding above may be closed by
silently choosing behavior during coding.

The Kotlin evidence is consistent with the implementation gate: the sole
source file exposes `PROTOCOL_REVIEW_REQUIRED = true` and UI-state names. It
contains no custom ratchet, handshake, CFS/carrier parser, Telegram transport
adapter, Keystore use, plaintext fallback path, or crypto dependency. This is
not evidence that future Android storage or Telegram transport requirements
can be met.

## Build and dependency evidence

The requested Gradle unit-test and dependency-report command was attempted:

```sh
./gradlew :SecureOverlay:testDebugUnitTest :SecureOverlay:dependencies \
  --configuration debugRuntimeClasspath
```

It did not start because the current shell has no Java runtime:

```text
ERROR: JAVA_HOME is not set and no 'java' command could be found in your PATH.
```

The repository-prescribed retry was also attempted:

```sh
nix-shell --run './gradlew :SecureOverlay:testDebugUnitTest \
  :SecureOverlay:dependencies --configuration debugRuntimeClasspath --console=plain'
```

It was blocked before Gradle by the restricted environment:

```text
error: cannot connect to socket at '/nix/var/nix/daemon-socket/socket': Operation not permitted
```

Thus no unit-test result and no resolved Gradle dependency graph are available
from this environment. Source-level evidence shows `SecureOverlay/build.gradle`
declares no dependencies and `SecureOverlay/src/test` is absent. This supports
only the narrow conclusion that the checked-in placeholder declares no crypto
or transport dependency; it does not replace a successful dependency report,
license review, CVE scan, or test run.

## Disposition of `OPEN-ISSUES.md`

| Open issue | Internal disposition | Closure evidence required for r2 |
|---|---|---|
| 1. Ratchet backend | Open; IR1 | Named/pinned maintained backend, license/CVE ownership, adapter audit and vectors. |
| 2. Handshake/CFS | Open; IR2 | Independent construction review plus complete canonical and 4-DH/confirmation vectors. |
| 3. Telegram provenance/durable send | Open; IR3 | Adapter feasibility/design evidence and tests against the actual Telegram boundary. |
| 4. Keystore policy | Open; IR4 | Approved Android Keystore/state matrix and crash/rollback validation. |
| 5. Full vectors | Open; IR5 | Full machine-readable vectors reproduced by two independent consumers. |
| 6. Carrier/UX legal approval | Open; IR6 | Recorded legal/product approval and UX acceptance evidence. |

## Required revision-2 package

Before asking for a renewed external review, revision 2 must:

1. Resolve each of IR1–IR6 in writing without changing v1 semantics by
   implication.
2. Revise the specification where needed to make parser field constraints,
   storage/Keystore policy and Telegram adapter/durable-send boundaries
   implementable and testable.
3. Include complete deterministic bundle, control-signature, four-DH,
   transcript, HKDF, confirmation, envelope-AD/decrypt, ratchet-adapter and
   storage/crash fixtures, with exact state-mutation expectations.
4. Record independent reproduction of all normative fixtures by two separately
   written consumers and a named independent reviewer’s scope and decision.
5. Re-run Gradle unit tests, resolve and retain the dependency report, then use
   dependency/static scanning only as supplemental evidence.
6. Create a new revision-specific manifest and handoff; preserve revision 1
   artifacts unchanged as the historical package.

## Final conclusion

**CHANGES REQUIRED.** The protocol remains implementation-blocked. This
internal, non-independent review neither authorizes implementation nor changes
the standing decision; a later `APPROVED` decision requires a named independent
external reviewer and written closure or explicit acceptance of every blocking
issue.
