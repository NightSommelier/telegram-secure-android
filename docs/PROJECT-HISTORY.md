# Telegram Secure project history

This journal records security-relevant project decisions and their evidence.
Tracked documentation and Git history are the source of truth; this journal
does not grant implementation authority.

## 2026-07-21 — protocol-review baseline established

**Event:** Pinned the Telegram fork to upstream commit
`9bcf3d2769c6d3f07105a992e5d9493e33ac3348` (`update to 12.9.0 (6966)`) and
prepared **Telegram Secure overlay protocol v1, revision 1** for independent
cryptographic review.

**Decision:** `CHANGES REQUIRED`. This is a review-only baseline. No
production crypto, carrier parser, durable secure-state storage, Telegram
adapter, or secure UI is authorized.

**Evidence:**

- [Fork record](../FORK.md) and the upstream pin above.
- [Review request](protocol-review/REVIEW-REQUEST.md),
  [decision template](protocol-review/REVIEW-DECISION.md),
  [checklist](protocol-review/REVIEW-CHECKLIST.md),
  [fixture coverage](protocol-review/FIXTURE-COVERAGE.md), and
  [blocking issues](protocol-review/OPEN-ISSUES.md).
- The exact review bytes are pinned by
  [REVIEW-ARTIFACTS.sha256](protocol-review/REVIEW-ARTIFACTS.sha256); its
  handoff and verification procedure is in
  [REVIEW-HANDOFF.md](protocol-review/REVIEW-HANDOFF.md).
- A prior local validation of the parent protocol sandbox could not reproduce
  its Nix build: resolving `<nixpkgs>` required the Nix flake registry, but
  DNS/network access was unavailable; direct Gradle also had no JDK in
  `PATH`. This is environment evidence, not a source test result. See
  [`../SECURITY_READINESS_AUDIT.md`](../../SECURITY_READINESS_AUDIT.md),
  “Test and build evidence”.
- The fork's isolated `SecureOverlay` command
  `nix-shell --run './gradlew :SecureOverlay:assembleDebug :SecureOverlay:testDebugUnitTest --console=plain'`
  completed successfully on 2026-07-21 with JDK 17, after access to the local
  Nix daemon was available. It ran no unit-test sources (`NO-SOURCE`); it is a
  baseline build result, not protocol approval or interoperability evidence.

**Blocking issues:** named and pinned maintained Signal Double Ratchet backend
and adapter scope; independent review of handshake/CFS/limits/labels;
authenticated Telegram peer/chat provenance and durable-send boundary;
Keystore reset/rollback/corruption policy; complete independently reproduced
vectors with two consumers; legal/product approval of the carrier marker and
secure/fallback UX. The authoritative list is
[OPEN-ISSUES.md](protocol-review/OPEN-ISSUES.md).

**Current gate:** `CHANGES REQUIRED` in
[REVIEW-DECISION.md](protocol-review/REVIEW-DECISION.md).

**Next external step:** give the exact manifest-bound package to a named,
independent cryptographic reviewer and obtain a written decision. Only an
explicit `APPROVED` that closes or expressly accepts every blocking issue can
open the isolated implementation phase.
