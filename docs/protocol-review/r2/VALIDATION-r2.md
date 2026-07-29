# Revision 2 validation record

**Date:** 2026-07-21
**Scope:** test-only fixture consumers and existing repository unit tests. This
does not select a ratchet backend or approve implementation.

| Check | Result | Environment / evidence |
|---|---|---|
| Go fixture consumer | PASS | Go 1.26.3; `GOCACHE=/tmp/telegram-encryption-r2-gocache GONOSUMDB='*' GOPROXY=off go test ./...` in `consumers/go` |
| Kotlin fixture consumer | PASS | Kotlin 2.3.21 compiled independently; executed on OpenJDK 17.0.20+2 with `fixtures.json` |
| Gradle unit tests | PASS | `nix-shell --run './gradlew test dependencies --console=plain'`; Android Gradle Plugin 8.7.3, Kotlin plugin 2.0.21 |
| Resolved dependency report | PASS | `:secure-protocol:dependencies --configuration debugRuntimeClasspath`; includes Tink Android 1.23.0 and Kotlin stdlib 2.0.21 |
| r2 manifest | PASS | `sha256sum -c R2-ARTIFACTS.sha256` from this directory |
| r1 manifest | PASS | `sha256sum -c REVIEW-ARTIFACTS.sha256` from `../` |
| Scope boundary | PASS | Git status shows only untracked `r2/` plus the pre-existing untracked `INTERNAL-REVIEW-r1.md`; r2 contains review docs, fixtures, and test-only consumers only |

The Kotlin consumer validates CFS/signature reproduction, all four X25519 DH
values through the derived IKM, HKDF extract/expand, initiator confirmation,
envelope CFS associated-data hash, and every negative-fixture error mapping
without plaintext fallback. The Go consumer independently verifies
CFS/signatures, four DH values, envelope AD, XChaCha20-Poly1305 encryption,
tamper rejection, and every negative-fixture mapping while preserving its
test state generation. Neither consumer is production code; these test models
do not implement a ratchet or persistent storage.
