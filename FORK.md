# Telegram Secure fork record

## Status

This directory is the local upstream checkout for the **Telegram Secure** product fork. It is not yet a published product fork and does not contain secure-overlay implementation changes.

## Upstream baseline

- Upstream remote: `https://github.com/DrKLO/Telegram.git`
- Local remote name: `upstream`
- Pinned commit: `9bcf3d2769c6d3f07105a992e5d9493e33ac3348`
- Upstream subject: `update to 12.9.0 (6966)`
- Checkout date: 2026-07-21

Do not merge upstream changes without recording the resulting commit, reviewing conflicts, and running the fork compatibility test suite.

## Product boundary

Telegram Secure preserves Telegram’s client/server protocol behavior. Secure functionality is an isolated content-encryption overlay for explicitly supported clients; it must not modify MTProto, Telegram servers, request pacing, privacy controls, or rate-limit handling.

The protocol sandbox in the parent directory is not part of this upstream codebase. No code may be copied from it into this fork until the protocol specification and independent review gates in `../chatgpt-plan.md` §25A.4 and §25A.8 are satisfied.

## Required before a distributable build

1. Add a product remote (`origin`) owned by the project; retain `upstream` unchanged.
2. Choose a unique application ID, signing keys, Firebase configuration and Telegram `api_id`/`api_hash`. Never commit secrets, production keystores or service credentials.
3. Complete trademark/legal review. Upstream’s README requires that an app using the Telegram name makes its unofficial status clear and does not use the standard Telegram logo. Until review completes, all branding must say **Telegram Secure — Unofficial**.
4. Preserve upstream and third-party license notices; publish corresponding source as required by the applicable licenses.
5. Create CI and release provenance before distributing APKs.
6. Implement secure overlay only through the approved specification, with clear module boundaries and the public-beta gates in `../chatgpt-plan.md` §25A.8.

The in-repository review draft is `docs/secure-overlay-protocol-v1.md`. It is an implementation-blocking draft, not an approved cryptographic protocol.

`SecureOverlay/` is the intentionally transport-free Android library boundary. It is not yet wired into any upstream Telegram module.

## Local baseline build

This fork has a reproducible local NixOS development shell in `shell.nix`.
It provides the following versions, matching the upstream Gradle configuration:

- JDK 17
- Android SDK platform 35 and build-tools 35.0.0 (plus 34.0.0, required by
  the upstream AGP configuration)
- Android NDK 27.2.12479018
- CMake 3.22.1 for Telegram's native `TMessagesProj` build
- Nix-provided `aapt2` through Gradle's Maven override

From this directory, enter the shell and build the isolated overlay:

```sh
nix-shell
./gradlew :SecureOverlay:assembleDebug :SecureOverlay:testDebugUnitTest --console=plain
```

Then prove the unchanged upstream Android application variant builds:

```sh
./gradlew :TMessagesProj_App:assembleAfatDebug --console=plain
```

Equivalently, run each command directly with `nix-shell --run '…'`.
The included upstream dummy signing configuration and Firebase assets may be
used only for this non-distributable baseline build. They are not authorization
to distribute an APK or substitute production credentials and release signing.

## Upstream update procedure

1. Fetch `upstream` and select a specific commit/tag.
2. Create an update branch and record the old and new upstream revisions in the pull request.
3. Rebase/merge the fork changes, resolve conflicts without weakening upstream security behavior, then run build, tests and secure-overlay compatibility checks.
4. Review license/notice changes and dependency/security advisories.
5. Merge only after CI and release-owner approval; update this file’s pinned revision for a release baseline.
