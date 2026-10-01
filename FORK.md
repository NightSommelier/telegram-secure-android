# Telegram Secure Fork Record

> [!NOTE]
> [Українська версія документації доступна у файлі FORK_UK.md](FORK_UK.md).

## Status

This repository is the maintained development fork for **Telegram Fork-Secure**. It integrates the Signal Double Ratchet protocol (`SecureOverlay`) with the official Telegram Android application. Builds that include the secure overlay incorporate AGPLv3 `libsignal`; all distributed binaries are accompanied by full corresponding source code and license notices.

## Upstream Baseline

- Upstream repository: `https://github.com/DrKLO/Telegram.git`
- Local upstream remote: `upstream`
- Current upstream release baseline: **Telegram Android 12.10.5**
- Upstream merge commit: `060c661c0 chore(upstream): merge official Telegram Android 12.10.5 into fork`
- Pinned commit: `dc780e81e` (`update to 12.10.5 (7105)`)

Do not pull upstream changes directly into development branches. Upstream syncs must be reviewed on dedicated branches, conflict-resolved without weakening cryptographic invariants, and verified against the complete instrumentation test suite.

## Product Boundary & Architecture

Telegram Fork-Secure strictly preserves Telegram’s underlying client/server protocol behavior:

1. **Transport Isolation**: `SecureOverlay/` is a transport-free library module. It handles X3DH, Double Ratchet, cryptographic storage (Keystore), and payload serialization without importing Telegram classes or issuing network requests.
2. **Adapter Boundary**: `TMessagesProj` integrates with `SecureOverlay` strictly through designated adapters:
   - `SendMessagesHelper`: Gatekeeper ensuring only supported secure operations are encrypted and transmitted.
   - `ChatActivity`: Presentation of encrypted sessions, verification safety numbers, secret mode map rendering, and link anti-spoofing dialogs.
   - `SecureLinkGuard`: Phishing detection, IDN homoglyph normalization, and navigation safety warnings.
   - `MessageObject` & `ChatMessageCell`: Decoding and local cache presentation without leaking plaintext to the server.
3. **Fail-Closed Principle**: Any malformed carrier, unexpected downgrade, or authentication failure rejects immediately without mutating trusted ratchet state or falling back to unencrypted transmission.

## Development & Branching Policy

- **`dev`**: Primary branch for daily development. Feature branches are merged here after test verification.
- **`feature/<name>`**: Scoped branches for new features or bug fixes.
- **`main` / `master`**: Production release branches containing tagged, verified releases (`v<version>`).

## Local Development Environment

The fork uses a reproducible NixOS development environment in `shell.nix`:
- OpenJDK 21
- Android SDK platforms 35 and 36, build-tools 35.0.0 and 36.0.0
- Android NDK 27.2.12479018
- CMake 3.22.1

Build and verify the isolated layer:
```bash
./scripts/check-local-mvp.sh
./scripts/build-local-mvp.sh
nix-shell --run 'ANDROID_SERIAL=<device> ./gradlew :SecureOverlay:connectedDebugAndroidTest --console=plain'
```
