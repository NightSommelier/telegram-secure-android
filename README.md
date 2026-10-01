# Telegram Fork-Secure [![Android CI](https://github.com/NightSommelier/telegram-secure-android/actions/workflows/android.yml/badge.svg?branch=main)](https://github.com/NightSommelier/telegram-secure-android/actions/workflows/android.yml) [![License: GPL v2 or later](https://img.shields.io/badge/License-GPL--2.0--or--later-blue.svg)](LICENSE) [![Latest Release](https://img.shields.io/github/v/release/NightSommelier/telegram-secure-android?include_prereleases&label=release)](https://github.com/NightSommelier/telegram-secure-android/releases)

Telegram Fork-Secure is a privacy-hardened Telegram Android fork based on the official Telegram Android client (**v12.10.5**). It adds a transparent, end-to-end encrypted security overlay for standard 1:1 cloud chats and Saved Messages using the Signal Double Ratchet protocol (`SecureOverlay`), without requiring server-side cooperation or breaking compatibility with standard Telegram chat routing.

> [!NOTE]
> [Українська версія документації доступна у файлі README_UK.md](README_UK.md).

---

## Key Features

- **Signal Protocol E2EE (`SecureOverlay`)**: End-to-end encrypted messaging using X3DH, Double Ratchet, Ed25519/X25519 keys, and XChaCha20-Poly1305 authenticated encryption over standard Telegram 1:1 carriers.
- **Encrypted Rich Media**: Complete encryption of photos, voice notes, round video notes, audio/music files, documents, and stickers. Native playback runs directly from the decrypted cache with preserved waveforms and metadata.
- **Encrypted Contacts & Live/Static Geo-Location**: Dedicated secure payload codecs for `TYPE_CONTACT` (vCard / phone / name) and `TYPE_GEO_LOCATION` with secret mode protected map rendering.
- **Authenticated Remote Deletion**: Cryptographically signed remote delete control packets (`TYPE_CONTROL_DELETE`) with carrier digest verification and automatic purge of ciphertext, decrypted cache, and disk files.
- **Secure Media Forwarding**: Forward protected media across secure sessions; media is decrypted locally and safely re-encrypted under the recipient's ratchet chain, preserving captions, waveforms, and dimensions.
- **Anti-Spoofing Link Guard & Phishing Warning**: Integrated `SecureLinkGuard` detects IDN homoglyphs (confusable Cyrillic/Latin/Greek alphabets), Punycode (`xn--`), BiDi directional override characters, zero-width spaces, and URI authority spoofing (`user:pass@host`), requiring explicit user confirmation before external browser launch.
- **Screen Protection & Anti-Leak Guards**: Enforced `FLAG_SECURE` window protection across chat, profile, and media viewer; blocked gallery exports, screenshots, and sharing of decrypted media; cloud drafts and link previews suppressed in protected chats; unencrypted reactions blocked fail-closed.

---

## Downloads (v12.10.5)

Signed multi-architecture packages:

| Architecture | Package | Checksum |
| :--- | :--- | :--- |
| **arm64-v8a** | [`telegram-fork-secure-12.10.5-arm64-v8a.apk`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-arm64-v8a.apk) | [`SHA-256`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-arm64-v8a.apk.sha256) |
| **universal** | [`telegram-fork-secure-12.10.5-universal.apk`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-universal.apk) | [`SHA-256`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-universal.apk.sha256) |
| **armeabi-v7a** | [`telegram-fork-secure-12.10.5-armeabi-v7a.apk`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-armeabi-v7a.apk) | [`SHA-256`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-armeabi-v7a.apk.sha256) |
| **x86_64** | [`telegram-fork-secure-12.10.5-x86_64.apk`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-x86_64.apk) | [`SHA-256`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-x86_64.apk.sha256) |
| **x86** | [`telegram-fork-secure-12.10.5-x86.apk`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-x86.apk) | [`SHA-256`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-x86.apk.sha256) |

Release notes and verification details: [Releases](https://github.com/NightSommelier/telegram-secure-android/releases/tag/v12.10.5%2B965ecc7).

---

## Repository Structure & Documentation Map

```text
telegram-secure-android/
├── TMessagesProj/          # Telegram Android app sources (UI, networking, media, DB)
├── TMessagesProj_App/      # Android application packaging, flavors, and build configuration
├── SecureOverlay/          # Isolated Signal protocol layer, codecs, storage, and tests
├── docs/                   # Architectural blueprints, security audits, and developer guides
├── scripts/                # Local build, check, and deployment scripts
└── .github/workflows/      # Multi-architecture CI/CD workflows
```

- [**FORK.md**](FORK.md): Fork baseline, upstream relationship, and architectural boundaries.
- [**CONTRIBUTING.md**](CONTRIBUTING.md): Branching model (`dev`, `feature/*`, `main`), coding style, and pull request guidelines.
- [**SECURITY.md**](SECURITY.md): Security policy, vulnerability reporting, and trust boundaries.
- [**docs/LOCAL-MVP.md**](docs/LOCAL-MVP.md): Quick setup, Nix development environment, build commands, and device smoke-tests.
- [**docs/TELEGRAM-ANDROID-FORK-MAP.md**](docs/TELEGRAM-ANDROID-FORK-MAP.md): Code navigation map, message dispatch paths, and key entry points.
- [**docs/fork-secure-feature-security-audit.md**](docs/fork-secure-feature-security-audit.md): In-depth security audit of all messaging features, metadata leak analysis, and fail-closed defenses.
- [**docs/secure-overlay-protocol-v1.md**](docs/secure-overlay-protocol-v1.md): Wire protocol specification for Canonical Field Sequence (CFS) envelopes, handshakes, and ratchet state.

---

## Development & Branching Workflow

We follow a strict git branching model for all contributions:

1. **`dev`**: The default integration branch for ongoing development. All feature PRs target `dev`.
2. **`feature/<name>`**: Individual feature or bugfix branches created from `dev`.
3. **`main`**: Production release branch containing tagged, verified releases (`v<version>`).

---

## Local Build & Testing

The repository provides a reproducible Nix development shell (`shell.nix`) containing JDK 21, Android SDK platform/build-tools 35 & 36, NDK 27.2.12479018, and CMake 3.22.1.

### Prerequisites

1. Obtain your own `api_id` and `api_hash` from [my.telegram.org](https://my.telegram.org/apps).
2. Configure `local.properties` (see `local.properties.example`).

### Build Commands

```bash
# Verify environment and dependencies
./scripts/check-local-mvp.sh

# Build ARM64 debug APK locally
./scripts/build-local-mvp.sh

# Run connected Android instrumentation tests on device
nix-shell --run 'ANDROID_SERIAL=<device_serial> ./gradlew :SecureOverlay:connectedDebugAndroidTest --console=plain'

# Build production multi-architecture release APKs
./gradlew :TMessagesProj_App:assembleAfatRelease --console=plain
```

---

## Security & Independent Review Notice

> [!WARNING]
> Fork-Secure is a beta implementation for research, evaluation, and device testing. The independent cryptographic review status remains **`CHANGES REQUIRED`** (see [`docs/protocol-review/REVIEW-DECISION.md`](docs/protocol-review/REVIEW-DECISION.md)). Do not rely on this client for critical confidential communications until the formal review process is fully resolved.
