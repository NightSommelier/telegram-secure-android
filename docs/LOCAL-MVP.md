# Local MVP: Telegram Fork-Secure

> [!NOTE]
> [Українська версія документації доступна у файлі LOCAL-MVP_UK.md](LOCAL-MVP_UK.md).

This document outlines the setup, build, and verification workflow for **Telegram Fork-Secure** on local physical Android hardware.

Fork-Secure adds an end-to-end encrypted protocol layer for ordinary 1:1 cloud chats and a protected Saved Messages mode. Native Telegram Secret Chats, channels, and groups remain unchanged.

The cryptographic layer remains under active review ([`CHANGES REQUIRED`](protocol-review/REVIEW-DECISION.md)). Do not treat this build as an audited high-assurance confidential messenger.

---

## One-Time Local Setup

1. **Obtain Telegram API Credentials**:
   Register an application at [my.telegram.org/apps](https://my.telegram.org/apps) to obtain a valid `api_id` and `api_hash`.
2. **Configure Local Environment**:
   Copy `local.properties.example` to `local.properties`:
   ```properties
   TELEGRAM_API_ID=123456
   TELEGRAM_API_HASH=abcdef0123456789abcdef0123456789
   sdk.dir=/path/to/android-sdk
   ```
3. **Android SDK & Toolchain**:
   Requires JDK 21, Android SDK platform 35/36, build-tools 35.0.0/36.0.0, NDK `27.2.12479018`, and CMake `3.22.1`. Alternatively, enter the project's pre-configured Nix environment (`nix-shell`).

Verify your environment before proceeding:
```bash
./scripts/check-local-mvp.sh
```

---

## Local Build & Installation

### Fast Cycle (ARM64 Debug Build)

Build and install on a connected Android phone:
```bash
./scripts/build-local-mvp.sh
./scripts/install-local-mvp.sh <device_serial>
```

Or run the all-in-one local test runner:
```bash
./scripts/run-local-mvp.sh <device_serial>
```

The debug APK uses package `ua.securechat.telegram` and is signed with the local debug key, allowing side-by-side coexistence with the official Telegram client.

### Release Signing

To build a production, release-signed package:
```bash
./scripts/create-release-keystore.sh
```
This initializes `keystore/` and `signing.properties`. Then build production APKs:
```bash
./gradlew :TMessagesProj_App:assembleAfatRelease --console=plain
```

---

## Connected Device Verification

Run the full suite of cryptographic, storage, codec, and state machine instrumentation tests on a connected device:

```bash
nix-shell --run 'ANDROID_SERIAL=<device_serial> ./gradlew :SecureOverlay:connectedDebugAndroidTest --console=plain'
```

---

## Supported & Verified Capabilities (Telegram 12.10.5 Baseline)

- **Text & Formatting**: Encrypted UTF-8 text, entities, captions, client-side linkification, and stripped reply quote metadata.
- **Rich Media**: Photos, videos, voice notes, round video notes, audio/music tracks, arbitrary files, and stickers with decrypted native playback and waveform rendering.
- **Contacts**: Encrypted `TYPE_CONTACT` payload; standard Telegram vCard leakage stripped.
- **Geo-Location**: Encrypted `TYPE_GEO_LOCATION` payload with secret mode preview blocking external tile leakages.
- **Remote Deletion**: Cryptographically signed `TYPE_CONTROL_DELETE` control packet purging ciphertext, local cache, and disk files.
- **Secure Forwarding**: Decrypts and re-encrypts under recipient's ratchet session preserving waveforms and presentation attributes.
- **Link Anti-Spoofing (`SecureLinkGuard`)**: Filters Punycode, IDN homoglyphs, BiDi overrides, and authority spoofing with mandatory confirmation before external navigation.
- **Screen Protection**: `FLAG_SECURE` enforced across `ChatActivity`, `ProfileActivity`, and `PhotoViewer`; gallery export and sharing blocked.
