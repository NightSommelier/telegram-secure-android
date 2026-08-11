# Local MVP: Telegram Fork-Secure

This repository builds **Telegram Fork-Secure**, a local Telegram Android fork
for private beta testing. It includes an experimental Fork-Secure layer for
ordinary 1:1 chats and a separate protected Saved Messages mode. Native Telegram
Secret Chats are not modified; groups, channels, and ordinary chats use normal
Telegram behavior.

The additional layer is not independently security-reviewed. The protocol-review
gate remains [`CHANGES REQUIRED`](protocol-review/REVIEW-DECISION.md), so this
MVP must not be presented as a high-assurance confidential messenger.

## One-time local setup

1. Create an Android application at `https://my.telegram.org/apps` for this
   fork. Keep the resulting API ID and API hash private.
2. Copy `local.properties.example` to `local.properties`, set `sdk.dir`,
   `TELEGRAM_API_ID`, and `TELEGRAM_API_HASH`. That file is ignored by Git.
3. Install Android SDK platform/build-tools 35, NDK `27.2.12479018`, and CMake
   `3.22.1`. If CMake is outside `sdk.dir`, set `cmake.dir` in
   `local.properties`.

Confirm the environment before compiling:

```bash
./scripts/check-local-mvp.sh
```

## Build and install

```bash
./scripts/build-local-mvp.sh
./scripts/install-local-mvp.sh 636567fd
```

For the normal local cycle, one command rebuilds the ARM64 debug APK, installs
it on the one connected device, and opens the app:

```bash
./scripts/run-local-mvp.sh
```

If more than one device is connected, pass the intended ADB serial explicitly:

```bash
./scripts/run-local-mvp.sh 636567fd
```

The debug APK package is `ua.securechat.telegram`; it is signed with the
standard local Android debug keystore and can coexist with the official
Telegram client. Do not distribute this debug APK.

## Release signing

When you need an installable release APK, create a unique local signing key:

```bash
./scripts/create-release-keystore.sh
```

The script asks for a password and creates ignored `keystore/` and
`signing.properties` files. Back up `keystore/` securely: losing it prevents
you from updating an already installed release build. Release tasks fail until
this key is configured, so they cannot use Telegram's upstream signing key.

## Phone smoke test

1. Start **Telegram Fork-Secure** and leave **Use test server** disabled.
2. Log in to two separate production accounts on two devices.
3. In a paired 1:1 chat, verify protected text, captions, photos, files and
   supported media in both directions; also verify an ordinary message after
   turning protection off.
4. Verify protected Saved Messages text/media separately.
5. Close and reopen both apps; confirm that accounts, chats and received media
   remain available. Test import/recovery on a spare installation before relying
   on a backup.

## Verified local MVP (2026-07-22)

- Two real Android devices using separate production accounts.
- Two-way text, photo, document/file, and voice-message delivery.
- Sessions, chat history, and media persist after closing and reopening both
  apps.
- The locally signed release APK was installed on both devices and exchanged
  messages successfully.
- Notifications were observed during the two-device release test. Behavior
  after force-stop or device reboot remains outside this smoke test.

`SecureOverlay` is part of the fork implementation. `docs/protocol-review`
remains the independent-review boundary and must not be changed to imply approval.
