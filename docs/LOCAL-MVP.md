# Local MVP: Telegram Fork-Secure

This repository builds a local, ordinary Telegram client for device testing.
It does not provide an encrypted overlay or any additional confidentiality
guarantee beyond Telegram's normal client behavior.
Firebase library dependencies remain in the fork, but push delivery is not a
feature of this local MVP. A custom package cannot use Telegram's official
Firebase configuration, and a Firebase project owned by the fork would also
need a server-side delivery arrangement with Telegram. Do not copy or reuse
Telegram's Firebase configuration.

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
3. Send text, a photo, a document, and a voice message in both directions.
4. Close and reopen both apps; confirm that the accounts, chats, and received
   media remain available.

## Verified local MVP (2026-07-22)

- Two real Android devices using separate production accounts.
- Two-way text, photo, document/file, and voice-message delivery.
- Sessions, chat history, and media persist after closing and reopening both
  apps.
- The locally signed release APK was installed on both devices and exchanged
  messages successfully.
- Notifications were observed during the two-device release test. Behavior
  after force-stop or device reboot remains outside this smoke test.

`SecureOverlay` and `docs/protocol-review` are intentionally outside this MVP.
