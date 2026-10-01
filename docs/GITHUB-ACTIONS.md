# GitHub Actions: Multi-Architecture Android Build & Release

> [!NOTE]
> [Українська версія документації доступна у файлі GITHUB-ACTIONS_UK.md](GITHUB-ACTIONS_UK.md).

The continuous integration and release pipeline is defined at [`.github/workflows/android.yml`](../.github/workflows/android.yml).

---

## Workflow Jobs & Trust Boundaries

The workflow implements two distinct trust and privilege boundaries:

### 1. Verification Job (`verify`)
- **Triggers**: Pull requests and push events across `dev`, `main`, and `master`.
- **Privileges**: Read-only repository access (`permissions: contents: read`).
- **Action**: Compiles production Java/Kotlin sources and `SecureOverlay` test sources using structurally valid mock Telegram API identifiers (`TELEGRAM_API_ID=1`).
- **Isolation**: Untrusted pull requests never receive signing keys or production API secrets and do not generate distributable APKs.

### 2. Multi-Architecture Packaging Job (`package`)
- **Triggers**: Non-PR push events on `dev`, `main`, `master`, version tags matching `v*`, or manual `workflow_dispatch`.
- **Privileges**: Release publishing permissions (`permissions: contents: write`).
- **Compilation**: Compiles and signs five distinct Android package configurations:
  1. `universal`: Contains all four ABIs (`arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86`).
  2. `arm64-v8a`: Optimized for modern 64-bit ARM hardware.
  3. `armeabi-v7a`: For legacy 32-bit ARM smartphones.
  4. `x86_64`: For Chromebooks, PCs, and 64-bit emulators.
  5. `x86`: For 32-bit x86 environments.
- **Verification & Integrity**: Each APK is dumped via `aapt2` for badging validation and generates a matching `.sha256` checksum.
- **Artifacts**: Uploaded as a 14-day GitHub Actions workflow artifact.
- **Release Automation**: For `v*` tags, assets are uploaded directly to the corresponding GitHub Release.

---

## Required Repository Secrets

The packaging job requires the following GitHub Secrets:

| Secret Name | Description |
| :--- | :--- |
| `TELEGRAM_API_ID` | Production Telegram API identifier from my.telegram.org |
| `TELEGRAM_API_HASH` | Production Telegram API hash from my.telegram.org |
| `RELEASE_KEYSTORE_BASE64` | Base64-encoded PKCS#12 release keystore |
| `RELEASE_STORE_PASSWORD` | Password protecting the release keystore |
| `RELEASE_KEY_ALIAS` | Key alias in the keystore |
| `RELEASE_KEY_PASSWORD` | Password protecting the private key |

Secrets are decoded only to temporary runtime files (`signing.properties`, `local.properties`, `keystore/release.p12`) with `umask 077`, and are permanently wiped in an `always()` post-build step.
