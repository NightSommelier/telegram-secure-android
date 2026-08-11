# GitHub Actions: Android APK

The GitHub Actions workflow at
[`../.github/workflows/android.yml`](../.github/workflows/android.yml) has two
separate trust boundaries:

- Pull requests compile the production Java sources and SecureOverlay Android
  test sources with structurally valid placeholder Telegram API values. They do
  not receive signing credentials and do not create an APK.
- Pushes to `master`, tags `v*`, and manual runs build a signed **production**
  `afatRelease` APK. `DEBUG_VERSION` is false, so the login test-server switch
  is not included. The APK and SHA-256 checksum are kept as a 14-day Actions
  artifact; `v*` tags additionally create or update a GitHub Release.

Configure these repository secrets before the first protected build:

- `TELEGRAM_API_ID`
- `TELEGRAM_API_HASH`
- `RELEASE_KEYSTORE_BASE64` — the complete PKCS#12 keystore as one base64 value
- `RELEASE_STORE_PASSWORD`
- `RELEASE_KEY_ALIAS`
- `RELEASE_KEY_PASSWORD`

The workflow installs JDK 21, Android platform/build-tools 35, NDK
27.2.12479018 and CMake 3.22.1 on GitHub-hosted Ubuntu. Secrets are written
only to ignored temporary files and removed in an `always()` step. Do not
enable write tokens or secrets for pull requests from forks.
