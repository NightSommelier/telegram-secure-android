# Forgejo CI and Android releases

`.forgejo/workflows/release.yml` builds the maintained fork on the
`linux-amd64` runner. A push to protected `master` builds a **signed production
APK**, compiles the SecureOverlay instrumentation-test sources, and uploads the
APK plus its SHA-256 file as a Forgejo Actions artifact for 14 days. A tag such
as `v12.9.0` additionally publishes those two files to the Forgejo release for
that tag. `workflow_dispatch` can rebuild and republish an existing `v*` tag.

The workflow deliberately invokes `assembleAfatRelease`, never the debug
variant. Its `BuildConfig.DEBUG_VERSION` is `false`, so the login test-server
selector is not available in the CI APK; it targets Telegram's production
network unless someone previously changed the account's local server setting.

The workflow intentionally does not read `secrets.*` for application build
inputs. Configure these as protected environment variables on the runner:

- `TELEGRAM_API_ID`
- `TELEGRAM_API_HASH`
- `RELEASE_KEYSTORE_BASE64` — the complete PKCS#12 keystore encoded as one
  base64 value
- `RELEASE_STORE_PASSWORD`
- `RELEASE_KEY_ALIAS`
- `RELEASE_KEY_PASSWORD`

`ANDROID_SDK_ROOT` (or `ANDROID_HOME`), `JAVA_HOME`, and optionally
`ANDROID_CMAKE_DIR` are runner toolchain variables. The required SDK contents
are Android platform 35, build-tools 35.0.0, NDK 27.2.12479018, and CMake
3.22.1. `TELEGRAM_ABI` is optional and defaults to `arm64-v8a`.

Forgejo supplies the short-lived `FORGEJO_TOKEN` automatically to the release
action. Do not put that token, the keystore, or the generated properties files
in the repository. The workflow removes generated private files in its final
step, including after a failed build.

The runner receives signing variables, so this workflow intentionally runs only
after changes are merged to protected `master` or pushed as a protected tag.
Do not enable it for untrusted pull requests. Contributors run the local build
commands from [`CONTRIBUTING.md`](../CONTRIBUTING.md); a separate unprivileged
runner can be added later for PR-only compilation.

To prepare the keystore value outside the repository, for example:

```bash
base64 -w0 keystore/telegram-fork-secure-release.p12
```

If the runner uses another label, change only `runs-on` in the workflow. The
release asset is named `telegram-secure-<APP_VERSION_NAME>.apk` and is built
from the selected tag commit.
