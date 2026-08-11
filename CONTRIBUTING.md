# Contributing to Telegram Fork-Secure

## Scope and starting point

This repository is a private-beta Telegram Android fork. Product work belongs in
this repository; the protocol sandbox in the parent directory is not product
verification. Before a change, read
[`docs/TELEGRAM-ANDROID-FORK-MAP.md`](docs/TELEGRAM-ANDROID-FORK-MAP.md) and
start from its owning component. Keep crypto and state handling in
`SecureOverlay/`, not in a UI renderer.

The protocol review remains **CHANGES REQUIRED**. Do not present experimental
Fork-Secure behavior as independently reviewed security, or replace a rejected
secure operation with plaintext fallback.

## Development workflow

1. Write a short reproduction and identify the affected path (send, receive,
   media, recovery, or UI).
2. Add a focused failing test first when practical, then implement the smallest
   change that makes it pass. Parser, state, and media failures must fail closed
   without mutating trusted state.
3. Follow nearby Telegram Java/Kotlin style: four spaces, `UpperCamelCase`
   classes, `lowerCamelCase` members, and `UPPER_SNAKE_CASE` constants.
4. Test the owning module and build an APK locally:

   ```bash
   ./scripts/check-local-mvp.sh
   ./scripts/build-local-mvp.sh
   nix-shell --run './gradlew :SecureOverlay:compileDebugAndroidTestJavaWithJavac :TMessagesProj:compileReleaseJavaWithJavac --console=plain'
   ```

For crypto, storage, or state changes, also run the connected
`SecureOverlay` tests. For transport or chat UI changes, verify the affected
flow on two test devices and record what was tested manually.

GitHub Actions compiles pull requests without repository secrets. Its
signing-capable production APK job runs only after a `master` push, a `v*` tag,
or manual dispatch. See [`docs/GITHUB-ACTIONS.md`](docs/GITHUB-ACTIONS.md).
Never enable write tokens or release secrets for pull requests from forks.

## Pull requests and commits

Keep each PR focused. Explain the user-visible change, security boundary,
reproduction, and any remaining manual validation. Link the issue where one
exists; include before/after screenshots or a recording for UI work, plus the
exact build/test commands and device classes used. Use Conventional Commit
subjects such as `feat(android): ...`, `fix(secure): ...`,
`docs(security): ...`, or `chore: ...`.

Do not combine upstream merges, refactors, and behavior changes in one PR.
Never commit `local.properties`, API credentials, signing keys, recovery
exports, decrypted media, personal logs, or device dumps. Report security
issues privately as described in [`SECURITY.md`](SECURITY.md).
