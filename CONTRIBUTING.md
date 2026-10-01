# Contributing to Telegram Fork-Secure

> [!NOTE]
> [Українська версія документації доступна у файлі CONTRIBUTING_UK.md](CONTRIBUTING_UK.md).

## Scope and Architecture Starting Point

This repository contains the active, maintained Telegram Android Fork-Secure product. All code changes belong in this repository.

Before implementing any change, consult the code map:
- Read [`docs/TELEGRAM-ANDROID-FORK-MAP.md`](docs/TELEGRAM-ANDROID-FORK-MAP.md) to locate the owning component.
- Keep cryptographic operations, ratcheting, and serialization inside `SecureOverlay/`; do not spread protocol logic into UI cell renderers.
- Any change must preserve the **fail-closed** invariant: malformed carriers, unexpected states, or unsupported payloads must be rejected without mutating trusted state or falling back to unencrypted plaintext.

The independent protocol review status remains **CHANGES REQUIRED**. Never represent experimental behavior as an audited cryptographic solution.

---

## Branching Model & Development Workflow

We follow an explicit branch lifecycle for all work:

```
feature/<feature-name>  ──┐
feature/<fix-name>      ──┼──>  [ dev ]  ──>  [ main / master ]  (v12.10.5 tags)
```

1. **Active Development on `dev`**:
   - The primary integration branch is **`dev`**.
   - Do not commit directly to `main` or `master`.
2. **Feature Branches (`feature/<name>`)**:
   - Create feature or bugfix branches branched off `dev`: `git checkout -b feature/my-feature dev`.
   - Keep commits focused and atomic with Conventional Commit messages (`feat(secure): ...`, `fix(android): ...`, `test(secure): ...`, `docs: ...`).
3. **Pull Requests & Merging**:
   - Submit PRs targeting the **`dev`** branch.
   - Merges to `dev` must pass CI and local verification.
4. **Releases**:
   - Release versions are merged from `dev` into `main` (and synchronized with `master`).
   - Releases are tagged with version tags (`v<version>`), triggering multi-architecture release packaging in GitHub Actions.

---

## Verification Requirements

Before submitting code for review, verify your changes locally:

1. **Environment Check & Local Build**:
   ```bash
   ./scripts/check-local-mvp.sh
   ./scripts/build-local-mvp.sh
   ```
2. **Compile Verification**:
   ```bash
   nix-shell --run './gradlew :SecureOverlay:compileDebugAndroidTestJavaWithJavac :TMessagesProj:compileReleaseJavaWithJavac --console=plain'
   ```
3. **Instrumentation & Device Tests**:
   For any cryptographic, storage, codec, or state change, run connected tests on a physical device:
   ```bash
   nix-shell --run 'ANDROID_SERIAL=<device_serial> ./gradlew :SecureOverlay:connectedDebugAndroidTest --console=plain'
   ```
4. **Two-Device Verification**:
   For transport, chat UI, or media exchange changes, perform a two-device check across paired accounts and document the result.

---

## Commit Guidelines & Security Hygiene

- Use Conventional Commit format: `feat(secure): ...`, `fix(android): ...`, `test(secure): ...`, `docs(security): ...`, `ci: ...`.
- Keep commits atomic and readable; do not combine unrelated refactorings with security updates.
- **Never commit private build inputs**: `local.properties`, API credentials, signing keys (`keystore/`, `*.p12`), decrypted media files, device logs, or personal phone numbers.
- Report security issues privately as described in [`SECURITY.md`](SECURITY.md).
