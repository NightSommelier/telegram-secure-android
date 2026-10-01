# Security Policy

> [!NOTE]
> [Українська версія документації доступна у файлі SECURITY_UK.md](SECURITY_UK.md).

## Status

Telegram Fork-Secure is a private beta fork for local device testing and evaluation, not an audited consumer security product. The experimental Fork-Secure layer is implemented for ordinary 1:1 cloud chats and Saved Messages; native Telegram Secret Chats remain unchanged.

The independent cryptographic review of the protocol overlay is ongoing. The current review status remains [`CHANGES REQUIRED`](docs/protocol-review/REVIEW-DECISION.md). Successful local builds, passing unit tests, or two-device smoke tests do not constitute proof of cryptographic safety. Do not use this build for data where confidentiality breaches could result in significant harm.

---

## Reporting a Vulnerability

Do not disclose vulnerabilities, application logs, wire carriers, backup exports, secret keys, passwords, or decrypted attachments in public issues, discussions, or git commits.

Report security issues privately to the project maintainers via an agreed out-of-band private communication channel. When filing a report, please include:

- The exact APK release or source commit SHA, device hardware model, and Android version.
- Minimal, safe reproduction steps.
- Expected behavior versus actual behavior.
- Clarification on whether the issue impacts plaintext confidentiality, cryptographic keys, ratchet state, backup/recovery, authentication, or media transmission.

---

## Security Boundaries & Operational Best Practices

- **Zero Credential Leaks**: Never commit `local.properties`, API credentials, signing keystores, identity export archives, decrypted media files, or device logs.
- **Fail-Closed Processing**: Any malformed, unverifiable, or replay carrier marked with `TGS1:` must fail closed and must never fall back to plaintext display or transmission.
- **Screen Protection**: `FLAG_SECURE` window protection is active across chat, profile, and media viewer activities when screen protection is enabled.
- **Backup Safety**: Only export backup data to strongly encrypted volumes. Test restoration on a separate staging device before relying on it.
- **Upstream Telegram Issues**: Vulnerabilities inherent to official Telegram client or MTProto infrastructure should additionally be reported through the official [Telegram Security Channel](https://telegram.org/security).

---

## Protocol Review Scope

Any proposed change affecting wire formats, carrier parsing, ratchet or Keystore lifecycle, or the Telegram transport boundary requires an updated cryptographic assessment. Refer to [`docs/protocol-review/`](docs/protocol-review/) and the architectural code map in [`docs/TELEGRAM-ANDROID-FORK-MAP.md`](docs/TELEGRAM-ANDROID-FORK-MAP.md).
