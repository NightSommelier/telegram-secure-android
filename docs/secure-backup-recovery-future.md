# Secure backup and recovery — future protocol requirements

**Status:** non-normative future-work boundary. This document is not part of Secure Overlay v1 and does not authorize backup implementation.

## Product decision

A future release MAY let a user export encrypted recovery material under a password. It MUST be explicit opt-in, describe exactly what is recoverable, and retain an option to delete the export. Android Auto Backup and cloud backup remain disabled for all secure material.

A password-only archive is an offline password-guessing target. The product MUST state that the password cannot be recovered and MUST NOT imply that a backup restores ciphertext the user no longer possesses.

For this private MVP, recovery is now a planned post-text milestone. The first
implementation candidate is an **identity-continuity backup**, not an automatic
history backup:

- export is initiated by the user and written through Android's document picker;
- the archive is encrypted before leaving app-private storage;
- restore keeps the long-lived Fork-Secure identity only after an explicit
  fingerprint/account check;
- every contact session is replaced by a fresh recovery/re-pair flow, rather
  than restoring a stale ratchet snapshot;
- restored contacts must be shown a recovery event and may require
  re-verification according to the final protocol decision;
- losing both the archive password and every active device is unrecoverable.

The app must also continue to offer the safer alternative: reset to a new
identity and re-verify contacts. Restoring the same identity on two active
installations risks identity cloning, so simultaneous restore/multi-device use
is blocked until a separately reviewed device-management protocol exists.

## Current-state audit

The app currently has three different recovery classes that must not be
presented as one feature:

| State | Current storage | Identity-only restore result |
| --- | --- | --- |
| Local identity and registration | Keystore-encrypted blob records | Identity fingerprint can remain stable |
| Peer trust, ratchet sessions and pairing state | Keystore records plus `telegram_secure_chat_state_v1` | Not restored; each peer requires a fresh recovery/re-pair flow |
| Decrypted text and attachment manifests | Keystore-encrypted local display/content records | Not restored; old carriers cannot simply be decrypted again after ratchet state was consumed |

Decrypted media files are cache files and are also excluded from the
identity-only archive. Therefore identity recovery preserves who the user is,
but **does not preserve access to old message plaintext or attachments**. A
future history archive would need separately reviewed encrypted display/content
records, retention/deletion semantics and ciphertext availability guarantees.
It must not serialize a live ratchet snapshot as a shortcut.

The application manifest enables Android backup for Telegram's custom
`BackupAgent`. That agent currently names only `saved_tokens` and
`saved_tokens_login`; Fork-Secure preferences are not listed.
`scripts/check-secure-backup-boundary.sh` enforces this exact allowlist from the
local build preflight so an upstream backup-agent change cannot silently include
secure state.

Per-message and per-dialog deletion hooks now purge the matching encrypted
display/content records. In-memory display text and decrypted/encrypted media
cache directories are bounded. Durable encrypted display/content records are
intentionally not evicted automatically yet: without a history archive, that
would make old carriers permanently unreadable. A reviewed retention/history
policy remains required before old-message backup.

## Delivery plan

1. Decide and document the recovery threat model: lost phone, damaged app data,
   voluntary migration, stolen archive, compromised active device and cloned
   restore.
2. Review `secure-identity-backup-format-draft.md`, including its identity-only
   archive and fresh-session recovery handshake.
   Do not serialize live ratchet/session objects into the first format.
3. Produce deterministic format, wrong-password, tamper, rollback, account
   mismatch and duplicate-device fixtures with two independent consumers.
4. Implement test-only export/import around a synthetic protocol store, then
   verify that no plaintext, preview cache, Telegram credential, log or draft
   enters the archive.
5. Add opt-in Android export/import UI, password confirmation, fingerprint
   display, explicit overwrite/reset warnings and post-restore re-verification.
6. Run reinstall, device-to-device, wrong-account, corrupted archive, old
   archive and interrupted-write tests on physical phones.
7. Enable it for the private MVP only after the separate recovery review and
   implementation audit pass.

Acceptance requires that a copied archive alone cannot be opened without its
password, a restored archive cannot silently downgrade or clone a live secure
identity, failed restore leaves existing state unchanged, and every successful
restore produces a visible recovery/re-verification state for contacts.

## Required separate review specification

Before implementation, a recovery specification MUST define:

- a versioned canonical binary container, exact resource limits and authenticated metadata;
- precisely which identity/session/history keys and ciphertext references may be exported; plaintext messages, drafts, previews and logs are never exported;
- Argon2id parameters, unique random salt, output length, memory/time/parallelism bounds and a versioned parameter identifier;
- a unique archive encryption key derived only for that archive and AEAD encryption with a fresh nonce;
- authenticated binding to the identity fingerprint, export time, archive version and recovery policy;
- rollback/replay detection and an explicit restore conflict policy when the local identity or session state differs;
- restore UX: password failure, archive corruption, a changed identity/device, account mismatch, recovery completion and mandatory re-verification;
- secure deletion/retention policy for temporary plaintext, exports and imported archives;
- device migration, reinstallation and lost-device handling;
- machine-readable known-answer, malformed, resource-exhaustion, wrong-password, tamper and rollback fixtures.

## Non-goals until separately approved

This does not introduce cloud escrow, password recovery, automatic private-key synchronization, group/multi-device history fanout, or a claim that all past Telegram carriers remain available after restore.

## Gate

The backup format requires an independent protocol review and implementation audit in addition to the base-overlay approval. It must not share undocumented state or ad-hoc serialization with Secure Overlay v1.
