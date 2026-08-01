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

Automatic backup is a later delivery stage, after manual history
export/import is stable on physical devices. Prepare for it by keeping archive
creation independent of Android document pickers and cloud APIs:

- the archive codec produces authenticated ciphertext only;
- a future `RecoveryArchiveProvider` is responsible only for upload, download,
  listing, retention and deletion of opaque archive bytes;
- Google Drive, local files or another provider must not receive archive
  passwords, plaintext cache records, raw Keystore keys or Telegram
  credentials;
- automatic runs require explicit opt-in, visible last-success/error state,
  bounded retained generations and a tested local retry queue;
- provider failure must not block messaging or mutate identity/session state.

## Manual history archive implementation status

The current private build contains a manual `FSRK` implementation candidate:

- export includes the global identity, encrypted local text/content records and
  the known peer roster for one Telegram account;
- live libsignal sessions, peer trust and decrypted media files are excluded;
- restore replaces selected secure-store roots in one transaction and records
  a recovery marker so process restart can complete the paused-chat state;
- every recovered peer is paused until pairing and verification are repeated;
- wrong-account, tamper and non-empty-installation rejection leave existing
  state unchanged in instrumentation tests;
- settings present `FSRK` as the primary **full Fork-Secure backup**:
  one archive restores identity plus local protected-message/content records.
  The existing identity-only `FSBK` format remains an explicitly labelled
  advanced option and is not required when an `FSRK` archive is available.

This is not yet an automatic backup feature. Physical document-picker export,
app reinstall, import, old-message rendering and encrypted attachment re-open
still require a two-device acceptance run before the manual format is treated
as stable.

## Current-state audit

The app stores three recovery classes. The full archive combines the first and
third for usability while preserving their distinct security behavior:

| State | Current storage | Full `FSRK` restore result |
| --- | --- | --- |
| Local identity and registration | Keystore-encrypted blob records | Identity fingerprint can remain stable |
| Peer trust, ratchet sessions and pairing state | Keystore records plus `telegram_secure_chat_state_v1` | Not restored; each peer requires a fresh recovery/re-pair flow |
| Protected text and attachment manifests | Keystore-encrypted local display/content records | Restored; attachment manifests include media keys, but ciphertext must still be available from Telegram |

Downloaded decrypted media files remain cache files and are excluded from both
archive formats. The identity-only `FSBK` file preserves who the user is but
does not preserve access to old message plaintext or attachments. The full
`FSRK` archive preserves local protected-message/content records without
serializing live ratchet state; recovered chats remain paused until new pairing
and verification.

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
