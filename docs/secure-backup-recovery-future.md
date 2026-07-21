# Secure backup and recovery — future protocol requirements

**Status:** non-normative future-work boundary. This document is not part of Secure Overlay v1 and does not authorize backup implementation.

## Product decision

A future release MAY let a user export encrypted recovery material under a password. It MUST be explicit opt-in, describe exactly what is recoverable, and retain an option to delete the export. Android Auto Backup and cloud backup remain disabled for all secure material.

A password-only archive is an offline password-guessing target. The product MUST state that the password cannot be recovered and MUST NOT imply that a backup restores ciphertext the user no longer possesses.

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
