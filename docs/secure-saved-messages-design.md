# Fork-Secure Saved Messages design

**Status:** implementation contract for the private MVP; no automatic migration
of existing Telegram Saved Messages is performed.

## Modes and ownership

Saved Messages is a self-dialog, not a contact session. Its protected mode uses
a separate account-scoped self key (`saved-messages-v1`) and must never reuse a
peer ratchet or silently pair with the user's own Telegram identity. The
setting is opt-in and defaults to **off**. Plain and protected records may
coexist; the sender chooses the mode at send time, while the account setting
controls the default for new records only.

Each protected record carries a versioned Fork-Secure envelope with the account
scope, self-key generation, content kind (`text`, `photo`, `video`, `document`,
`audio`, `voice`, `round-video`, `animation`) and a stable message reference.
Captions are encrypted as part of the same record. The Telegram carrier contains
only the authenticated envelope and opaque attachment bytes; filenames and
previews must not disclose the original content.

## Key lifecycle and recovery

The self key is generated in Android Keystore-backed storage and referenced by
generation. A manual full backup includes the encrypted self-key material and
protected local records, but never Telegram credentials, plaintext previews,
drafts, logs, or decrypted media cache. Restore is transactional: authenticate
the archive, validate account and generation, stage all records, then commit;
any failure leaves the current state untouched. A restored identity pauses
protected Saved Messages until the user confirms the recovery event. Key reset
creates a new generation and does not decrypt old records; old records remain
available only on devices/archives retaining the old generation.

Automatic cloud backup is a later provider feature. Providers receive opaque
authenticated archive bytes only, with explicit opt-in, bounded generations,
retry state, and deletion. A backup must not be treated as a second active
device without a reviewed device-management protocol.

## Forwarding and unsupported operations

Forwarding a protected Saved Message to another protected 1:1 chat decrypts
locally and re-encrypts for that contact. Forwarding to a plain chat is blocked
with an explicit explanation; no plaintext fallback is allowed. Replies,
edits, scheduled sends, captions and supported media use the same content-kind
contract. Reactions and unsupported Telegram objects remain plain or are
rejected according to the existing secure-content policy; they must never cause
the original protected record to be replaced by its carrier text.

## Acceptance gates

Before exposing the settings switch, tests must cover deterministic envelope
encoding, wrong-generation and tamper rejection, duplicate/order handling,
transactional restore, plain/protected coexistence, and no-plaintext forwarding.
Physical reinstall and two-device recovery are required before calling the
feature stable.
