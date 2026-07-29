# Fork-Secure identity backup format — draft 1

**Status:** local identity-only MVP implemented; independent format review,
cross-implementation fixtures and destructive reinstall/restore testing remain
required before this is treated as a release recovery mechanism.
This draft defines an identity-continuity archive only. It does not back up
message plaintext, attachment manifests, media, peer trust, sessions, Telegram
credentials, drafts, logs, or notification data.

## Threat and recovery boundary

The archive protects against loss of one installation when the user retains
both the archive and its password. Theft of both permits offline password
guessing. A compromised unlocked device may export the identity and is outside
this archive's protection.

Restore requires login to the same Telegram owner ID and an installation with
no secure conversations or remote protocol state. It may replace the
automatically generated but unused local identity; it never silently overwrites
an active identity.
Restoring one archive on multiple devices creates clones; peers must detect this
through the recovery protocol below. A peer that has never seen the identity
cannot independently detect an older restored archive.

## Canonical binary container

All integers are unsigned big-endian. Parsers reject unsupported values,
non-zero reserved fields, length overflow, truncation and trailing bytes before
running the password KDF where possible.

| Field | Size | Required value |
| --- | ---: | --- |
| Magic | 4 | ASCII `FSBK` |
| Format version | 2 | `1` |
| KDF ID | 1 | `2` = PBKDF2-HMAC-SHA-256 |
| AEAD ID | 1 | `1` = AES-256-GCM |
| Flags | 2 | `0` |
| KDF parameter 1 | 4 | iterations = `600000` |
| KDF parameter 2 | 4 | `0` |
| KDF parallelism | 1 | `1` |
| Salt length | 1 | `16` |
| Nonce length | 1 | `12` |
| Reserved | 1 | `0` |
| Plaintext length | 4 | `1..4096` |
| Salt | 16 | fresh random bytes |
| Nonce | 12 | fresh random bytes |
| Ciphertext | plaintext length | AES-GCM output without tag |
| Authentication tag | 16 | AES-GCM tag |

`AAD` is every byte from `Magic` through `Nonce`, inclusive.
PBKDF2-HMAC-SHA-256 derives exactly 32 bytes from the UTF-8 password bytes and
the stored salt. Password normalization is not performed; the UI requires
identical entry twice, at least 12 characters, and the codec accepts at most
512 UTF-8 bytes. KDF ID 2 uses the available-platform fallback work factor from
the [OWASP Password Storage Cheat
Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
Argon2id remains the preferred future KDF ID after Android dependency,
performance and independent-vector review; adding it must not reinterpret KDF
ID 2 archives.

## Authenticated plaintext

The decrypted plaintext begins with ASCII `FSBP`, version `U16 = 1`, then
canonical fields encoded as `tag U8 | length U16 | value`. Tags are strictly
increasing, unique and complete; no unknown tag is accepted in version 1.

| Tag | Value |
| ---: | --- |
| 1 | random archive ID, exactly 16 bytes |
| 2 | Telegram owner user ID, `U64`, non-zero |
| 3 | identity generation, `U64` |
| 4 | export Unix time, `U64` |
| 5 | libsignal registration ID, `U32` |
| 6 | serialized identity key pair, `16..512` bytes |
| 7 | SHA-256 of the canonical public identity key, 32 bytes |
| 8 | recovery policy, `U8 = 1` (identity only) |

Import derives the public identity from tag 6 and compares tag 7 in constant
time. Registration and key serialization must also pass libsignal parsing and
range validation before any state mutation.

## Restore transaction

1. Parse resource bounds, authenticate/decrypt, validate all fields, compare
   the logged-in Telegram owner ID and show the recovered fingerprint.
2. Reject if secure conversation state, remote identity/session state, staged
   recovery, or an unresolved recovery marker already exists. Failed validation
   leaves all state unchanged.
3. Stage identity and registration under separate encrypted record names and
   atomically write a `PREPARED` recovery marker.
4. After explicit confirmation, atomically replace only identity and
   registration, remove prekeys/trust/sessions, and set marker `COMMITTING`.
5. Clear every secure-chat gate. Secure engine construction completes a
   `COMMITTING` import idempotently before send/decrypt state is opened.
6. Generate fresh prekeys, increment the archived identity generation, create a
   fresh recovery ID, then remove the marker and staging records.

The encrypted blob store now encrypts all replacements before performing one
synchronous preferences transaction. The staging payload and marker are
Keystore-encrypted. A `PREPARED` import waits for explicit fingerprint
confirmation and can be deleted without changing protocol state; a
`COMMITTING` import is always completed. Password and decrypted temporary byte
arrays are cleared on handled paths and KDF work runs off the UI thread.

The local recovery-generation record and peer rollback/clone classifier are
implemented independently of archive import. They use fixed-length,
Keystore-encrypted records, never mutate peer trust during classification, and
advance the local generation when the user explicitly resets their identity.
A version-2 pairing codec carries that metadata and its identity signature
covers the canonical pre-key bundle, generation and recovery ID. New pairing
offers use this format. A higher generation pauses secure sending until the
distinct recovery dialog is explicitly accepted; rollback, same-generation
clone, and downgrade offers are rejected without replacing the trusted session.
Legacy offers remain accepted only until a signed recovery record has been
stored for that peer.

The Android UI exposes the global identity, generation, current per-account
secure-state counts, encrypted export, staged restore and identity reset under
`Settings > Fork-Secure`. The same screen explicitly states that the archive
does not contain a chat/session roster. After restore, all secure gates are
cleared and each contact must be paired and verified again; “restore all chats”
is not claimed.

## Peer recovery protocol

The next pairing object must authenticate `identity_generation` and a random
`recovery_id` under the restored identity. A peer stores the highest accepted
generation and recovery ID:

- lower generation: reject as rollback;
- same generation and same recovery ID: idempotent duplicate;
- same generation and different recovery ID: block as a possible clone;
- higher generation: show a recovery event, pause secure messaging and require
  explicit re-verification before accepting new sessions.

The original still-active device becomes stale after peers accept the higher
generation. This mechanism limits clone/rollback detection to peers that have
previously stored the identity state; it is not a global device registry.

## Required fixtures and acceptance

Before release use, publish machine-readable known-answer fixtures for the
container, KDF, AEAD and plaintext encoding plus negatives for wrong password,
tamper, malformed lengths, trailing bytes, excessive KDF parameters, account
mismatch, key/fingerprint mismatch, rollback, duplicate restore and clone
conflict. Two independent test-only consumers must reproduce them. The current
Android suite has a Python-derived PBKDF2 known answer, deterministic Java
encode/decode, authentication/tamper/resource-bound negatives and atomic
blob-replacement coverage; it is not the required second consumer.

Acceptance also requires interrupted-restore tests at every marker phase,
reinstall and two-phone recovery tests, confirmation that Android/Telegram
backup excludes all Fork-Secure preferences, and proof that temporary plaintext
and password buffers are not persisted or logged.

## Planned automatic recovery archive

The identity-only `FSBK` archive cannot restore access to historical protected
messages or attachments. A separate, opt-in automatic archive revision must
therefore cover the identity plus the minimum ratchet/session records and
message/media content-key records required by the local encrypted stores. It
must not upload plaintext messages, decrypted media, passwords, Telegram
credentials, or raw Keystore wrapping keys.

Before implementation, define and test snapshot consistency, incremental
versioning, deletion/retention, rollback and clone handling, password/key
rotation, archive-size limits, interrupted upload/restore, and recovery on a
clean installation. Automatic Android backup remains excluded. Any future
provider such as Google Drive receives only an already authenticated encrypted
archive and must be replaceable by a local-file or other storage backend.
