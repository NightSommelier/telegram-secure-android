# Fork-Secure identity backup format — draft 1

**Status:** implementation blocked pending separate protocol/security review.
This draft defines an identity-continuity archive only. It does not back up
message plaintext, attachment manifests, media, peer trust, sessions, Telegram
credentials, drafts, logs, or notification data.

## Threat and recovery boundary

The archive protects against loss of one installation when the user retains
both the archive and its password. Theft of both permits offline password
guessing. A compromised unlocked device may export the identity and is outside
this archive's protection.

Restore requires login to the same Telegram owner ID and an installation with
no Fork-Secure identity. It never silently overwrites an active identity.
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
| KDF ID | 1 | `1` = Argon2id candidate |
| AEAD ID | 1 | `1` = AES-256-GCM |
| Flags | 2 | `0` |
| Argon2 memory KiB | 4 | `65536` |
| Argon2 iterations | 4 | `3` |
| Argon2 parallelism | 1 | `1` |
| Salt length | 1 | `16` |
| Nonce length | 1 | `12` |
| Reserved | 1 | `0` |
| Plaintext length | 4 | `1..4096` |
| Salt | 16 | fresh random bytes |
| Nonce | 12 | fresh random bytes |
| Ciphertext | plaintext length | AES-GCM output without tag |
| Authentication tag | 16 | AES-GCM tag |

`AAD` is every byte from `Magic` through `Nonce`, inclusive. Argon2id derives
exactly 32 bytes from the UTF-8 password bytes and the stored salt. Password
normalization is not performed; export requires identical entry twice and
accepts at most 512 UTF-8 bytes. The Argon2id backend and parameters remain
candidates until the Android performance, licensing and independent-vector
review is complete.

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
2. Reject if an identity, staged recovery, or unresolved recovery marker
   already exists. Failed validation leaves all state unchanged.
3. Stage identity and registration under separate encrypted record names and
   atomically write a `PREPARED` recovery marker.
4. After explicit confirmation, atomically replace only identity and
   registration, remove prekeys/trust/sessions, and set marker `COMMITTING`.
5. Reset every secure chat to recovery-required state. Startup must block all
   secure send/decrypt operations while `COMMITTING` exists and complete this
   step idempotently after a crash.
6. Generate fresh prekeys, increment the archived identity generation, create a
   fresh recovery ID, then remove the marker and staging records.

The storage layer needs a reviewed multi-record commit API before this flow can
be implemented.

The local recovery-generation record and peer rollback/clone classifier are
implemented independently of archive import. They use fixed-length,
Keystore-encrypted records, never mutate peer trust during classification, and
advance the local generation when the user explicitly resets their identity.
They are not yet carried in pairing objects, so they do not provide peer-side
clone detection until the authenticated wire-format revision is reviewed. A
version-2 pairing codec is now implemented and tested: its identity signature
covers the canonical pre-key bundle, generation and recovery ID. Production
pairing remains on the legacy format until downgrade handling, atomic peer-state
updates and the distinct recovery-verification UI are complete.

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

Before Android UI work, publish machine-readable known-answer fixtures for the
container, KDF, AEAD and plaintext encoding plus negatives for wrong password,
tamper, malformed lengths, trailing bytes, excessive KDF parameters, account
mismatch, key/fingerprint mismatch, rollback, duplicate restore and clone
conflict. Two independent test-only consumers must reproduce them.

Acceptance also requires interrupted-restore tests at every marker phase,
reinstall and two-phone recovery tests, confirmation that Android/Telegram
backup excludes all Fork-Secure preferences, and proof that temporary plaintext
and password buffers are not persisted or logged.
