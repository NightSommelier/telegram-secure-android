# Revision 2 protocol clarifications

This document changes only omissions/ambiguities in the r1 review draft. It
remains review material, not implementation authorization.

## CFS validation table

Before Base64 decoding, a marked carrier is at most 8,192 UTF-8 bytes and has
only unpadded RFC 4648 base64url characters. Decoded envelope data is at most
6,144 bytes. A CFS object is `magic[4] || version:u8 || type:u8 || fields`;
each field is `tag:u8 || length:u16be || value[length]`. Reject truncation,
zero-length header fragments, length beyond remaining bytes, duplicate,
descending, unknown or omitted required tags, trailing bytes, wrong
magic/version/type, or any resource limit before allocating nested data.

| Field class | Constraint |
|---|---|
| U16/U32/U64 | Exactly 2/4/8 bytes, unsigned big-endian; owner U64 is non-zero |
| ID | Exactly 16 bytes; handshake ID is fresh and single-use until expiry |
| KEY/HASH/SIG | Exactly 32/32/64 bytes; reject an all-zero X25519 *output* |
| nested bundle | 1..2,048 bytes, valid complete `TGSB/1/0x01` CFS; no nested trailing bytes |
| text | Valid shortest UTF-8, 1..4,096 bytes, no NUL; no normalization |
| nonce/ciphertext | Exactly 24 bytes / 17..4,112 bytes |

Every outer object has the exact registry tag set. A signature field is
omitted entirely (tag and length included) from its signed CFS. Nested object
bytes count against both their own and their parent's limit.

## Transcript and handshake correction

The r1 wording made the response transcript self-referential. Define
`response_core` as the response CFS with fields 7 (transcript) and 8
(signature) omitted. Then:

```
T0 = SHA-256("TGS/v1/transcript/0" || init_full_cfs)
T  = SHA-256("TGS/v1/transcript/1" || T0 || response_core)
```

Field 7 equals `T`; response signing covers the response with field 8 omitted
(and therefore includes field 7). All four X25519 values, IKM ordering, HKDF
labels, confirmation inputs, session ID derivation, expiry and single-use ID
rules remain exactly as r1 §5 states.

## Durable state and Keystore lifecycle template

The selected storage design must supply an authenticated, versioned
transaction with `state_generation = prior + 1`. A receive transaction stages
ratchet/replay mutation, authenticates AEAD, writes the new state and durable
generation, commits, and only then releases plaintext. A send transaction
stages and commits the send mutation before submission. Failure leaves no
partly usable state; it writes/retains a non-secret reset marker.

| Event | Required durable result | Secure action |
|---|---|---|
| Keystore invalidated/unavailable/unwrap failure | reset marker with typed cause | block; re-verify and create fresh session |
| authenticated-store MAC/decode failure | reset marker; preserve forensic error code | block; never recreate silently |
| observed generation lower than committed | `STORAGE_ROLLBACK` reset marker | block; explicit recovery |
| transaction crash/failure | previous committed state or reset marker only | block if outcome cannot be proven |
| app reinstall/device reset | no old state assumed; identity-change flow | block pending verification |

The Android security owner must fill hardware-backed requirement, user-auth
window, backup exclusion, invalidation policy, and supported-device behavior
in `STATE-AND-TRANSPORT-PACKETS.md`.

## Telegram provenance and durable-send contract

The Telegram adapter supplies an immutable inbound record containing account
ID, chat ID, sender user ID, message ID, update ID/order evidence, date, and
raw marked carrier. It MUST establish that the selected one-to-one peer and
the envelope sender owner/device match before the protocol parser can accept
the carrier. Carrier bytes never establish provenance themselves.

`submitCommitted(envelope, committed_send_generation)` returns either a
durable Telegram message identifier with account/chat binding, or
`SEND_OUTCOME_UNKNOWN`. Timeout, process death after submission, ambiguous
TDLib callback, or lost update is unknown—not success and not safe retry.
Unknown blocks the session for explicit encrypted resync/reset; the original
plaintext is never auto-sent as fallback and a fresh counter is never silently
used to retry it.

## Carrier and fallback UX decision

`TGS1:` reserves marked text. In a pending or configured secure chat, a
marked malformed/unsupported/authentication-failed carrier is visibly
rejected and never rendered as ordinary text. Leaving secure mode requires an
explicit warning/decision, discards the secure draft, and does not send it as
plaintext. Ordinary unmarked Telegram text is distinctly labelled non-secure
and cannot advance protocol state. Product and legal acceptance criteria and
owners remain open in the decision packet.
