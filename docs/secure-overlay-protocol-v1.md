# Telegram Secure overlay protocol v1 — review specification

**Status:** REVIEW ONLY — `changes required` until a named independent reviewer records written approval in `protocol-review/REVIEW-DECISION.md`.

This is the implementation gate for the narrow MVP: one verified Android device per Telegram user and 1:1 UTF-8 text only. It specifies an application-content overlay; it does not alter MTProto, TDLib semantics, Telegram routing, or ordinary Telegram messages. Files, media, groups, multi-device fanout, history sync, backups and cross-platform clients are out of scope.

Normative terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are as in RFC 2119. A decoder MUST reject rather than repair a non-canonical input.

## 1. Profile and immutable limits

`protocol_version = 1`; `suite_id = 0x0001` is `Ed25519 + X25519 + HKDF-SHA-256 + XChaCha20-Poly1305 + reviewer-approved Signal Double Ratchet`. No other suite is negotiated in v1. An unsupported value is `UNSUPPORTED_VERSION` or `UNSUPPORTED_SUITE`, never a plaintext fallback.

| Item | Maximum / exact size |
|---|---:|
| Telegram carrier UTF-8 bytes, including marker | 8,192 |
| Base64url envelope text after `TGS1:` | 8,187 |
| decoded envelope | 6,144 bytes |
| any control payload | 2,048 bytes |
| encrypted UTF-8 plaintext | 4,096 bytes |
| device ID / session ID | exactly 16 bytes |
| Ed25519 / X25519 public key | exactly 32 bytes |
| Ed25519 signature | exactly 64 bytes |
| XChaCha nonce / AEAD tag | exactly 24 / 16 bytes |
| ratchet message number / previous-chain length | 0…2^32-1 |
| skipped message keys retained / receive-chain gap | 256 / 256 |
| bundle validity / session lifetime | 90 days / 30 days or 65,536 messages |

All timestamps are unsigned Unix seconds. Accept a bundle only when `created_at <= now + 300` and `now <= expires_at`; a session only when `now <= expires_at`. Clock failure or a backwards jump over 300 seconds blocks secure use as `CLOCK_UNTRUSTED`.

## 2. Canonical wire encoding

Every binary object is a **Canonical Field Sequence (CFS)**:

```
object := magic[4] || version:u8 || type:u8 || fields
field  := tag:u8 || length:u16be || value[length]
```

Fields are strictly increasing by tag, occur exactly once, and have exact minimal fixed-width values. Unknown fields, trailing bytes, indefinite/alternate integer representations, duplicate fields and non-canonical text are rejected. Integers are fixed-width unsigned big-endian; text is shortest valid UTF-8 with no NUL and is never normalized. Check outer-carrier and decoded limits before Base64 allocation, then object limits before parsing.

Telegram carries exactly `TGS1:` plus unpadded RFC 4648 base64url of one CFS envelope. The marker is reserved: text beginning with it is a secure carrier even if malformed, and MUST visibly fail rather than render as ordinary text in a configured or pending secure chat.

Common values: `U64` = 8 bytes; `U32` = 4 bytes; `ID` = 16 bytes; `KEY` = 32 bytes; `SIG` = 64 bytes; `HASH` = 32 bytes. Telegram user IDs are positive `U64`; device IDs are uniformly random opaque IDs, never hardware IDs.

## 3. Object registry

| Type | Magic/type | Required CFS fields (tag: meaning) |
|---|---|---|
| identity bundle | `TGSB/0x01` | 1 suite U16, 2 owner U64, 3 device ID, 4 key version U32, 5 created U64, 6 expires U64, 7 Ed key KEY, 8 X key KEY, 9 rotation HASH or empty, 10 signature SIG |
| capability request | `TGSC/0x01` | 1 request ID, 2 initiator bundle bytes, 3 target owner U64, 4 target device ID, 5 issued U64, 6 expires U64 |
| capability response | `TGSC/0x02` | 1 request ID, 2 responder bundle bytes, 3 initiator owner U64, 4 initiator device ID, 5 issued U64, 6 expires U64, 7 signature SIG |
| handshake init | `TGSH/0x01` | 1 handshake ID, 2 initiator bundle bytes, 3 responder bundle hash HASH, 4 initiator ephemeral KEY, 5 issued U64, 6 expires U64, 7 signature SIG |
| handshake response | `TGSH/0x02` | 1 handshake ID, 2 responder bundle bytes, 3 init hash HASH, 4 responder ephemeral KEY, 5 issued U64, 6 expires U64, 7 transcript HASH, 8 signature SIG |
| handshake confirm | `TGSH/0x03` | 1 handshake ID, 2 role (`0x49` I or `0x52` R), 3 transcript HASH, 4 confirmation 32 bytes |
| secure envelope | `TGSE/0x01` | §6 |

For a signed object omit the signature field, including tag and length, to form `signed_bytes`; `signature = Ed25519.Sign(signing_secret, SHA-256("TGS/v1/sign" || signed_bytes))`. A bundle rotation is empty only for the first identity; otherwise it is SHA-256 of the previously verified full bundle CFS and invalidates old sessions. A response signature uses its responder identity key.

## 4. Capability and trust

The user explicitly starts discovery for one ordinary 1:1 Telegram peer. The adapter, not carrier content, supplies authenticated inbound sender and chat; it MUST equal the bundle owner and selected peer. Send one request per peer per 10 minutes, at most three per 24 hours. `expires - issued <= 600`. A response is accepted only for a live request ID in the same peer/chat before expiry, after bundle and response signatures verify. Capability cache lasts at most 24 hours and is never trust or consent.

Before a session the UI compares fingerprints/QR derived as `base64url(SHA-256("TGS/v1/verify" || min(bundleA,bundleB) || max(bundleA,bundleB)))`. Only explicit successful comparison creates `VERIFIED`. A changed/new device, expired bundle, reset or corrupted local state blocks secure use and cannot overwrite a prior verified record.

## 5. Authenticated handshake

Roles are fixed by the request: initiator I and responder R. Both use verified bundles and fresh X25519 ephemerals. An init expires in 10 minutes and is single-use. Reject all-zero X25519 output, reused ID, mismatched bundle hash, invalid signature, wrong peer/chat/role, stale timestamp or transcript mismatch.

`init_signature` signs `SHA-256("TGS/v1/hs-init" || init signed_bytes)`; `response_signature` signs `SHA-256("TGS/v1/hs-resp" || response signed_bytes)`. Define `T0 = SHA-256("TGS/v1/transcript/0" || init_full_cfs)` and `T = SHA-256("TGS/v1/transcript/1" || T0 || response_full_cfs)`; the response transcript field equals T.

Let SI/SR be identity X25519 public keys and EI/ER ephemeral public keys. Concatenate in this exact order:

```
IKM = X25519(eI, SR) || X25519(SI, eR) || X25519(eI, eR) || X25519(SI, SR)
salt = SHA-256("TGS/v1/hs-salt" || T)
PRK  = HKDF-Extract(SHA-256, salt, IKM)
root_key      = HKDF-Expand(PRK, "TGS/v1/root" || T, 32)
confirm_I_key = HKDF-Expand(PRK, "TGS/v1/confirm/I" || T, 32)
confirm_R_key = HKDF-Expand(PRK, "TGS/v1/confirm/R" || T, 32)
session_id    = first16(SHA-256("TGS/v1/session" || T))
```

`confirmation = HMAC-SHA-256(confirm_<role>_key, "TGS/v1/confirm" || role || handshake_id || session_id || T)`. I sends confirmation after validating the response; R validates, durably creates the session, then confirms; I validates and durably creates the session. Neither is `SECURE_ACTIVE` beforehand. `root_key` enters only the approved ratchet adapter.

## 6. Signal Double Ratchet boundary and envelope

Use a maintained, independently reviewed Signal Double Ratchet library approved by the reviewer; the exact library/version/binding/CVE policy and adapter audit are blocking open issues. The adapter accepts root key, I/R role, session ID and peer-device binding and exports an opaque message key plus ratchet public key (32), previous-chain length U32 and message number U32. It retains at most 256 skipped keys, rejects a gap above 256, consumes a key only after successful AEAD and permits one-time use. Application code MUST NOT implement ratchet DH, KDF chains or skipped-key handling.

`TGSE/0x01` fields: 1 suite U16; 2 sender owner U64; 3 sender device ID; 4 recipient owner U64; 5 recipient device ID; 6 session ID; 7 session expiry U64; 8 ratchet public KEY; 9 previous-chain U32; 10 message number U32; 11 nonce (24); 12 ciphertext-with-tag (17…4112). Plaintext is valid UTF-8, 1…4096 bytes. `AD = SHA-256("TGS/v1/envelope-ad" || envelope CFS with fields 11 and 12 omitted)`. Encrypt using XChaCha20-Poly1305(message_key, nonce, plaintext, AD); field 12 is ciphertext then its 16-byte tag. Generate a fresh uniform nonce for every message key.

Before AEAD, verify peer/chat provenance, identities, suite, session ID, expiry and resource bounds. Do not mutate replay/ratchet state until AEAD succeeds; atomically persist the transition before displaying plaintext. On send persist the send transition before transport submission. An uncertain submission is `SEND_OUTCOME_UNKNOWN`: block the session and require explicit encrypted resync/reset; never silently retry at a new counter.

## 7. Durable state, reset and errors

Use a versioned, authenticated, transactional store with monotonic `state_generation`; its authentication key is Keystore-wrapped. A record contains identity fingerprint, peer/device binding, suite, expiry, ratchet state, skipped-key bound and generation. Rollback, unwrap failure, decode/authentication failure, missing key, hardware invalidation or failed transaction preserves a non-secret reset marker and blocks send.

| Code | Required result |
|---|---|
| `NOT_SECURE_CARRIER` | ordinary text only when marker absent |
| `MALFORMED_CARRIER`, `RESOURCE_LIMIT`, `NON_CANONICAL` | visible rejected secure message; no state change |
| `UNSUPPORTED_VERSION`, `UNSUPPORTED_SUITE`, `DOWNGRADE_DETECTED` | blocking state; no plaintext fallback |
| `PEER_BINDING_FAILED`, `BUNDLE_INVALID`, `AUTH_FAILED` | reject; no state change |
| `REPLAY`, `OUT_OF_ORDER_LIMIT`, `SESSION_EXPIRED` | reject and block/resync as appropriate |
| `STORAGE_FAILED`, `STORAGE_ROLLBACK`, `KEYSTORE_INVALIDATED`, `KEYSTORE_CORRUPT` | persistent security reset |
| `SEND_OUTCOME_UNKNOWN`, `CLOCK_UNTRUSTED` | send blocked; explicit recovery |

The only downgrade is an explicit user decision to leave secure mode after the blocking warning. Discard the secure draft; never auto-send it as plaintext. An ordinary Telegram message while secure is active is distinctly labelled non-secure and cannot drive a protocol transition.

## 8. Versioning and implementation gate

v1 accepts only this exact magic/version/type/field set. A future version needs a new version, migration, fresh labels/signatures and review; it MUST NOT reinterpret v1 bytes or negotiate by omission. The fixtures in `protocol-review/` are normative. No handshake, ratchet, carrier parser, transport adapter or Telegram UI is authorized until the decision is APPROVED and every blocking issue is closed in writing.
