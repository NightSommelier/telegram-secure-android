# Independent protocol review checklist

Use this checklist to record a review of revision 1. A checked item is evidence of review, not an implementation authorization. Record findings in `REVIEW-DECISION.md` with severity, rationale and required disposition.

## Inputs and scope

- [ ] Reviewer received the exact specification, both JSON fixture files and `OPEN-ISSUES.md`.
- [ ] Reviewer confirmed the scope is one verified Android device per user and 1:1 UTF-8 text only.
- [ ] Reviewer confirmed no security claim is made for Telegram metadata, endpoint compromise, screenshots, backups, groups, media or multi-device use.
- [ ] Reviewer confirmed this design does not modify MTProto, Telegram servers or TDLib semantics.

## Wire format and parsing

- [ ] CFS has a unique, implementable encoding for every object and field.
- [ ] Every field has a type, exact/maximum size and canonical rejection rule.
- [ ] Carrier, Base64, decoded-object and nested-field bounds can be enforced before allocation.
- [ ] Unknown, duplicate, out-of-order, truncated and trailing fields fail closed.
- [ ] Control messages and secure envelopes cannot be confused by magic, version or type.

## Identity, trust and handshake

- [ ] The identity bundle signature and rotation statement provide the claimed device-key continuity.
- [ ] Telegram peer/chat provenance is independently authenticated by the future adapter, not asserted by the carrier.
- [ ] Capability request/response binding, expiry and rate limits resist unsolicited or cross-chat setup.
- [ ] The verification QR/fingerprint uses a deterministic ordering and cannot verify a different peer/device.
- [ ] X25519 inputs, all-zero handling, role binding, transcript construction and signature coverage are complete.
- [ ] HKDF extract/expand inputs and labels provide intended key separation.
- [ ] Confirmation ordering prevents either party from becoming active before mutual confirmation.
- [ ] Session ID, expiry, suite and device binding cannot be substituted across peers or sessions.

## Ratchet, envelope and persistence

- [ ] A named maintained Signal Double Ratchet backend is acceptable for Android and its adapter boundary is sufficient.
- [ ] The 256 skipped-key and gap bounds are safe and operationally reasonable.
- [ ] Envelope associated data authenticates all routing and security-relevant cleartext fields.
- [ ] AEAD failure cannot consume replay/ratchet state.
- [ ] Send/receive durable transitions and uncertain-send recovery cannot silently duplicate, skip or downgrade secure text.
- [ ] Keystore reset, corruption and rollback produce visible blocking reset state.

## Versioning, UX and verification

- [ ] Unsupported versions/suites and malformed marked carriers never become plaintext.
- [ ] Explicit downgrade discards the secure draft and has no automatic plaintext fallback.
- [ ] Fixture values and encodings were independently reproduced by two implementations.
- [ ] Negative fixtures cover all error classes and state-mutation guarantees.
- [ ] Every unresolved issue has a documented owner and an acceptable closure criterion.
- [ ] Decision is recorded as APPROVED or CHANGES REQUIRED; approval includes scope and date.
