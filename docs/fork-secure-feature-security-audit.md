# Fork-Secure Telegram feature security audit

**Audit date:** 2026-07-29
**Scope:** ordinary one-to-one cloud chats in the private Android fork. Native
Secret Chats and group chats are not changed by Fork-Secure.

## Executive result

The current build is a working text/photo/document/sticker prototype with a
central fail-closed send boundary. Unsupported outbound actions are blocked
before Telegram upload, but the media/state protocols and recovery design are
still incomplete.

Telegram will still observe both account IDs, message and file timing, carrier
and ciphertext sizes, delivery/read activity, scheduling, and IP/network data.
Fork-Secure cannot hide those properties while using Telegram transport.

## Current implementation

| Capability | Current result | Remaining exposure or gap |
| --- | --- | --- |
| Text | Encrypted `TGS1:` carrier; local display cache | Telegram still observes carrier size/timing |
| Replies and quotes | Encrypted body; plaintext quote fields stripped | Reply message ID remains Telegram metadata |
| Forwarding | Secure text is decrypted locally and re-encrypted for the destination | Secure media forwarding is blocked |
| Silent send | `notify=false` is preserved | Telegram sees the silent flag |
| Scheduled send | Encrypted carrier and schedule parameters are preserved | Telegram sees schedule; delayed/out-of-order ratchet behavior needs tests |
| Stickers | WEBP, TGS and WEBM bytes are encrypted under opaque upload names | File size and timing remain visible |
| Photos | Original bytes, name, MIME and caption are encrypted; native viewer works | Albums, spoilers and view-once are incomplete |
| Documents | File bytes and authenticated metadata are encrypted | Native media-specific playback is incomplete |
| Edits | Blocked fail-closed | Needs an authenticated edit control message |
| Reactions | Native Telegram reactions are available without per-action warnings | Telegram sees the emoji, target message ID and actor; this limitation remains documented in the secure-chat status details |
| Deletion | Telegram carrier and matching local text/content records are deleted | Authenticated remote delete controls are not implemented |
| Identity reset and recovery | Reset, identity-only archive, and manual identity-plus-history archive prototype | History restore pauses every recovered chat; automatic backup and safe multi-device protocol remain pending |

## Closed P0 fallback paths

1. Cloud drafts are cleared and not saved while the chat is protected.
2. Server link-preview discovery and attached webpage metadata are suppressed.
3. Plaintext quote text/entities and other reply-side content are stripped.
4. A central send gate plus direct edit/vote/todo guards reject unallowlisted
   protected-chat actions. Reactions are an explicit exception and use
   Telegram's normal unencrypted metadata path.
5. Telegram message/dialog deletion removes matching local display/content
   records; display memory and media files use bounded caches.

Durable encrypted display/content records remain intentionally unbounded until
the manual history archive passes physical reinstall testing and a retention
policy exists. Evicting them earlier could permanently remove access to old
message plaintext after the ratchet has advanced.

## Telegram feature matrix

### Can be protected with the current one-to-one model

- rich text, entities, captions and encrypted client-generated link previews;
- photos, video, GIF, voice, round video, audio and arbitrary files;
- contacts, static location and venues encoded as authenticated payloads;
- forwarding by local decrypt plus destination-session re-encryption;
- replies/quotes with encrypted quoted text;
- scheduled and silent carriers;
- authenticated edit, reaction, delete and expiry control messages.

These require typed canonical payloads, strict size limits, replay/order rules,
local UI support and negative tests. They must never reuse Telegram's plaintext
structured fields for protected content.

### Require a separate state protocol

- disappearing/view-once media and deletion acknowledgement;
- live location updates;
- polls, votes and collaborative todo state;
- multi-device fanout, device removal and identity-clone detection;
- key recovery and optional old-history recovery;
- sender-key group encryption, which is outside this audit.

### Cannot remain end-to-end private while preserving the server feature

- cloud drafts, server-side link previews, server translation/transcription and
  server content search;
- bots, inline bots, business bots, Mini Apps, games and payments that must read
  or process the input;
- public/channel stories, public polls, giveaways, paid media and statistics;
- contact discovery, presence, typing, read receipts and delivery metadata.

The correct protected-mode behavior is to disable these, use a local
alternative, or require an explicit and clearly labelled exit from secure mode.

### Already covered by a different Telegram security boundary

Telegram documents one-to-one voice/video calls as end-to-end encrypted.
Telegram Passport and native Secret Chats also have their own encryption
boundaries. Fork-Secure should not replace or silently modify them; it may only
improve verification and metadata/privacy explanations in the UI.

References: [Telegram APIs](https://core.telegram.org/),
[MessageMedia types](https://core.telegram.org/type/messagemedia),
[cloud drafts](https://core.telegram.org/api/drafts),
[scheduled messages](https://core.telegram.org/api/scheduled-messages),
[E2E calls](https://core.telegram.org/api/end-to-end/video-calls), and
[Telegram FAQ](https://www.telegram.org/faq).

## Ordered hardening plan

1. Add one outbound policy gate for every protected one-to-one chat. Initially
   allow only audited text, sticker, photo and document carriers.
2. Disable cloud draft synchronization, server link previews, plaintext quote
   fields, bot/inline actions and unsupported media while protected.
3. Bind local cache records to Telegram message IDs and purge them on delete,
   logout, account removal, identity reset policy and bounded retention.
4. Complete physical reinstall/recovery tests for the identity-only and manual
   identity-plus-history archives. Keep both formats distinct; history restore
   must pause every recovered contact rather than restore live ratchets.
5. Add native video, voice, round video, GIF and audio payloads one at a time.
6. Add authenticated edit/delete/reaction/expiry protocols and their conflict
   tests.
7. Audit notifications, widgets, clipboard, screenshots, share/export,
   accessibility, logs, crash reports and temporary files on both devices.

## Deferred privacy and resilience backlog

The following ideas are intentionally scheduled after the current recovery and
media milestones. They are not part of the message protocol and must not delay
the one-to-one secure-chat MVP.

### Planned candidates

1. Add a security and privacy checklist for Telegram 2FA, risky privacy
   settings, USB debugging and device-integrity warnings. Every suggested
   settings change must remain explicit and individually reviewable.
2. Add proxy health checks and optional proxy rotation as a Telegram transport
   feature. It must remain independent of `SecureOverlay`, preserve the user's
   selected routing policy and never silently enable a direct fallback.
3. Add a direct, non-reflective spoofed-link check at the URL-opening boundary,
   including Telegram usernames, link parameters and Unicode/IDN cases.
4. Evaluate encrypted local database storage after history recovery has a
   stable lifecycle. SQLCipher/Keystore designs may be used as references, but
   key loss, reinstall, migration, rollback and interrupted-write behavior need
   Fork-Secure-specific tests.
5. Design optional duress profiles and a false passcode only as a separately
   reviewed safety feature. Actions need durable `pending/completed/failed`
   state, safe retry behavior and authenticated activation bound to an approved
   contact. Remote deletion or logout must never be presented as atomic unless
   acknowledgements prove completion.

Voice modification, disguised application variants and wrong-passcode camera
capture remain research ideas only. They add significant performance, legal or
maintenance risk and have no planned MVP milestone.

### Integration groundwork

- Keep secure protocol, Telegram transport, local-at-rest protection and
  general privacy UI in separate packages with narrow adapter interfaces.
- Keep the protected-chat outbound policy as the single fail-closed send
  boundary; future privacy features may observe it but must not bypass it.
- Keep recovery archives versioned and typed so a future storage provider can
  upload only authenticated ciphertext. Provider credentials, scheduling and
  retention do not belong in archive codecs.
- Keep destructive safety actions outside ratchet/session transactions and
  expose idempotent operations with persisted results.
- Add every candidate through focused RED/GREEN tests and a feature flag before
  exposing it in the private beta.

## MVP acceptance boundary

The UI must not show a protected shield if any visible send action can transmit
content through a plaintext Telegram path. Every unsupported action must be
blocked with a localized explanation. Network and database tests must prove
that Telegram receives only opaque carriers/files for every allowlisted action,
and rejected actions cause no send and no secure-state mutation.
