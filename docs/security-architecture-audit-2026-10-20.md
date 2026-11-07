# Security and Architecture Audit: Fork-Secure (2026-10-20)

**Date:** 2026-10-20  
**Scope:** `telegram-secure-android/SecureOverlay/src/main` (cryptography, protocol, storage, backups), integration points in `TMessagesProj` (`ChatActivity`, `SendMessagesHelper`, `MessageObject`, media pipeline), build configuration, and scripts.  
**Method:** Manual code review (static analysis). This is not a formal cryptographic audit or on-device penetration test.  
**Status:** In progress — findings are added as the analysis proceeds. Last updated 2026-11-01. The code changed after the first pass, so a re-verification of earlier findings against the current source is under way (see [Re-verification After Remediation](#re-verification-after-remediation-2026-11-01-in-progress)). Also reviewed since the first draft: `NotificationsController`, `MediaDataController`, `ChatActivityEnterView`, manifest/backup config, dependency supply chain, `SecureMediaCrypto`, `SecureSavedMessage*`, the local stores, the backup/recovery subsystem (`SecureIdentityBackup*`, `SecureHistoryBackup*`, `SecureRecoveryGenerationStore`), `SecureLinkGuard`, the outbound guard, and screen protection. Remaining items are listed under [Pending Review](#pending-review).

## Severity Scale

| Level | Definition |
| --- | --- |
| Critical | Direct compromise of confidentiality or authenticity of secret content or cryptographic keys |
| High | Realistic attack or failure that violates stated security guarantees or causes data leakage |
| Medium | Security degradation, DoS, metadata leakage, or brittle architecture carrying regression risks |
| Low | Defense-in-depth, code hygiene, documentation discrepancies |
| Info | Informational observations without direct security risks |

## Summary Table

| ID | Severity | Area | Summary |
| --- | --- | --- | --- |
| SA-01 | Critical | Groups / SenderKey | `SenderKeyDistributionMessage` is broadcast to group chats as plaintext carrier messages without pairwise encryption |
| SA-02 | Critical | Groups / Authenticity | Sender key distribution is accepted from anyone; sender identity is determined solely by Telegram's `from_id` |
| SA-03 | High | Pairing / TOFU | Initial pairing offer is automatically accepted without fingerprint verification (vulnerable to Telegram server MITM) |
| SA-04 | High | Sender Binding | Session address for decryption is taken from message `from_id`; result is cached under a different peer chat |
| SA-05 | High | Ratchet Rollback | Rolling back a Signal session after a "rejected" edit can lead to message key reuse |
| SA-06 | High | Concurrency | Session encryption and decryption are not serialized (different locks, `encryptText` uncoordinated) causing lost ratchet state updates |
| SA-07 | High | Pairing Bypass | Incoming `PreKeySignalMessage` for a peer without a trusted identity silently establishes a session and enables `PROTECTED` mode |
| SA-08 | Medium | Error Handling | `DuplicateMessageException` is disguised as a "deleted message" and wipes the local record |
| SA-09 | Medium | Key Hygiene | Signed pre-key (ID 2) and Kyber last-resort key (ID 3) are never rotated; one-time pre-keys are re-published cyclically |
| SA-10 | Medium | Identity Binding | Pairing offer is not cryptographically bound to sender/recipient Telegram user IDs; legacy v1 offer without metadata signature is still accepted |
| SA-11 | Medium | Plaintext Leak | Decrypted text is placed into Android notifications (lock screen, wearables, notification listeners) |
| SA-12 | Medium | Plaintext Leak | IME incognito flag is set only for native Secret Chats; the keyboard learns Fork-Secure plaintext |
| SA-13 | Medium | Plaintext Leak | `FileLog.d` writes decrypted captions / contact names / music titles (pinned-message path) |
| SA-14 | Medium | Local Metadata | Chat trust state is stored in plaintext SharedPreferences; record names expose peer IDs, carrier digests, and tombstones |
| SA-15 | Medium | Local Metadata | Secure media/link classification is indexed into Telegram's plaintext SQLite `media_v4` |
| SA-16 | Medium | Architecture / Storage | All secure state lives in one unbounded SharedPreferences XML; writes span several stores without transactions |
| SA-17 | Medium | Media / DoS | "Streaming" AES-GCM is probably fully buffered by Conscrypt; with a 512 MiB limit this means OOM |
| SA-18 | Medium | Traffic Analysis | No padding: carrier length reveals plaintext length and content type; media size is exact |
| SA-19 | Medium | Architecture / Scope | Groups are implemented and reachable, contrary to documented scope; engine state is constructed ad hoc everywhere |
| SA-20 | Low | Saved Messages | Record `kind` header is not in the AAD; records are not bound to message ID (replay / edit rollback) |
| SA-21 | Low | Domain Separation | Control/display sentinels share a namespace with user text (legacy UTF-8 path and `TYPE_TEXT`) |
| SA-22 | Low | Robustness | Static global `failedDecryptCarriers` is not scoped by account/peer and permanently caches transient failures |
| SA-23 | Low | Hygiene | `requireSafeFile` does not confine to a root; predictable `.tmp` holds plaintext after a crash |
| SA-24 | Low | Backup Surface | `allowBackup="true"` + default `onFullBackup` expose plaintext secure state to `adb backup` / D2D |
| SA-25 | Low | Supply Chain | No Gradle dependency verification for `libsignal` from a third-party Maven repository |
| SA-26 | Low | Notifications | Notification path deletes with `revoke=true`, chat path with `false` (inconsistent destructive action) |
| SA-27 | High | Backups | "No password" export writes the identity private key and full history (plaintext + media keys) under a public, constant KDF input |
| SA-28 | Medium | Backups | 5-character minimum backup password with GPU-friendly PBKDF2; password passes through immutable `String` |
| SA-29 | Medium | Identity / Multi-account | One installation-wide Signal identity for all Telegram accounts (cross-account linkability); history restore wipes other accounts' history |
| SA-30 | Medium | Link Guard | Host extraction mis-parses `@` in path/query and `\`; the "open link" dialog can display a host other than the real destination |
| SA-31 | Medium | Link Leak (needs verification) | Links from protected chats may open with Instant View / in-app browser, which can disclose the decrypted URL to Telegram |
| SA-32 | Low | Outbound Guard | Guard is keyed on the `TGS1:` text prefix; plaintext starting with the marker bypasses encryption |
| SA-33 | Low | Link Guard | Minor analyzer gaps: case-sensitive host replacement, no IPv6 handling, exact-match-only confusable list |
| SA-34 | Medium | Plaintext Leak | The chat list (`DialogCell`) shows decrypted previews but its window has no `FLAG_SECURE` (screenshots, recents thumbnail, screen recording) |
| SA-35 | Info | Send Policy | In `WAITING`/`PAUSED` modes the outbound guard lets plaintext through; the UI must make this unmistakable |
| SA-36 | Low | Robustness | Failed-decrypt cache keys on a 32-bit `String.hashCode()` of the carrier, so a crafted collision can suppress a legitimate message for 10 minutes (found in re-verification) |
| SA-37 | Medium | Binding (residual) | Offer-owner and sender checks are skipped when the offer is v2 or `senderUserId == 0`; protections are opt-in per call site (found in re-verification) |
| SA-38 | Low | Architecture | `SecureSessionManager` exists but 28 direct `new SecureChatEngine(...)` calls remain (found in re-verification) |
| SA-39 | High | Storage (regression) | `KeystoreEncryptedBlobStore` swallows all init errors and silently falls back to a per-instance in-memory map: identity, sessions and pre-keys stop persisting without any error (found in re-verification) |
| SA-40 | Medium | Metadata masking | `SecureNameMask.getOrGenerateKey(null)` caches an all-zero key for the process lifetime, turning record-name masking into an unkeyed hash (found in re-verification) |
| SA-41 | Low | Migration | Legacy SharedPreferences are cleared before the SQLite transaction commits; a crash loses all protocol state (found in re-verification) |
| SA-42 | Medium | Backup (regression) | Backup/extraction exclusions name files that no longer exist (`…_state.xml`, `telegram_secure_database.db`); the real `telegram_secure_overlay_v2.db` is not excluded (found in re-verification) |
| SA-43 | Medium | Backups (side effects) | The strength policy is also enforced on **decrypt**, so older archives (5-11 char passwords, or "no password") can no longer be restored; the "entropy" rule is just 4 distinct characters (found in re-verification) |
| SA-44 | Low | Media format | For attachments whose padded size fits one segment (≤ 64 KiB), the segmented and legacy-padded ciphertext sizes are identical, so `decryptAttachmentFile` always takes the segmented path; legacy-padded files of that size would fail authentication (found in re-verification) |
| SA-45 | Medium | Identity lifecycle | `SecureChatEngine.isStale()` compares the per-account epoch with **account 0's** epoch, so engines for other accounts are permanently "stale" or never detect a reset (found in re-verification) |
| SA-46 | Low | Send policy / UI | In `INITIAL_PAIRING_PENDING` the "unencrypted" hint is cleared while the outbound guard still sends plaintext (found in re-verification) |

## Detailed Findings

### SA-01 (Critical): Group SenderKey Is Distributed via Plaintext

**Location:**
- [ChatActivityEnterView.java:7935-7976](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/Components/ChatActivityEnterView.java#L7935-L7976) — `/secure-start`, `/secure-group-key`, `/secure-group-rotate`, and automated redistribution prior to each message transmit `createGroupSenderKeyDistributionCarrier(dialog_id)` as plain text directly to the group `dialog_id`.
- [SendMessagesHelper.java:3596](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java#L3596) — Same transmission logic in the outbound message path.
- [SecureChatEngine.java:199-208](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L199-L208) — Carrier `TYPE_SENDERKEY_DISTRIBUTION` consists of raw distribution message bytes without any encryption layer.

**Details:** The `SenderKeyDistributionMessage` in libsignal contains the chain key and public signature key in the clear; Signal relies on it being delivered inside an established pairwise 1:1 session. A code comment in [SecureCarrierCodec.java:17](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureCarrierCodec.java#L17) explicitly notes this requirement ("sent via 1:1 pairwise secure session"), yet the implementation publishes it straight into the group chat.

**Impact:** The Telegram server, any member of the group (including non-fork users, bots, or future members with access to chat history) can derive all message keys and decrypt **all** group messages. Simultaneously, the UI misleadingly displays the group as secure.

**Remediation:** Immediately disable group encryption (via feature flag / fail-closed in `SendMessagesHelper`). Before re-enabling: deliver distributions strictly over established and verified 1:1 sessions (`encrypt(peerAddress, distribution)`), enforce sender key rotation upon group membership changes, and add tests ensuring carrier type 5 is never dispatched to `dialog_id < 0`. Synchronize documentation: [TELEGRAM-ANDROID-FORK-MAP.md](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/docs/TELEGRAM-ANDROID-FORK-MAP.md) states that group chats remain standard Telegram.

---

### SA-02 (Critical): Unauthenticated Acceptance of Group Sender Key Distribution

**Location:** [SecureChatEngine.java:211-228](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L211-L228), [ChatActivity.java:21344-21351](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L21344-L21351), `NotificationsController.java:1884-1889`.

**Details:** `processGroupSenderKeyDistributionCarrier(message.getFromChatId(), carrier)` stores the distribution under the address `telegram-user-<from_id>`. Here, `from_id` is unauthenticated server metadata; the distribution is not bound to the sender's identity key. Furthermore, receiving any distribution automatically activates the group (`enableGroup()` → `markPaired`) and clears global `failedDecryptCarriers`.

**Impact:** The server or an attacker in the group can forge a distribution on behalf of any arbitrary user and subsequently send "verified" (`forkSecureVerified = true`) messages impersonating them; they can also force-enable secure mode for the group.

**Remediation:** Accept distribution messages strictly as payload within decrypted pairwise messages originating from verified peers, ensuring the sender address strictly matches the pairwise session address; never alter chat security modes based on untrusted inbound traffic without explicit user confirmation.

---

### SA-03 (High): TOFU Auto-Acceptance of Initial Pairing Offer

**Location:** [SecureChatEngine.java:266-396](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L266-L396) (`canAutoAcceptPairingOffer()` → `ACCEPTED_INITIAL`), [ChatActivity.java:21305-21315](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L21305-L21315) — Automatically invoked during message history rendering, immediately dispatching an ACK.

**Details:** The pre-key bundle is transmitted over standard Telegram cloud messages, meaning it transits the server (the primary adversary in the threat model). If the mode is `OFF`, the initial offer is accepted without user interaction, a session is initialized, the chat transitions to `PROTECTED`, and an acknowledgment is dispatched automatically. Fingerprint comparison (`getOwnFingerprint`/`getTrustedFingerprint`) is purely optional.

**Impact:** The server (or anyone with message interception capability) can perform a Man-in-the-Middle (MITM) attack by replacing both bundles, while the user is shown a "protected" chat status. Additionally, any contact can forcibly initiate and transition a chat into secure mode via a single message.

**Remediation:** Distinguish between `PROTECTED_UNVERIFIED` and `VERIFIED` states; mandate explicit user consent to accept a pairing offer; display a persistent visual indicator for unverified sessions; ideally implement QR code or safety number verification derived from both identity keys.

---

### SA-04 (High): Signal Session Address Inferred Directly from `from_id`

**Location:** [SecureChatEngine.java:1076-1079](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L1076-L1079), similarly in `decryptAttachmentManifest` (834-840) and `decryptStaticStickerManifest` (487-493); called from [ChatActivity.java:21414](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L21414).

**Details:** An engine instance initialized for peer `P` decrypts payloads using the session `telegram-user-<senderUserId>` whenever `senderUserId > 0`, but it caches the resulting plaintext, applies delete-control records, and calls `markPaired` within the stores bound to `P`. Signal message contents do not include authenticated associated data containing the conversation or recipient identifier.

**Impact:** A message valid for a session with user `X` can be injected or replayed into a chat with peer `P` and presented as verified; a `TYPE_CONTROL_DELETE` sent from `X` could delete records inside chat `P`; a message key in `X`'s session is consumed, leading to decryption failures (DoS) for legitimate subsequent messages in `X`'s chat. It also triggers `markPaired(P)` even when no session exists with `P`.

**Remediation:** In 1:1 conversations, strictly enforce `peerAddress` and reject any message where `senderUserId != peerUserId`; embed authenticated contextual fields (`sender`, `recipient`, `conversation id`) into the `FSC1` plaintext envelope.

---

### SA-05 (High): Ratchet Rollback on Failed Edit Can Cause Message Key Reuse

**Location:** [SecureChatEngine.java:619-708](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L619-L708) (`rollbackAttachmentEdit`, `rollbackTextEdit`).

**Details:** After generating an outbound carrier, the session state is reverted to a previous snapshot if Telegram "rejects" the edit. The check ensuring that "no subsequent message used the session" is strictly local. In ambiguous failure scenarios (network timeout, connection drop after server acknowledgment, `FLOOD_WAIT` post-receipt), the carrier encrypted with message key `N` might have been delivered, while the subsequent message will reuse key `N` with entirely different plaintext.

**Impact:** Reusing message keys and IVs (AES-CBC + HMAC in libsignal) undermines core cryptographic properties, exposes plaintext prefix equalities, and causes `DuplicateMessageException` along with permanent message loss on the recipient side (see SA-08).

**Remediation:** Never roll back ratchet state once a carrier has been handed over to the network layer; treat the message key as consumed if an edit fails. Rollbacks should strictly be limited to pre-flight client validations prior to network dispatch (e.g., local caption length validation).

Call sites: [SendMessagesHelper.java:5887-5915](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java#L5887-L5915) rolls back session state on **any** `error` returned by `messages.editMessage`, including internal/timeout errors; [SendMessagesHelper.java:1531-1562](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java#L1531-L1562) triggers rollbacks when cancelling an edit.

---

### SA-06 (High): Race Condition Between Encrypt and Decrypt on Same `SessionRecord`

**Location:** [SecureChatEngine.java:56-57](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L56-L57) — Separate locks (`DECRYPT_LOCK` and `ENCRYPT_LOCK`); [SecureChatEngine.java:431-435](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L431-L435) — `encryptText`, `encryptContact`, `encryptLocation`, `encryptDeleteControl`, and `createPairingAcknowledgement` execute with no locks at all; [KeystoreSignalProtocolStore.java:250-270](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/KeystoreSignalProtocolStore.java#L250-L270) — `loadSession`/`storeSession` lack record-level mutual exclusion.

**Details:** `SessionCipher` in libsignal 0.86.6 does not employ internal monitor synchronization (verified via `javap` — no `monitorenter` instructions), executing a standard load → modify → store sequence that relies on the caller to serialize operations per address. Decryption is triggered concurrently from the UI thread (`ChatActivity`) and background queues (`NotificationsController`, `DialogCell` previews), while encryption originates from both UI interactions and `SendMessagesHelper`.

**Impact:** Concurrent execution of encryption and decryption causes later `storeSession` calls to overwrite prior updates:
1. Reversion of the sending chain counter → message key reuse (similar to SA-05).
2. Loss of receiving chain / skipped keys → inability to decrypt subsequent inbound messages.
3. Overwritten or dropped DH ratchet steps, desynchronizing the ratchet state.

**Remediation:** Introduce a unified per-address (or global) lock guarding **all** operations that read or write sessions, identities, pre-keys, and sender keys (including `establish`, rollbacks, and `acceptPendingIdentity`); implement concurrent stress tests exercising interleaved encrypt/decrypt operations.

---

### SA-07 (High): Explicit Pairing Bypass via Inbound PreKey Message

**Location:** [KeystoreSignalProtocolStore.java:173-178](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/KeystoreSignalProtocolStore.java#L173-L178) (`isTrustedIdentity` returns `true` if identity is not yet saved), [SecureChatEngine.java:1076-1144](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L1076-L1144) (`markPaired` invoked upon any successful decrypt).

**Details:** Published pre-key bundles in cloud messages are fully accessible to the server. The server (or an eavesdropper observing an offer) can construct a `PreKeySignalMessage` under an arbitrary identity and deliver it to a chat with a peer for whom no trusted identity has been stored. libsignal saves the unverified identity (TOFU), initializes the session, and the engine marks the chat as paired (`markPaired`) — entirely bypassing peer offer verification, `PairingOfferResult`, and UI confirmation. Combined with SA-04, this succeeds even with forged `from_id` metadata.

**Impact:** Total bypass of the "pending identity / fingerprint" verification model; seamless zero-click MITM on first contact.

**Remediation:** Enforce that `isTrustedIdentity` returns `true` exclusively for identities explicitly acknowledged via `receivePairingOffer`/`acceptPendingIdentity` (using an explicit allow-list); ensure decryption does not implicitly alter the chat security state; accept `PreKeySignalMessage` strictly when in a `WAITING` state corresponding to an outbound offer.

---

### SA-08 (Medium): `DuplicateMessageException` Disguised as Deletion

**Location:** [SecureChatEngine.java:1149-1159](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L1149-L1159), handled in [ChatActivity.java:21421-21432](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L21421-L21432).

**Details:** A re-delivered or replayed message (due to server replay, lost cache after recovery/clearing, or side effects of SA-05/SA-06) returns `CONTROL_DELETE_DISPLAY`, triggers `forgetByDigest` for its digest, and causes `ChatActivity` to permanently **delete the Telegram message** (`deleteMessages`).

**Impact:** The server can coerce a client into hiding or deleting arbitrary historical messages simply by re-delivering their carrier payloads; protocol anomalies are misrepresented as legitimate peer deletions, complicating debugging and masking attacks.

**Remediation:** Introduce a distinct "duplicate / replayed message" UI indicator without initiating destructive actions; restrict message deletion strictly to verified and authenticated `TYPE_CONTROL_DELETE` control packets.

---

### SA-09 (Medium): Absence of Signed and Kyber Pre-Key Rotation

**Location:** [KeystoreSignalProtocolStore.java:116-151](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/KeystoreSignalProtocolStore.java#L116-L151).

**Details:** `signedPreKeyId = 2` and `kyberPreKeyId = 3` are generated once during initialization and never replaced unless the identity is completely reset. Furthermore, one-time pre-keys are dispensed cyclically using `prekey_offer_offset`, causing identical one-time keys to appear across multiple published pairing offers.

**Impact:** Compromise of the long-lived signed pre-key (e.g., via device backup extraction or forensic physical access) impacts past and future initial session handshakes; re-issuing an already consumed one-time pre-key breaks session negotiation for subsequent peers (`InvalidKeyIdException`).

**Remediation:** Implement periodic rotation for signed and Kyber pre-keys, retaining historical keys over a graceful sunset window; treat one-time pre-keys as strictly consumable (retiring them from the available pool once published).

---

### SA-10 (Medium): Pairing Offer Not Cryptographically Bound to Participants

**Location:** [SecurePreKeyBundleCodec.java:93-126](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecurePreKeyBundleCodec.java#L93-L126), [SecurePreKeyBundleCodec.java:139-172](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecurePreKeyBundleCodec.java#L139-L172).

**Details:** The v2 envelope signature covers public keys and recovery metadata, but omits the Telegram user IDs of the sender and intended recipient. Additionally, the legacy v1 format (which lacks metadata signatures) is still accepted for establishing new peers.

**Impact:** Unknown-Key-Share (UKS) vulnerability: the server can replay user A's pairing offer into a conversation with user M. Furthermore, downgrading to v1 strips recovery generation protections during initial pairing.

**Remediation:** Include `owner_user_id`, `intended_peer_id`, and a timestamp/nonce inside the signed payload; reject legacy v1 offers once client migration is complete.

---

### SA-11 (Medium): Decrypted Plaintext in Android Notifications

**Location:** [NotificationsController.java:1861-1947](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/NotificationsController.java#L1861-L1947) (`ForkSecureTextPreview` formatted with `result`; also `messageObject.messageText = result`).

**Details:** Decryption is skipped only while the device is locked. Once it's unlocked, the decrypted text goes into the system notification. The notification stays visible after the device locks again, and it's forwarded to wearables, Android Auto, notification history, and any app holding `NotificationListenerService` access. The notification path also advances the ratchet and processes group distributions (SA-02) in the background.

**Impact:** Secure plaintext leaves the app's process and its protection boundary: lock screen, third-party listeners, OEM notification logs.

**Remediation:** Default to a generic "New secure message" notification with `VISIBILITY_SECRET`/`PRIVATE` and no content. If previews are allowed, make that a separate explicit setting. Don't perform protocol state transitions (distributions, deletions) from the notification path.

---

### SA-12 (Medium): Keyboard Learns Fork-Secure Plaintext

**Location:** [ChatActivityEnterView.java:5808-5812](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/Components/ChatActivityEnterView.java#L5808-L5812): `IME_FLAG_NO_PERSONALIZED_LEARNING` is set only when `encryptedChat != null` (native Secret Chat).

**Details:** In a `PROTECTED` Fork-Secure chat, and in protected Saved Messages, the keyboard runs in normal mode.

**Impact:** Typed plaintext flows into the IME's personal dictionary and prediction model, which may be cloud-synced (Gboard, SwiftKey, OEM keyboards).

**Remediation:** Set `IME_FLAG_NO_PERSONALIZED_LEARNING` whenever the dialog is in any Fork-Secure mode, and re-apply `imeOptions` when the mode changes.

---

### SA-13 (Medium): Decrypted Content Written to `FileLog`

**Location:** [ChatActivity.java:32287-32288](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L32287-L32288): `FileLog.d("ForkPinned: resolved secure label for pinned message: " + pinnedText)`. `getForkSecureReplyLabel` ([ChatActivity.java:23282-23330](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L23282-L23330)) returns the decrypted caption, contact name, or performer/title.

**Details:** `FileLog` writes to disk in debug builds, and in release builds when logging is enabled. These logs are routinely attached to bug reports. There are also many `FileLog.d` lines with metadata: message IDs, dialog IDs, media types, URL counts (`MediaDataController.java:4242, 4554, 4697`; `ChatActivity.java:22443`).

**Impact:** Secure plaintext and classification metadata are persisted outside the encrypted store.

**Remediation:** Remove secure content from all log statements. Add a CI lint/grep rule (e.g. forbid `FileLog.*(.*(pinnedText|caption|plaintext|localText))`). Log error codes only.

---

### SA-14 (Medium): Plaintext Trust State and Metadata in Local Storage

**Location:** [SecureChatState.java:12-58](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatState.java#L12-L58) (plain `SharedPreferences` `telegram_secure_chat_state_v1`: `paired.`, `pending-carrier.`, `identity-epoch`, …). Record names in [SecureLocalTextStore.java:117-119](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureLocalTextStore.java#L117-L119) and [SecureLocalMessageCache.java:66-86](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureLocalMessageCache.java#L66-L86) (`incoming-text.v1.<account>.<peer>.<sha256(carrier)>`, `fork_secure_tombstone_v1/...`).

**Details:** Values in `KeystoreEncryptedBlobStore` are encrypted, but record names are plaintext. Chat state (who is paired, pending identities, identity epoch) has neither confidentiality nor integrity protection.

**Impact:** Anyone with access to app files (root, forensics, backup, see SA-24) gets the list of secure contacts, which messages were decrypted on this device (the carrier hash matches what the server sees), and which were remotely deleted. Editing `paired.*`/`waiting.*` changes trust logic without touching the Keystore.

**Remediation:** Move chat state into the encrypted store, or at minimum MAC it with a Keystore-held key. Derive record names as `HMAC(K_name, account‖peer‖digest)` instead of embedding IDs.

---

### SA-15 (Medium): Secure Media/Link Classification in Telegram's Plaintext SQLite

**Location:** [MediaDataController.java:4200-4245](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/MediaDataController.java#L4200-L4245) (`indexForkSecureMedia` → `REPLACE INTO media_v4`), [MediaDataController.java:4650-4700](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/MediaDataController.java#L4650-L4700) (decrypts text to search for URLs and writes a `MEDIA_URL` row). Callers: [ChatActivity.java:22540-22590](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L22540-L22590).

**Details:** For secure messages, `cache4.db` records the type (photo / video / voice / music / GIF / file / **contains a URL**), which the server can't learn. The serialized `messageOwner` is a live object that the UI thread may mutate while `serializeToStream` runs on `Utilities.globalQueue`. That's a data race and a crash risk. *Unverified:* whether `messageOwner.media` has already been replaced with decrypted metadata (file name, MIME, `attachPath`) when it's serialized. If so, manifest secrets reach plaintext SQLite.

**Impact:** Local leakage of exactly the metadata the encrypted manifest is designed to hide.

**Remediation:** Keep the shared-media index only in `SecureMediaIndex` (the encrypted store) and drive counters and UI from it. Snapshot (copy) TL objects on the UI thread before any background serialization.

---

### SA-16 (Medium, Architecture): Single Unbounded SharedPreferences File, No Cross-Store Transactions

**Location:** [KeystoreEncryptedBlobStore.java](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/KeystoreEncryptedBlobStore.java) (`getAll()` in `replace*`, `delete*`, `snapshotPrefixes`). [KeystoreSignalProtocolStore.java:312-319](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/KeystoreSignalProtocolStore.java#L312-L319): `has()` decrypts a full blob just to test existence, and `putIndexed` is two separate commits. [SecureChatEngine.java:1477-1527](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L1477-L1527): `acceptPendingIdentity` makes about 6 independent writes across 3 stores.

**Details:** Identity, sessions, pre-keys, sender keys, every message display copy, media manifests (including keys), and tombstones share one XML file. Android loads it fully into memory and rewrites it fully on every `commit()`. The docs state that display records are intentionally "unbounded". Protocol state, chat state (`SecureChatState`), and the recovery store are separate files with no shared transaction, and rollback is best-effort inside `catch`.

**Impact:** O(n) cost per message, leading to ANR/OOM as history grows. A crash between writes leaves inconsistent trust state (e.g. new identity saved but `pending` not cleared, or the old session deleted with no new one). Every `containsSession` is a Keystore AES-GCM operation.

**Remediation:** Move to SQLite/Room (or SQLCipher with a Keystore-wrapped key) with real transactions. Use separate tables for protocol state, chat state, and display copies. Add a retention policy. Run multi-step operations (`acceptPendingIdentity`, restore) in a single transaction.

---

### SA-17 (Medium): "Streaming" Media Encryption Likely Buffers the Entire File

**Location:** [SecureMediaCrypto.java:20-26](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureMediaCrypto.java#L20-L26) (`MAX_ATTACHMENT_BYTES = 512 MiB`), [SecureMediaCrypto.java:406-429](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureMediaCrypto.java#L406-L429), [SecureMediaCrypto.java:491-511](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureMediaCrypto.java#L491-L511).

**Details:** The code reads in 64 KiB chunks, but on Android `Cipher.getInstance("AES/GCM/NoPadding")` resolves to Conscrypt's `OpenSSLAeadCipher`, which accumulates all input until `doFinal()` (certainly for decryption, typically for encryption too). *Requires on-device confirmation.* On the plus side, the ciphertext's SHA-256 from the authenticated manifest is checked **before** decryption, so releasing unauthenticated plaintext isn't a concern.

**Impact:** Heap use grows with file size (even with `largeHeap`), so large videos and documents cause OOM/crash. A peer can trigger this on purpose (DoS) by sending a large file.

**Remediation:** Use segmented AEAD (e.g. STREAM: AES-GCM per 64 KiB segment with a counter-derived nonce and a last-segment flag, like Tink's `AesGcmHkdfStreaming`). Until then, lower the limit to a safe size and add a device test with a file larger than 100 MiB.

---

### SA-18 (Medium): No Padding — Length Leakage

**Location:** [SecureContentCodec.java:467-480](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureContentCodec.java#L467-L480) (`encode` has no padding), [SecureMediaCrypto.java:437-440](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureMediaCrypto.java#L437-L440) (ciphertext = plaintext + 16).

**Details:** Carrier length maps directly to plaintext length. Control messages have recognizable fixed sizes: location = 24-byte payload, pairing ack/ready/reject are constant strings, delete-control = 32·n. Media file size is exact, so known files (memes, documents) can be identified by size.

**Impact:** The server can classify content (location, delete, ack) and estimate message length. That's significant for a messenger whose adversary is the server.

**Remediation:** Pad the `FSC1` plaintext to buckets (e.g. 160 B as Signal does, or powers of two), and pad media to size buckets (Padmé).

---

### SA-19 (Medium, Architecture): Scope Drift and Engine Lifecycle

**Location:** [TELEGRAM-ANDROID-FORK-MAP.md](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/docs/TELEGRAM-ANDROID-FORK-MAP.md) says "channels, and groups remain standard Telegram". In contrast: `applySecureTextOverlayInternal` accepts `isChatDialog` ([ChatActivity.java:21258](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L21258)), `ChatActivityEnterView` has group commands, and `MessagesController.java:16163` calls `rotateGroupSenderKey`. The `SecureChatEngine` constructor ([SecureChatEngine.java:163-182](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L163-L182)) runs `resumeInterruptedRestore`, `resumeInterruptedImport`, and `ensureLocalIdentity` every time, and engines are created ad hoc in dozens of places (`SendMessagesHelper`, `NotificationsController`, `DialogCell`, …).

**Details:** (1) Groups are reachable through commands and inbound processing, yet docs and tests treat them as out of scope, which is how SA-01/SA-02 slipped in. (2) Nothing owns the engine lifecycle. Every construction may trigger recovery/import and Keystore work on any thread, including the UI thread. (3) `peerUserId` holds both user IDs (>0) and group IDs (<0), so branches like `peerUserId >= 0` are scattered through the engine.

**Remediation:** Put groups behind a compile-time/runtime feature flag, off by default. Add a per-account `SecureSessionManager` singleton that owns locking (SA-06), caching, and recovery, with a single UI entry point. Split `DirectChatEngine` and `GroupChatEngine` into separate types.

---

### SA-20 (Low): Saved Messages Records

**Location:** [SecureSavedMessageCrypto.java:31-127](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureSavedMessageCrypto.java#L31-L127). Used in [SendMessagesHelper.java:5820-5827](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java#L5820-L5827).

**Details:** The AAD contains only `generation`. The `kind` byte (TEXT/PHOTO) and `MAGIC` are unauthenticated. `encryptRecord(byte[], key)` always labels records as `PHOTO`, including text edits. Records aren't bound to a message ID, account, or creation time. The key is static per generation (no forward secrecy), and `rotate()` leaves old records undecryptable.

**Impact:** The server can flip the kind (changing the decryption path), replace an edited record with an older one (rolling back an edit), or duplicate records. All of these still authenticate.

**Remediation:** Put `MAGIC‖generation‖kind‖account‖record_id` in the AAD. Keep previous key generations for decryption after rotation.

---

### SA-21 (Low): Control Sentinels Share a Namespace with User Text

**Location:** [SecureChatEngine.java:1081-1135](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L1081-L1135).

**Details:** The UI maps results by comparing strings against `\u0000fork-secure-display:*`. Both the legacy path (non-`FSC1` UTF-8) and `TYPE_TEXT` can yield any string, including `CONTROL_DELETE_DISPLAY`, `PAIRING_REJECTED_DISPLAY`, or `PHOTO_DISPLAY`. Control messages (ack/ready/reject) are themselves sent as legacy strings rather than `TYPE_CONTROL`.

**Impact:** A peer can make text be treated as a control action (pausing or deleting the session via a "rejection", deleting a message, an invalid media mapping). The peer is authenticated, so impact is limited, but this is a source of logic bugs.

**Remediation:** Return a typed result (`enum` + payload) from the engine instead of magic strings. Move ack/ready/reject to `TYPE_CONTROL`. Remove the legacy path.

---

### SA-22 (Low): Global `failedDecryptCarriers`

**Location:** [SecureChatEngine.java:58-65](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L58-L65), lines 1063-1067 and 1162-1164.

**Details:** There's one static LRU across all accounts and peers. Any decryption failure blocks the carrier until the process restarts, or until some group distribution arrives and calls `clearFailedDecryptCache`. That includes transient failures: a Keystore error, a message arriving before its session exists, or a race from SA-06.

**Remediation:** Cache only deterministic failures (`InvalidMessage` after the session loaded successfully), scope the cache by account/peer, and add a TTL.

---

### SA-23 (Low): File Hygiene in Media Crypto

**Location:** [SecureMediaCrypto.java:537-569](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureMediaCrypto.java#L537-L569).

**Details:** `requireSafeFile` canonicalizes the path but doesn't check that it's inside an allowed root. A canonical path always passes the parent check, so despite its name the function provides no traversal protection. The temp file `destination + ".tmp"` receives plaintext during decryption, and if the process dies it stays there until the cache is pruned.

**Remediation:** Pass an allowed root directory and check `startsWith(root)`. Delete `*.tmp` in the secure media directories on startup. Keep decrypted media in a dedicated subdirectory of `noBackupFilesDir`/`cacheDir`.

---

### SA-24 (Low): Backup Surface

**Location:** [AndroidManifest.xml:97-101](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/AndroidManifest.xml#L97-L101) (`allowBackup="true"`, `backupAgent=".BackupAgent"`), [BackupAgent.java](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/BackupAgent.java).

**Details:** The key/value agent covers only `saved_tokens`, but it doesn't override `onFullBackup`. The default implementation backs up the entire data directory for `adb backup` (Android ≤ 11) and device-to-device transfer. That includes the plaintext `telegram_secure_chat_state_v1` (SA-14) and the encrypted blobs. The blobs are useless without the Keystore key, and `ensureInstallationState` handles that case correctly.

**Remediation:** Add `fullBackupContent`/`dataExtractionRules` that exclude `telegram_secure_*` and the secure media directories, or override `onFullBackup`.

---

### SA-25 (Low): Supply Chain

**Location:** [SecureOverlay/build.gradle](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/build.gradle) (repository `build-artifacts.signal.org`, `libsignal-android`/`libsignal-client` 0.86.6). There's no `gradle/verification-metadata.xml`.

**Details:** The native crypto library is fetched with no checksum or signature verification. The jar is also repackaged with some classes excluded, which makes comparing it against the upstream artifact harder.

**Remediation:** Enable Gradle dependency verification (`--write-verification-metadata sha256`), at least for `org.signal:*`. Record the hash of the repackaged jar in the review artifacts.

---

### SA-26 (Low): Inconsistent Deletion Between Notifications and Chat

**Location:** [NotificationsController.java:1912-1914](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/NotificationsController.java#L1912-L1914) (`deleteMessages(..., true /* revoke */, ...)`) vs [ChatActivity.java:21430-21432](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L21430-L21432) (`false`).

**Details:** The same event (a delete-control, or a duplicate per SA-08) triggers a server-side "delete for everyone" from the notification path but only a local deletion from the open chat.

**Remediation:** Handle delete-control in one function in one layer (not the UI), with consistent semantics.

---

### SA-27 (High): "No Password" Backups Are Effectively Plaintext

**Location:** [SecureIdentityBackupCodec.java:50-52, 111-120, 397-407](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureIdentityBackupCodec.java#L50-L120) (`FLAG_NO_PASSWORD`, `NO_PASSWORD_KDF_INPUT = "Fork-Secure unprotected identity backup v1"`); the same pattern in `SecureHistoryBackupCodec.java:58-61`. UI: [ForkSecureSettingsActivity.java:756-800](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ForkSecureSettingsActivity.java#L756-L800) (empty password + empty confirmation → `confirmUnprotectedExport`), and the export goes to any SAF destination via `ACTION_CREATE_DOCUMENT` (lines 598-602, 646-654).

**Details:** With an empty password, the archive key is PBKDF2 over a constant string that ships in the APK. Anyone who has the file can decrypt it. The history archive (`.fsrk`) contains the identity private key, every outgoing/incoming display copy, every content record (including per-file media keys for ciphertext that still lives on Telegram servers), and the Saved Messages key. SAF destinations are often cloud-synced (Google Drive, OEM clouds, Downloads backed up by the vendor).

**Impact:** One leaked file means full compromise: impersonation via the identity key, all historical plaintext, and every media attachment still downloadable from Telegram. There's a warning dialog, but the option turns the entire E2E design into "trust your cloud drive".

**Remediation:** Remove unprotected export, or at least restrict it to the identity-only archive behind a second explicit confirmation. Never allow it for history. If convenience matters, offer a generated high-entropy recovery code (e.g. 24 words / 128-bit) instead of an empty password.

---

### SA-28 (Medium): Weak Backup Password Policy

**Location:** [ForkSecureSettingsActivity.java:764-766](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ForkSecureSettingsActivity.java#L764-L766) (`password.length >= 5`), [SecureIdentityBackupCodec.java:40, 268-303](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureIdentityBackupCodec.java#L268-L303) (hand-rolled PBKDF2-HMAC-SHA-256, 600 000 iterations), line 756 (`first.getText().toString().toCharArray()`).

**Details:** 600k PBKDF2 iterations match the OWASP floor, but PBKDF2 isn't memory-hard and parallelizes well on GPUs. A 5-character password (≈ 26⁵–62⁵ candidates) falls to offline brute force within minutes to hours. The archive is offline-attackable by design: the header and salt are public, and a failed tag is a perfect oracle. The `char[]` zeroization is undermined because the password is first materialized as an immutable `String` from the `EditText`.

**Impact:** A leaked archive (cloud sync, lost SD card, shared file) can be cracked for typical short passwords.

**Remediation:** Require at least 12 characters or a passphrase, with a strength meter (zxcvbn). Move to Argon2id (the container already has explicit KDF IDs). Prefer generated recovery codes. Use the platform `SecretKeyFactory("PBKDF2WithHmacSHA256")` or a vetted library instead of a custom loop. Read the password straight from the `Editable` into a `char[]`.

---

### SA-29 (Medium): Single Installation-Wide Identity Across Telegram Accounts

**Location:** [KeystoreSignalProtocolStore.java:42-70](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/KeystoreSignalProtocolStore.java#L42-L70) (records `identity` / `registration` are not account-scoped), [SecureChatEngine.java:1559-1569](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L1559-L1569) (`resetOwnIdentity` is installation-wide), [SecureHistoryBackupManager.java:30-47, 186-190](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureHistoryBackupManager.java#L30-L47) (`replaceSelected(..., PROTOCOL_ROOTS, HISTORY_PREFIXES, ...)` with unscoped prefixes).

**Details:** All Telegram accounts on the device share one Signal identity key and one registration ID. Only `localAddress` differs per account. Separately, a history restore for `targetAccount` deletes the protocol roots **and the display/content records of every account**, while the archive contains only one account's records (export is scoped to `account.`).

**Impact:** (1) Privacy: any peer, or the server watching pairing offers, can link two Telegram accounts to the same person by comparing identity keys/fingerprints. That defeats a common reason for running multiple accounts. (2) Data loss: restoring account A permanently erases account B's secure history. The identity backup's `ownerUserId` check is also misleading, since the identity being restored is shared by all accounts.

**Remediation:** Scope identity, registration, pre-keys, sessions, and the recovery store per account (prefix every root with `account/<n>/`). Restrict `replaceSelected` to `HISTORY_PREFIXES[i] + targetAccount + '.'`. Add a multi-account restore test.

---

### SA-30 (Medium): Link Guard Shows the Wrong Destination Host

**Location:** [SecureLinkGuard.java:141-167](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureLinkGuard.java#L141-L167) (manual host extraction), [SecureLinkGuard.java:28-29](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureLinkGuard.java#L28-L29) (`USER_INFO_PATTERN`). Displayed in [ChatActivity.java:40310-40328](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L40310-L40328) (`ForkSecureExternalLinkBody` shows `analysis.unicodeHost` as the destination).

**Details:** The analyzer finds the first `@` **before** cutting the path, query, or fragment. For `https://evil.example/login@paypal.com`, the real host is `evil.example`, but the analysis reports `host = paypal.com`. `USER_INFO_PATTERN` doesn't match (there's a `/` before `@`), so the link isn't flagged, and the "external link" dialog says it opens `paypal.com`. Backslashes aren't normalized either: browsers treat `\` as `/` for special schemes, so `https://evil.example\.paypal.com` and similar forms show misleading hosts. The real navigation then goes to `Uri.parse(url)`, which is a different parser.

**Impact:** The anti-spoofing feature itself gives the user a false, trusted-looking destination: phishing with a "security-verified" label.

**Remediation:** Parse with the same parser that will navigate (`Uri.parse` / `java.net.URI` with WHATWG-style normalization, `\` → `/`), and take the host from its authority component only. Reject or flag any URL whose parsed host differs from the naive host. Add negative tests for `@` in path/query/fragment, `\`, `%40`, and IPv6 literals.

---

### SA-31 (Medium, Needs Verification): Decrypted URLs May Reach Telegram via Instant View / In-App Browser

**Location:** [ChatActivity.java:40256-40266](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L40256-L40266) (`Browser.openUrl(..., allowIV = !forceNoIV, ...)`), also reached after both Fork-Secure link dialogs (lines 40288, 40328).

**Details:** Links from protected chats open through Telegram's standard `Browser.openUrl` with Instant View allowed and the in-app browser enabled. Upstream, these paths can call `messages.getWebPage` / `getWebPagePreview` or Telegram's IV/telegra.ph handling, which sends the URL to Telegram's servers. Fork-Secure suppresses link previews when sending, but the opening path hasn't been checked on a device.

**Impact:** If confirmed, the decrypted URL (often the most sensitive part of a message) leaks to the very server the overlay is meant to hide it from.

**Remediation:** For protected chats, force `forceNoIV = true` and open with an external browser/Custom Tab only, with no Telegram RPC. Verify with a network log (MTProto request tracing) that no `getWebPage*` request is sent.

---

### SA-32 (Low): Outbound Guard Keyed on the `TGS1:` Prefix

**Location:** [SendMessagesHelper.java:6815-6816](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java#L6815-L6816) (`forkSecureCarrier = isMarked(message) || isMarked(caption)`), [SendMessagesHelper.java:6858](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java#L6858) (`if (!forkSecureCarrier && isForkSecureProtectedPeer(peer))`).

**Details:** Any outbound text that merely starts with `TGS1:` is treated as an already-encrypted carrier and skips the protected-chat guard. Typed, pasted, or shared text (e.g. from another app's share intent, a bot keyboard, or a draft) beginning with the marker goes to Telegram as plaintext. Forwarding non-carrier messages into a protected chat is also allowed and sent as a normal plaintext forward, while the chat UI still says protected.

**Impact:** A guard bypass that depends on content, not provenance. It needs the plaintext to start with the marker, so the practical impact is limited.

**Remediation:** Mark carriers by provenance (a flag on `SendMessageParams` set only by `SecureChatEngine` callers), not by prefix. When the destination is protected, reject or require confirmation for forwards of plaintext messages.

---

### SA-33 (Low): Minor Link-Analyzer Gaps

**Location:** [SecureLinkGuard.java:163-166, 198-204, 249-253](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureLinkGuard.java#L163-L253); copy-safe-link in [ChatActivity.java:40292-40294](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L40292-L40294).

**Details:** `canonicalDisplayUrl` and "copy safe link" call `replace(rawHost, ...)` on the original URL, but `rawHost` is lowercased, so mixed-case hosts aren't replaced and the "safe" copy keeps the original form. The first `:` truncates IPv6 literals (`[::1]` → `[`). Confusable detection only matches the exact skeleton of 17 hard-coded domains, and the map covers a small subset of Unicode confusables. Every Punycode host gets flagged, which mitigates this somewhat.

**Remediation:** Rebuild URLs from parsed components instead of string replacement. Use ICU `SpoofChecker` (available on Android API 29+ via `android.icu`) or the full Unicode confusables data. Handle bracketed IPv6.

---

### SA-34 (Medium): Decrypted Previews in the Unprotected Chat List

**Location:** [DialogCell.java:1336-1340, 3003-3015](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/Cells/DialogCell.java#L3003-L3015) (`applyForkSecureDialogPreview`, `forkSecurePreviewCache`), [SecureChatEngine.java:1177-1230](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L1177-L1230) (`resolveDialogPreview` returns `PLAINTEXT` with the decrypted text). Compare [ChatActivity.java:8821-8827](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L8821-L8827): `FlagSecureReason` is applied only inside a protected chat. `SecureContentSettings.isScreenProtectionEnabled` isn't consulted for the dialog list.

**Details:** The main chat list renders the last decrypted secure message of every protected dialog, while the window is not `FLAG_SECURE`. Screenshots, screen recording, casting, the Recents/task-switcher thumbnail, and OEM "smart capture" features all see the plaintext. The preview path can also decrypt (not cache-only) from the list, which advances the ratchet outside the chat screen (see SA-06).

**Impact:** The screen-protection setting (on by default) gives a false sense of coverage: the same plaintext it hides in the chat is exposed one screen up.

**Remediation:** When screen protection is on and any visible dialog is protected, apply `FLAG_SECURE` to the dialogs screen. Alternatively, show a generic "🔒 Secure message" preview by default (with an opt-in for previews), and keep list previews cache-only.

---

### SA-35 (Info): Plaintext Allowed in `WAITING`/`PAUSED` Modes

**Location:** [SendMessagesHelper.java:2745-2770](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java#L2745-L2770) (`isForkSecureProtectedPeer` is true only for `PROTECTED`, `IDENTITY_CHANGED`, `RECOVERY_CHANGED`).

**Details:** After the user starts pairing (`WAITING`), or after a pause/rejection (`PAUSED`), ordinary sends go out as plaintext. That's a deliberate design choice, but a user who just tapped "secure" can easily assume the following messages are protected. Note that the guard **fails closed** on engine errors, and it encrypts or blocks notification/wear replies (`WearReplyReceiver` → central guard). Both are positive.

**Recommendation:** In `WAITING`/`PAUSED`, show an explicit "not encrypted yet" banner in the composer, or require per-message confirmation for plaintext. Add a UI test for this.

---

## Re-verification After Remediation (2026-11-01, in progress)

Between 2026-10-28 and 2026-10-31 the code changed substantially (new `SecureSessionManager`, `SecureNameMask`, per-account stores, `verification-metadata.xml`, backup-exclusion XML files, and many new `*JvmTest` classes). Findings above describe the code as first reviewed. This section records, step by step, what I re-checked in the **current** source. "Verified" means I read the code path; I have **not** run the new tests or tried the app on a device.

### Status of earlier findings (partial, updated as I go)

| ID | Status | Evidence in current code |
| --- | --- | --- |
| SA-01 | Fixed (verified) | `createGroupSenderKeyDistributionCarrier` now needs a paired, non-paused 1:1 peer (`peerUserId > 0`) and wraps the distribution in `SecureContentCodec.encodeSenderKeyDistribution` encrypted through the pairwise session (`SecureChatEngine.java:229-265`). Groups are also off by default: `SecureSessionManager.GROUPS_ENABLED = false`, and the engine constructor throws for `peerUserId < 0`. |
| SA-02 | Fixed (verified) | `processGroupSenderKeyDistributionCarrier` always throws (`:268-271`); a distribution is only processed from a decrypted 1:1 payload where `senderUserId == peerUserId` (`:1240-1252`). `TYPE_SENDERKEY_DISTRIBUTION` carriers are rejected in decrypt and preview paths. |
| SA-03 | Fixed (verified, engine + UI) | Initial offers are staged as `PendingKind.INITIAL_OFFER` and return `INITIAL_OFFER_PENDING`; `canAutoAcceptPairingOffer()` returns `false` (`SecureChatEngine.java:431-440, 497-500`). The chat shows a dialog with both fingerprints and the instruction to compare them "through another trusted channel"; only **ForkSecureVerifyAccept** calls `acceptPendingIdentity()` and sends the ack (`ChatActivity.java:23758-23800`); `/secure-reject` sends a rejection. Residual: acceptance is still one tap, and the app keeps no "verified vs. unverified" distinction afterwards. |
| SA-04 | Fixed (verified: text, attachments, stickers) | `requireValidInboundSender` rejects `senderUserId != peerUserId` in 1:1 chats, and decrypt always uses `peerAddress` in 1:1 for text, attachment and sticker manifests (`SecureChatEngine.java:565-580, 903-917, 1144, 1174-1176, 1769-1776`). See residual risk SA-37. |
| SA-05 | Fixed (verified) | `rollbackTextEdit` and `rollbackAttachmentEdit` are now deprecated no-ops; an edit carrier's message key is treated as consumed once created (`SecureChatEngine.java:770-780`). The UI callers still invoke them, which is harmless. |
| SA-06 | Fixed (verified) | `encryptAndRemember`, the edit/attachment encrypt paths, decrypt, pairing, group distribution, and `resetOwnIdentity` all take the same `SESSION_LOCK` (= `KeystoreSignalProtocolStore.PROTOCOL_STATE_LOCK`, lines 552, 633, 681, 1036, 1128, 1706). |
| SA-07 | Mostly fixed (verified); residual remains | `isTrustedIdentity` returns true for an unknown identity only for `Direction.RECEIVING` and a peer in `WAITING` state; `requireInboundSessionAllowed` rejects unsolicited messages (`KeystoreSignalProtocolStore.java:417-427`, `SecureChatEngine.java:1732-1748`). Residual: see SA-37. |
| SA-08 | Fixed in engine (verified); UI not re-read | `DuplicateMessageException` now returns `DUPLICATE_MESSAGE_DISPLAY` and no longer calls `forgetByDigest` (`:1268-1273`). Need to confirm `ChatActivity`/`NotificationsController` no longer delete on it. |
| SA-09 | Not yet re-checked | |
| SA-10 | Partly fixed (verified) | New v3 "participant-bound" offers carry `ownerUserId`/`recipientUserId` inside the signed body, and `decodeOffer` now accepts only v2 and v3 (legacy v1 dropped). Senders pass the owner/recipient IDs (`ChatActivityEnterView.java:7960`, `ChatActivity.java:21484-21491`). Residual: v2 offers are still accepted and are unbound (SA-37). |
| SA-19 | Partly fixed | `SecureSessionManager` exists, groups sit behind a flag, and constructors call `ensureInitialized()` once per account. But 28 direct `new SecureChatEngine(...)` calls remain in `TMessagesProj` (SendMessagesHelper ×10, ChatActivity ×6, and others), so the manager is not the single owner yet (SA-38). |
| SA-21 | Partly fixed (verified) | Legacy unversioned plaintext is rejected (`:1256-1257`); user text beginning with the display sentinel gets a leading space (`:1190-1192`). Ack/ready/reject are now `TYPE_CONTROL` actions. Sentinel strings are still used as the engine→UI interface. |
| SA-22 | Mostly fixed (verified) | The failed-decrypt cache is keyed by account/peer, has a 10-minute TTL, and only caches `InvalidMessage`, `InvalidKeyId`, `UntrustedIdentity` failures. New issue: SA-36. |
| SA-24 | **Not effectively fixed (verified)** | `allowBackup="true"` now points to `full_backup_content.xml` and `data_extraction_rules.xml`, but they exclude the **wrong file names**: `telegram_secure_overlay_state.xml` and `telegram_secure_database.db`. The real names are `telegram_secure_overlay_state_v1.xml` (legacy source) and the new SQLite store `telegram_secure_overlay_v2.db` (`KeystoreEncryptedBlobStore.java:37-39`) with its `-wal`/`-shm`/`-journal` files. Only `telegram_secure_chat_state_v1.xml` is named correctly. See SA-42. |
| SA-25 | Partly fixed (verified) | `gradle/verification-metadata.xml` pins `org.signal:libsignal-android:0.86.6` (aar, pom, module). However its `<trusted-artifacts>` rule `^(?!org\.signal($|\b)).*$` (regex) trusts **every other group without checksums**, so verification covers only `org.signal`. I did not check whether `libsignal-client` (the artifact repackaged in `SecureOverlay/build.gradle`) has its own checksum entry. |
| SA-14 | Partly fixed (verified) | `SecureNameMask` derives HMAC-SHA-256 record names for peer IDs and carrier digests, with the key stored in the encrypted store. I haven't checked that every call site uses it, or that migrated legacy records were re-keyed. Two new problems in the same area: SA-40, SA-41. |
| SA-16 | Partly fixed, but regressed (verified) | `KeystoreEncryptedBlobStore` now uses an indexed SQLite table with real multi-statement transactions (`putAll`, `replaceRoots`, …), which resolves the O(n) rewrite and the cross-record atomicity problem. But its constructor swallows all initialization errors and falls back to a non-persistent in-memory map: see SA-39. |
| SA-29 | Fixed (verified) | Protocol stores, recovery store, identity epoch and `resetOwnIdentity` are all per account. History restore now deletes only `account/<n>` roots and the target account's history prefixes (`HISTORY_PREFIXES[i] + targetAccount + '.'`); account 0 additionally owns the legacy unprefixed roots (`SecureHistoryBackupManager.java:195-210, 261-265`). One account-scoping bug remains in the engine: SA-45. |
| SA-11 | Fixed (verified) | `resolveForkSecureNotificationText` no longer decrypts or advances the ratchet. It only reads the cache (`getIncomingText`/`getOutgoingText`) and always shows the generic `ForkSecureReplyPreview` string; group distributions are no longer processed there; forwarded and Saved Messages carriers get generic text (`NotificationsController.java:1861-1915`). |
| SA-12 | Fixed (verified) | `IME_FLAG_NO_PERSONALIZED_LEARNING` is now set when `encryptedChat != null` **or** `parentFragment.isForkSecureContentProtected()` (`ChatActivityEnterView.java:5691-5695`). |
| SA-13 | Fixed for the cited line (verified) | The `FileLog.d("ForkPinned: … " + pinnedText)` call is gone. I did not re-audit every other `FileLog` call. |
| SA-26 | Fixed (verified) | The notification path no longer deletes messages at all (a delete-control just returns `null`); the chat path calls `getMessagesController().applyForkSecureControlDelete(...)`. |
| SA-08 | Fixed (verified, engine + chat UI) | In addition to the engine change above, `ChatActivity` now treats `DUPLICATE_MESSAGE_DISPLAY` as a non-destructive status row (`ChatActivity.java:21376-21378, 21413`), while real delete-controls go through `applyForkSecureControlDelete` with the digests. |
| SA-27 | Fixed at codec level (verified); UI not re-read | `encodePassword` in both backup codecs now rejects empty/weak passwords (`SecureIdentityBackupCodec.java:425-433`), so an unprotected archive can no longer be produced. The `FLAG_NO_PASSWORD` flag is still parsed. Side effect: SA-43. |
| SA-28 | Partly fixed (verified) | Minimum is now 12 characters (`MIN_PASSWORD_CHARS`) plus an "entropy" check; the UI reads the password with `Editable.getChars` instead of going through a `String` (`ForkSecureSettingsActivity.java:788`). KDF is still hand-rolled PBKDF2-HMAC-SHA-256, 600k iterations, no Argon2id. The "entropy" check is weak (SA-43). |
| SA-31 | Fixed (verified) | `processExternalUrl` forces `forceNoIV = true` for protected chats and skips `requestUrlAuth`, so Instant View / `getWebPage` / url-auth RPCs aren't triggered from secure links (`ChatActivity.java:40263-40290`). Not tested on a device. |
| SA-34 | Fixed by a different approach (verified) | `DialogCell.formatForkSecureDialogPreview` shows the generic `ForkSecureReplyPreview` text for plaintext previews while screen protection is enabled (the default). When the user turns screen protection off, previews show decrypted text again, which matches the setting's meaning. `DialogsActivity` still has no `FLAG_SECURE`. |
| SA-18 | Fixed (verified at design level) | `SecureContentCodec` pads the inner plaintext to 160-byte blocks (`PADDING_BLOCK_SIZE`, lines 28, 559-561) with a padding delimiter checked on decode (511-518), and media uses Padmé sizing (`SecureMediaCrypto.padmeSize`, `SecureContentCodec.java:963-967`). I haven't yet reviewed the padding code paths in detail. |
| SA-09 | Fixed (verified) | Signed and Kyber pre-keys rotate after 7 days; retired ones are kept for a 30-day sunset window (`PREKEY_SUNSET_GRACE_PERIOD_MS`, measured from creation time, so at least 23 days remain after retirement) and then pruned by `pruneExpiredPreKeys`; one-time pre-keys come from a `prekey_pool` that is popped on publication and removed on use (`KeystoreSignalProtocolStore.java:260-360, 612-619`). |
| SA-15 | Fixed (verified) | `MediaDataController.indexForkSecureMedia` no longer serializes the message into `media_v4`; it only deletes any existing rows for the message, so no secure media/link classification is written to Telegram's SQLite (`MediaDataController.java:4193-4210`). Callers still exist but have no effect. |
| SA-20 | Mostly fixed (verified) | Saved Messages records use a new `MAGIC_V2` with AAD = magic ‖ generation ‖ kind ‖ account ‖ recordId (`SecureSavedMessageCrypto.buildAad`), and text vs. media kind is now chosen correctly. Residual: `recordId` is random and not tied to the Telegram message ID, so the server can still swap in an older valid record for the same message (edit rollback) or duplicate it. |
| SA-23 | Partly fixed (verified) | `SecureSessionManager.ensureInitialized` now purges stray `*.tmp` files at startup in the secure cache directories, and `requireSafeFile(File, File allowedRoot, String)` exists. But all call sites still use the two-argument overload, which passes `null` as the root, so the path-confinement check is still ineffective (`SecureMediaCrypto.java:757-793`, calls at 152, 267, 432, 559, 822). |
| SA-32 | Fixed (verified) | The guard now keys on `SendMessageParams.forkSecureProvenance` (set only by Fork-Secure code, 8 uses) instead of the `TGS1:` prefix. When set, the carrier is decoded and validated (type, direction); ordinary text that happens to start with `TGS1:` goes through the normal protected-chat encryption path (`SendMessagesHelper.java:6799-6812`). |
| SA-30 | Fixed (verified by tracing) | The host now comes from the authority only (cut at the first `/`, `\`, `?` or `#`, taking the **last** `@` inside it), with bracketed IPv6 handled, and it is cross-checked against `java.net.URI.getHost()` (`SecureLinkGuard.java:146-237`). `https://evil.example/login@paypal.com` now reports host `evil.example` and is flagged by `PATH_EMBEDDED_DOMAIN_AT_PATTERN`; `\` delimiters and encoded user-info are flagged too. Minor: the path-`@domain.tld` rule will also warn on benign URLs such as Mastodon-style `/@user@example.com` (acceptable false positive). |
| SA-33 | Fixed (verified) | `canonicalDisplayUrl` is now built positionally from the host's absolute offsets rather than `String.replace` (`:310-323`), IPv6 is handled, and confusable detection also uses an ICU `SpoofChecker` via reflection (`isIcuSpoof`). I did not re-read the copy-safe-link helper that follows. |
| SA-17 | Fixed for new attachments (verified by reading); legacy path unchanged | Attachments are now encrypted in 64 KiB AES-GCM segments (`SEGMENT_SIZE`). Each segment uses nonce = `baseNonce[0..7) ‖ segmentIndex(4) ‖ isLast(1)` and AAD = `prefix ‖ photoFlag ‖ segmentIndex ‖ isLast` (`SecureMediaCrypto.java:81-96`), so reordering, truncation and extension all fail authentication; the whole-ciphertext SHA-256 from the manifest is still checked first, and Conscrypt now buffers at most one segment. The old single-shot GCM path (`decryptLegacy`) remains for earlier files and still buffers the entire file. Found one format ambiguity: SA-44. |
| SA-35 | Mostly fixed (verified) | The composer hint now says "⚠️ Messages are unencrypted until pairing completes" in `WAITING` and "⚠️ Secure messaging paused — sending in plaintext" in `PAUSED` (`ChatActivity.java:23634-23649`). Gap: in the new `INITIAL_PAIRING_PENDING` mode the hint is cleared (`setOverrideHint(null)`) and plaintext still goes out (SA-46). |
| SA-40 | Confirmed, but order-dependent (verified) | Every record-name helper (`SecureLocalTextStore.keyByDigest`, `SecureLocalContentStore.keyByDigest`, used by history export/restore) calls `SecureNameMask.getOrGenerateKey((Context) null)`. Store constructors (`SecureChatState`, `SecureLocalTextStore`, `SecureLocalContentStore`, `SecureMediaIndex`, `SecureLocalMessageCache`) load the real key first, so normal flows work. Any static path that runs before one of those constructors in a fresh process gets the sticky all-zero key. |
| Others | Not yet re-checked | None of the original findings remain unchecked. Device-level confirmation is still open for SA-17, SA-31 and SA-34. |

### New findings from the re-verification

#### SA-36 (Low): Failed-decrypt cache key uses a 32-bit `String.hashCode()` of the carrier

**Location:** [SecureChatEngine.java:77-79](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L77-L79) (`account + ":" + peerUserId + ":" + carrier.hashCode()`), used at lines 1155-1165 and 1280-1283.

**Details:** The cache identifies a carrier by `String.hashCode()`. A malicious or compromised peer or the server can craft a garbage carrier whose hash equals a legitimate carrier's hash (Java string hashes are trivial to collide), get it to fail, and thereby make the legitimate message fail with "previously failed" for the 10-minute TTL.

**Impact:** Targeted, short-lived message suppression/DoS. Low severity because it needs attacker-controlled carriers in the same chat and expires.

**Remediation:** Key the cache by the SHA-256 digest of the carrier (the code already computes carrier digests elsewhere).

#### SA-37 (Medium, Residual): Binding checks are skipped when the sender or offer owner is unknown

**Location:** [SecureChatEngine.java:444-468](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L444-L468) (`requireValidOfferBinding` only checks `if (offer.ownerUserId > 0)` / `if (offer.recipientUserId > 0)`), [SecureChatEngine.java:1769-1776](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L1769-L1776) (`requireValidInboundSender` skips the 1:1 check when `senderUserId == 0`), `SecurePreKeyBundleCodec` (v2 still accepted).

**Details:** (1) A v2 offer (no owner/recipient fields) passes the binding check by construction. The server can't forge a v2 offer, but it can replay any genuine v2 offer ever published by an older client into a different chat, and the new check never fires. (2) Every caller that still passes `senderUserId = 0` (the overloads `decryptText(carrier)`, `decryptAttachmentManifest(carrier)`, `receivePairingOffer(carrier, id)`, `resolveDialogPreview(..)` defaults) bypasses the sender/peer comparison. For 1:1 chats the session address is still `peerAddress`, so message keys remain bound to the right session. The remaining exposure is the offer binding, and any new code path that forgets to pass the sender.

**Impact:** The SA-04/SA-10 protections are opt-in per call site rather than enforced by the API, which makes silent regressions likely.

**Remediation:** Remove the overloads without a sender and require `senderUserId`/`localUserId` (or an explicit `UNKNOWN` marker that fails closed for incoming network messages). Reject v2 offers once clients have migrated to v3. Add a lint/test that grep-fails on `decryptText(` calls with one argument in `TMessagesProj`.

#### SA-38 (Low, Architecture): `SecureSessionManager` is not the single entry point yet

**Location:** `new SecureChatEngine(` appears 28 times in `TMessagesProj/src/main/java` (e.g. [SendMessagesHelper.java:2452, 2554, 2627, 2735, 2819, 3053, 3213, 3399, 3485, 3560](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java), [ChatActivity.java:14676, 14804, 21202, 21230, 21984, 22213](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java), [DialogCell.java:3113](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/Cells/DialogCell.java#L3113), [NotificationsController.java:1894](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/NotificationsController.java#L1894)). `SecureChatEngine.get(...)` (which goes through the manager) is used instead of `new` nowhere in this list.

**Details:** The manager caches engines per peer, but call sites bypass it. Since each engine captures `identityEpoch` at construction and calls `requireCurrentIdentity()`, a cached engine would also go stale after an identity reset, so the manager's `clear()` has to be wired to `resetOwnIdentity` before adoption.

**Remediation:** Replace constructor calls with `SecureChatEngine.get(...)`, invalidate the cache on identity reset/restore, and make the constructor package-private.

#### SA-39 (High, Regression): Secure state store silently falls back to a volatile in-memory map

**Location:** [KeystoreEncryptedBlobStore.java:79-107](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/KeystoreEncryptedBlobStore.java#L79-L107) (the constructor's `catch (Exception e) { helper = null; prefs = null; }`, commented "In headless JVM unit tests…"), and the `testStorage` fallback branch in every method (e.g. `put` at line 152, `putAll` at 182, `get` at 546, `contains` at 566, `delete` at 596).

**Details:** The constructor wraps `getSharedPreferences`, `new DatabaseHelper`, **`ensureInstallationState`** and `migrateLegacyPreferences` in one catch-all. If any of them throws in production (SQLite open failure on a full or corrupted disk, sentinel file creation failure, Keystore inspection failure, migration error), `dbHelper` becomes `null` and every later operation silently reads and writes `testStorage`. That map is an **instance** field (`private final Map ... testStorage = new ConcurrentHashMap<>()`), so each `new KeystoreEncryptedBlobStore(context)` gets its own empty map. The previous version of this class threw `IllegalStateException` in the same cases (fail-closed).

**Impact:** After a transient storage error, the app keeps running with no persistence and no error: a fresh identity is generated per store instance, sessions and pre-keys are never saved or shared between components, message keys can be consumed without the ratchet state being kept, and everything disappears on process death. The user would see arbitrary decrypt failures, identity changes for peers, or a silently non-protected setup. That's both a security regression (lost/forked ratchet state, key material only in RAM) and a data-loss risk.

**Remediation:** Remove the production fallback. Test-only storage should be injected through the `EncryptedStateStorage` interface (which already exists), not selected by catching exceptions. In the constructor, let initialization errors propagate (fail closed), and surface a clear "secure storage unavailable" state to the UI.

#### SA-40 (Medium): `SecureNameMask.getOrGenerateKey(null)` caches an all-zero key

**Location:** [SecureNameMask.java:54-66](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureNameMask.java#L54-L66).

**Details:** With a `null` context, the method stores `new byte[KEY_LEN]` (32 zero bytes) in the static `cachedKey` and returns it. Every later call, including those with a real context, hits the early `cachedKey != null` return and keeps using the zero key until the process restarts. The same fallback also kicks in indirectly through SA-39 (a store whose `put` goes to the throwaway map would generate a key that is then lost).

**Impact:** Record names become an unkeyed HMAC-SHA-256 with a public key, so anyone with the database can recompute `peer:<account>:<id>` and `carrier:…:<digest>` names and confirm which peers and carriers exist: exactly the metadata leak SA-14 tried to close. Because the zero key is sticky, the stored names would also be inconsistent with names written before and after a restart.

**Remediation:** Throw on `null` context instead of generating a key. Never cache a key that isn't persisted. Keep `setCachedKeyForTesting` in test code only.

#### SA-41 (Low): Legacy preferences are wiped before the SQLite transaction commits

**Location:** [KeystoreEncryptedBlobStore.java:110-133](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/KeystoreEncryptedBlobStore.java#L110-L133) (`migrateLegacyPreferences`).

**Details:** `db.setTransactionSuccessful()` is followed immediately by `prefs.edit().clear().commit()`, but the SQLite transaction only commits at `db.endTransaction()` in the `finally` block. A crash or kill between those two statements deletes the legacy SharedPreferences (the only copy) while the SQL transaction is rolled back. The migrated blobs include the identity key, registration ID, sessions and pre-keys. Also, the catch-all in the constructor (SA-39) would swallow a migration exception and continue.

**Impact:** Rare but permanent loss of all protocol state on upgrade.

**Remediation:** Commit the transaction first (`endTransaction()`), verify the rows, and only then clear the legacy preferences. Make the migration idempotent so it can be re-run safely.

#### SA-42 (Medium, Regression): Backup exclusions reference files that no longer exist

**Location:** [full_backup_content.xml](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/res/xml/full_backup_content.xml), [data_extraction_rules.xml](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/res/xml/data_extraction_rules.xml) (`cloud-backup` and `device-transfer`) vs [KeystoreEncryptedBlobStore.java:37-39](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/KeystoreEncryptedBlobStore.java#L37-L39).

**Details:** The rules exclude `sharedpref/telegram_secure_overlay_state.xml` and `database/telegram_secure_database.db*`. The code actually uses `telegram_secure_overlay_state_v1.xml` and `telegram_secure_overlay_v2.db`. Neither the real database nor its `-wal`/`-shm`/`-journal` siblings is excluded. `fork_secure_content_settings` and `fork_secure_saved_messages` preferences aren't excluded either. The `file` domain entries are mostly irrelevant (`fork-secure-*` directories live under `cacheDir`/`noBackupFilesDir`, which aren't backed up anyway).

**Impact:** The whole secure database (Keystore-encrypted values with HMAC-masked names, but still the key sizes, counts and timestamps) is included in cloud backup and device-to-device transfer. The values are useless without the non-exportable Keystore key, and `ensureInstallationState` correctly discards state restored without its key. So the direct confidentiality impact is limited, but the mismatch means the protection the team believes it has isn't there.

**Remediation:** Exclude `telegram_secure_overlay_v2.db`, `-wal`, `-shm`, `-journal`, and the `_v1.xml` legacy file. Add an instrumentation or unit test that derives the file names from the constants in the store classes and asserts they appear in both XML files, so renames can't silently break this again.

#### SA-43 (Medium): Password policy also blocks restoring older backups, and the strength rule is trivial

**Location:** [SecureIdentityBackupCodec.java:142-146, 395-433](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureIdentityBackupCodec.java#L395-L433) (`decrypt` calls the same `encodePassword`, which throws unless `isStrongPassword`), `MIN_DISTINCT_PASSWORD_CHARS = 4` (line 48); the same shared policy in `SecureHistoryBackupCodec.java:58, 548-554`.

**Details:** (1) `decrypt` derives the key through the same `encodePassword` used for export, so it applies the new 12-character/entropy policy to passwords entered for **existing** archives. Archives made by earlier builds with a 5 to 11 character password, and "no password" archives (empty password), now fail with `IllegalArgumentException` before the KDF runs, even though the user knows the right password. `parseContainer` still recognizes `FLAG_NO_PASSWORD`, but `decrypt` no longer has a branch for it. (2) The "sufficient entropy" check only counts distinct non-whitespace characters (≥ 4), so `"123412341234"` or `"abcdabcdabcd"` pass; the guarantee is much weaker than the message suggests.

**Impact:** Users can be locked out of their own recovery archives after updating (a recovery-path availability failure, which in this product means permanently losing secure history), while the policy still accepts guessable passwords.

**Remediation:** Enforce the policy only when **creating** an archive; on decrypt accept any non-empty password (and keep the empty-password path for legacy `FLAG_NO_PASSWORD` archives, import-only). Replace the distinct-character rule with a real estimator (zxcvbn-style) or a generated passphrase/recovery code. Keep a test that restores archives produced by previous formats.

#### SA-44 (Low): Segmented vs legacy ciphertext sizes collide for single-segment attachments

**Location:** [SecureMediaCrypto.java:576-590](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureMediaCrypto.java#L576-L590) (`isSegmented` is tested by size equality, then `isLegacy`), and `calculateSegmentedCiphertextSize` (lines 65-79).

**Details:** The code decides the format from sizes only. For one segment, `segmentedSize = padded + 1×16` equals `legacyPaddedCiphertextSize = padded + 16`, so for any attachment whose padded plaintext is ≤ 64 KiB, `isSegmented` is true and the segmented nonce/AAD are used. A file produced by the older single-shot padded format with that size has different nonce and AAD and will fail with "authentication failed". No format-version byte exists in the manifest to disambiguate. This isn't an attack (the manifest is authenticated by the Signal message); it's a compatibility hole that would show up as unexplained media failures.

**Remediation:** Add an explicit format/version field to the attachment manifest (or try the legacy construction as a fallback only for the colliding size), and add a test that decrypts a stored legacy sample ≤ 64 KiB.

#### SA-45 (Medium): `isStale()` uses the wrong account's identity epoch

**Location:** [SecureChatEngine.java:202](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L202) (`identityEpoch = state.getIdentityEpoch(account)`) vs [SecureChatEngine.java:507-509](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L507-L509) (`return identityEpoch != state.getIdentityEpoch();`). `SecureChatState.getIdentityEpoch()` is `getIdentityEpoch(0)` (`SecureChatState.java:358-360`).

**Details:** The engine captures its own account's epoch but compares it with account 0's. `requireCurrentIdentity()` (used by `createPairingOffer`, `receivePairingOffer`, `acceptPendingIdentity`, `createPairingRejection`, `resumeIfPaused`, `getOwnFingerprint`, …) throws when they differ. Consequences for any account `n ≥ 1`:
- Once account `n` or account 0 has reset its identity a different number of times, every engine for account `n` is "stale": pairing, accepting a contact, rejecting, and showing fingerprints all fail with "secure identity was reset; recreate chat engine", and recreating doesn't help.
- When the epochs happen to match, an identity reset of account `n` doesn't bump account 0's epoch, so a long-lived engine for account `n` (e.g. cached by `SecureSessionManager`) isn't marked stale and keeps the old `IdentityKeyPair` it loaded at construction. It could then sign offers or show a fingerprint for an identity that no longer exists.
- Resetting account 0 marks every other account's engines stale.

The multi-account work (SA-29) made this path reachable; with a single account it's invisible, which is probably why tests didn't catch it.

**Impact:** Multi-account users can be locked out of secure pairing, or operate briefly on a destroyed identity after a reset. Mostly availability, with an identity-confusion edge case.

**Remediation:** `return identityEpoch != state.getIdentityEpoch(account);`. Mark `getIdentityEpoch()` without an account `@Deprecated` (or remove it), and add a JVM test that resets account 1 and checks staleness for accounts 0 and 1.

#### SA-46 (Low): No "unencrypted" warning while an initial offer is pending

**Location:** [ChatActivity.java:23650-23657](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L23650-L23657) (`INITIAL_PAIRING_PENDING` → `setOverrideHint(null, true)`), [SendMessagesHelper.java:2745-2770](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java#L2745-L2770) (guard is true only for `PROTECTED`, `IDENTITY_CHANGED`, `RECOVERY_CHANGED`), [ChatActivityEnterView.java:7905-7925](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/Components/ChatActivityEnterView.java#L7905-L7925).

**Details:** After a contact's offer arrives (and before the user accepts it), ordinary text is sent as plaintext, which is consistent with "not paired yet". Unlike `WAITING` and `PAUSED`, though, the composer shows no warning, and the header shows a lock icon with "initial offer pending". A user who sees a lock and a pending secure setup may reasonably assume their reply is protected.

**Remediation:** Show the same "⚠️ Messages are unencrypted until pairing completes" hint in `INITIAL_PAIRING_PENDING`, or block plaintext until the user accepts or rejects the offer.

---

## Positive Observations

- Strict, well-structured parsers: canonical base64url check in `SecureCarrierCodec.decode`; length checks and `size == remaining` in `SecureContentCodec`, `SecurePreKeyBundleCodec`, and the contact/sticker/attachment codecs.
- `KeystoreEncryptedBlobStore`: non-exportable AES-256-GCM Keystore key, record name bound as AAD, `setUnlockedDeviceRequired(true)`, synchronous `commit()`, and correct handling of state restored without its Keystore key.
- PQXDH (Kyber-1024) in the pre-key bundle; v2 offer signature with domain separation.
- Media: random per-file key and nonce; ciphertext SHA-256 checked before decryption; plaintext size bounded by the manifest; atomic `rename` of the output.
- Outbound guard in `SendMessagesHelper` against uploading a plaintext path (`SendMessagesHelper.java:9382-9387`).
- No committed credentials: `local.properties`, `signing.properties`, and `keystore/` are in `.gitignore`; signing secrets are read from properties.
- Backups (password-protected mode): the whole container header (KDF ID, iterations, salt, nonce, length) is GCM AAD; KDF parameters are pinned, so they can't be downgraded; canonical TLV parsing with bounds; owner-user check; key material zeroized after use.
- Backups never restore live ratchet sessions (`SecureHistoryBackupCodec` docs and `replaceIdentityForRecovery` drop `session`/`sender`). Restored chats stay paused until re-verification, and each restore gets a fresh recovery generation and UUID, so peers see `RECOVERY_CHANGE_PENDING` and clones/rollbacks are rejected by `SecureRecoveryGenerationStore`. This correctly avoids message-key reuse after restore.
- Identity import is two-phase (prepare → confirm → commit) with a Keystore-encrypted staging marker and crash resumption.
- The central outbound guard fails closed on engine/storage errors and encrypts or blocks replies sent from notifications and wearables. Protected chats suppress cloud drafts and link-preview discovery. Screen protection is on by default, and when it's on, `PhotoViewer` disables save/share/forward.

## Pending Review

- Remaining edge paths in `SendMessagesHelper`: quick replies, inline bots, Web App `sendData`, business auto-replies in protected chats.
- Export of decrypted media through `FileProvider` / "Open with" when screen protection is **off**.
- On-device confirmation of SA-17 (Conscrypt buffering), SA-31 (Instant View RPC), and SA-34 (recents thumbnail).

## Prioritized Remediation Plan

1. **Immediately:** fix SA-39 (the in-memory storage fallback is a new regression and can silently destroy protocol state), correct the backup exclusions (SA-42), and keep groups disabled until re-reviewed (SA-01, SA-02, SA-19; the engine-level fixes look good, see re-verification).
2. **Before any beta:** SA-03 + SA-07 (explicit trust; `isTrustedIdentity` allow-list), SA-04 (sender binding + AD), SA-05 + SA-06 (single lock, no rollback after send), SA-27 (remove unprotected backups).
3. **Next:** SA-11, SA-12, SA-13, SA-31, SA-34 (plaintext/URLs leaving the process or screen), SA-30 (link guard host parsing), SA-08 / SA-26 (non-destructive duplicate handling), SA-28 (password policy / Argon2id).
4. **Architecture:** SA-16 (transactional DB), SA-29 (per-account identity), SA-14 / SA-15 (metadata), SA-17 (segmented AEAD), SA-18 (padding), SA-09 / SA-10.
5. **Hygiene:** SA-20 through SA-25, SA-32, SA-33.
