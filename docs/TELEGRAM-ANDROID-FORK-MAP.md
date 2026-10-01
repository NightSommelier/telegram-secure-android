# Telegram Android Fork-Secure: Code Map

> [!NOTE]
> [Українська версія документації доступна у файлі TELEGRAM-ANDROID-FORK-MAP_UK.md](TELEGRAM-ANDROID-FORK-MAP_UK.md).

This document serves as the developer navigation map for the `telegram-secure-android/` product codebase. Native Telegram Secret Chats, channels, and groups remain standard Telegram. Fork-Secure operates exclusively within verified 1:1 cloud chats and a dedicated protected Saved Messages mode.

---

## 1. Repository Directory Map

```text
telegram-secure-android/
├── TMessagesProj/                 # Upstream Telegram Android client & library code
│   └── src/main/java/org/telegram/
│       ├── messenger/              # Account state, messages, media controllers, database
│       ├── tgnet/                  # TL schemas, MTProto engine, network transport
│       └── ui/                     # UI screens, ChatActivity, cells, viewers, dialogs
├── TMessagesProj_App/              # APK flavor packaging, manifests, build configuration
├── SecureOverlay/                  # Transport-isolated Signal protocol library & device tests
│   └── src/main/java/org/telegram/secureoverlay/
├── docs/                           # Architecture specs, security audits, and protocols
├── scripts/                        # Local environment checks, build, and deploy scripts
└── keystore/                       # Local signing keys and properties (strictly ignored)
```

`SecureOverlay` is strictly transport-isolated: it must not import Telegram classes or issue MTProto requests directly. `TMessagesProj` invokes `SecureOverlay` via narrow adapters. Any new feature must first define canonical binary serialization and unit/instrumentation tests in `SecureOverlay` before UI integration.

---

## 2. Text, Actions & Link Flow

### Outbound Send Path

```text
ChatActivity / ChatActivityEnterView
    -> SendMessagesHelper (central outbound guard)
    -> SecureChatEngine
       -> SecureContentCodec (type, payload serialization)
       -> SecureCarrierCodec (TGS1 RFC 4648 base64url envelope)
    -> Standard Telegram MTProto send in tgnet
```

`SendMessagesHelper` acts as the single choke-point for outbound actions. If a feature or action is unsupported or the ratchet session is not active, the operation is blocked fail-closed before any network call.

### Inbound Receive Path

On receipt, Telegram stores an opaque carrier text (`TGS1:...`). `ChatActivity` detects the carrier marker, calls `SecureChatEngine` to decrypt via the Double Ratchet session, and populates `MessageObject` with the decrypted text. The Telegram cloud server only ever sees the ciphertext envelope.

### Key Entry Points: Text, Actions, & Protection

| Component / Task | File / Path |
| --- | --- |
| Secure mode toggle, pairing, receive/display, link alerts | `TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java` |
| Outbound guards, edits, forwarding, remote deletions | `TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java` |
| Client-side linkification, message classification, local state | `TMessagesProj/src/main/java/org/telegram/messenger/MessageObject.java` |
| Link anti-spoofing engine (IDN, Punycode, homoglyphs, BiDi) | `SecureOverlay/.../SecureLinkGuard.java` |
| Payload serialization (Text, Contact, Location, Delete, Media) | `SecureOverlay/.../SecureContentCodec.java` |
| Carrier packaging (`TGS1:` base64url envelope) | `SecureOverlay/.../SecureCarrierCodec.java` |
| Session management, pairing, ratchet orchestration | `SecureOverlay/.../SecureChatEngine.java` |
| Keystore Signal protocol store & encrypted blob storage | `KeystoreSignalProtocolStore.java`, `KeystoreEncryptedBlobStore.java` |

---

## 3. Media Flow & Decrypted Playback

```text
User attachment / Camera / Voice & Round recorder
    -> SendMessagesHelper: classify photo/video/voice/round/audio/document/sticker
    -> SecureContentCodec: generate authenticated media manifest
    -> SecureMediaCrypto: encrypt file bytes with uniform nonce, random upload name
    -> Telegram uploads opaque file + TGS1 manifest
    -> ChatActivity downloads ciphertext -> decrypts to bounded local cache
    -> MessageObject routes decrypted path to native renderers
    -> Native playback for voice, audio, and video notes directly from decrypted cache
```

Original filenames, MIME types, captions, dimensions, durations, waveforms, and album grouping belong strictly to the encrypted manifest. Telegram server fields only contain randomized technical placeholders.

### Media Viewers & Screen Protection

- **Screen Protection**: `FLAG_SECURE` is programmatically enforced in `ChatActivity`, `ProfileActivity`, and `PhotoViewer` whenever secret mode or screen protection is enabled. Screenshots, screen recording, and system task switcher previews are blocked.
- **Export Guards**: Saving decrypted photos/videos to the public gallery, downloads directory, or forwarding to unencrypted external targets is disabled under screen protection.
- **Waveform & Duration Preservation**: Decrypted voice notes, round video notes, and audio tracks preserve their audio waveforms and scrubber timing inside `ChatMessageCell`.

---

## 4. Special Payload Codecs

- **Contacts (`TYPE_CONTACT`)**: Serializes contact name, phone number, and optional vCard payload inside the secure envelope; strips Telegram's unencrypted contact fields.
- **Geo-Location (`TYPE_GEO_LOCATION`)**: Serializes latitude, longitude, accuracy, and live period; the bubble preview blocks external tile network calls (`currentMapProvider = -1`) and requires user confirmation to open in secret mode.
- **Remote Deletion (`TYPE_CONTROL_DELETE`)**: Cryptographically signed deletion command; upon receipt, purges matching message ciphertext, decrypted memory cache, and local disk files.

---

## 5. Saved Messages & Backup Boundaries

Saved Messages operate without a remote peer ratchet, utilizing dedicated keystores:
- `SecureSavedMessagesKeyStore` & `SecureSavedMessageCrypto`.
- Cloud drafts and link preview metadata are strictly suppressed in protected Saved Messages.

Identity and history backups are separated into two distinct archives:
- `SecureIdentityBackupCodec/Manager`: Identity keys and session materials.
- `SecureHistoryBackupCodec/Manager`: Local plaintext and display records.
- After importing history, sessions remain paused until explicit re-verification to prevent replay hazards.

---

## 6. Development Workflow for New Features

1. **Define Specification**: Add canonical payload tag and bounds to `SecureContentCodec`.
2. **Add Failing Tests**: Write unit and device tests for serialization, boundaries, and corruption failure.
3. **Implement Crypto & Engine**: Wire encrypt/decrypt into `SecureChatEngine` or `SecureMediaCrypto`.
4. **Implement Outbound Guard**: Add strict validation gate in `SendMessagesHelper`.
5. **Implement UI & Presentation**: Add receive mapping in `ChatActivity` and presentation in `MessageObject`/`ChatMessageCell`.
6. **Verify on Hardware**: Test on connected Android device (`./scripts/check-local-mvp.sh`, connected tests).
