# Telegram Android Fork-Secure: карта коду

Це внутрішній довідник для локальної розробки. Він описує підтримуваний форк
`telegram-secure-android`, а не старі sandbox-модулі в корені
`telegram-encryption/`. Нативні Secret Chats Telegram не змінюються; Fork-Secure
працює лише у звичайних захищених чатах 1:1 та в окремому режимі Saved Messages.

## 1. Карта репозиторію

```text
telegram-secure-android/
├── TMessagesProj/                 # основний Telegram Android client/library
│   └── src/main/java/org/telegram/
│       ├── messenger/              # стан акаунта, повідомлення, медіа, БД
│       ├── tgnet/                  # TL-схеми, MTProto та API-транспорт
│       └── ui/                     # екрани, клітинки, viewer, відправлення
├── TMessagesProj_App/              # APK-складання та variant app
├── SecureOverlay/                  # ізольований secure-протокол і device tests
├── docs/                           # рішення, межі безпеки, плани та аудит
├── scripts/                        # локальна перевірка, build/install/run
└── keystore/                       # локальні signing-матеріали, не комітити
```

`SecureOverlay` не повинен імпортувати Telegram-класи або сам виконувати
MTProto-запити. `TMessagesProj` викликає його через вузькі адаптери. Будь-яка
нова можливість спочатку має отримати канонічний формат і негативні тести в
`SecureOverlay`, а вже потім UI-інтеграцію.

## 2. Потік текстового повідомлення

### Відправлення

```text
ChatActivity / ChatActivityEnterView
    -> SendMessagesHelper (єдина outbound-перевірка)
    -> SecureChatEngine
       -> SecureContentCodec (тип і payload)
       -> SecureCarrierCodec (TGS1 carrier)
    -> звичайний Telegram send API у tgnet
```

`SendMessagesHelper` вирішує, чи дозволений action у захищеному чаті. Якщо
payload не підтриманий або сесія не готова, відправлення має бути відхилене
до виклику Telegram API і без зміни secure-state.

На прийомі Telegram зберігає opaque carrier. `ChatActivity` розпізнає його,
`SecureChatEngine` перевіряє сесію та розшифровує, а локальний display-cache
підставляє текст у `MessageObject`. Сервер не отримує plaintext.

Ключові місця:

| Завдання | Файл |
| --- | --- |
| Secure mode, pairing, receive/display | `TMessagesProj/.../ui/ChatActivity.java` |
| Єдина відправка, media/send/edit/forward guards | `TMessagesProj/.../messenger/SendMessagesHelper.java` |
| Тип, текст, caption, album metadata | `SecureOverlay/.../SecureContentCodec.java` |
| TGS1 parsing, signature, replay envelope | `SecureOverlay/.../SecureCarrierCodec.java` |
| Session, pairing, local plaintext records | `SecureOverlay/.../SecureChatEngine.java` |
| Keystore state and Signal store | `KeystoreEncryptedBlobStore.java`, `KeystoreSignalProtocolStore.java` |

## 3. Потік медіа

```text
Telegram picker/share intent
    -> SendMessagesHelper: identify photo/video/document/sticker/audio
    -> SecureContentCodec: authenticated manifest
    -> SecureMediaCrypto: encrypt bytes, random upload name
    -> Telegram uploads opaque file + TGS1 manifest
    -> ChatActivity downloads/decrypts to bounded local cache
    -> MessageObject.forkSecureMedia*
    -> ChatMessageCell / DialogCell / PhotoViewer / media grid
```

Реальне ім'я, MIME, caption, розмір, dimensions і album id належать до
зашифрованого manifest. У Telegram-полях та upload-name залишаються лише
безпечні технічні значення. `SecureMediaIndex` дозволяє відновити прев'ю у
списку чатів; `SecureMediaCache` обмежує локальні копії. Для відео список чатів
використовує статичний `vthumb://0:` thumbnail, а повноекранний viewer може
використовувати звичайне відтворення після розшифрування.

### Viewer layout and thumbnail cache

`PhotoViewer.FrameLayoutDrawer.onMeasure()` lays out both the bottom
`GroupedPhotosListView` (68dp) and the video controls (48dp). The video controls
must receive the grouped-strip height as an additional bottom margin; otherwise
the first fullscreen opening after re-entering a chat draws the seekbar and time
over the thumbnails. Album-to-album switching can appear correct because the
second layout pass has already completed.

Secure fullscreen video thumbnails are written asynchronously to
`FileLoader.MEDIA_DIR_CACHE/fork-secure-thumbnails/`, keyed by the MD5 of the
local authenticated video path. The cache is bounded to 80 files/32 MiB. Do not
extract frames on the UI thread. A first open may briefly use the `vthumb://`
fallback while the JPEG is generated; the next bind must replace it from cache.
If entering a chat still causes a visible delay, profile `MediaDataController`,
`SecureMediaIndex`, and `PhotoViewer` binding first, then prewarm only the
authenticated local paths that are actually visible.

### Latest runtime evidence

On 2026-08-01, CPH (`636567fd`) reproduced a remaining delay only when entering
the chat after leaving it; switching inside an already-open album was responsive.
The current code path calls `ChatActivity.applySecureTextOverlay()` for the
loaded batch. After a process restart, `SecureLocalTextStore.displayCache` is
cold, so the first per-message reads may cross the Keystore-backed
`SharedPreferences` store. This is a working hypothesis, not yet a measured
root cause. The next safe step is timing the first/second overlay pass and
separately timing `SecureMediaIndex.find`, manifest restore, and thumbnail bind
before adding a worker-thread preload or changing cache semantics.

### Caption editing boundary

Long-press/message-menu editing of an authenticated photo or video is handled by
`SendMessagesHelper.editForkSecureAttachmentCaptionIfNeeded()`. It decrypts the
old manifest, changes only the authenticated caption/above-below marker, creates
a new carrier, and calls `messages.editMessage`; media bytes, local path, and
album identity stay unchanged. Only the author may edit a paired 1:1 message.
The same helper has a separate Saved Messages branch. Fullscreen secure viewers
remain read-only on open. The localized `EditCaption` action is shown in the
`⋮` menu only for the authenticated author; selecting it explicitly opens the
normal editor, so the input does not cover the album strip just because a viewer
was opened. The provider's `onApplyCaption()` callback resolves the currently
visible authenticated source (including the current item of an album) and calls
the public `SendMessagesHelper.editForkSecureAttachmentCaption()` bridge with
the explicit above/below placement. The media bytes, local path, and album
identity are still unchanged. Caption entry during initial media composition
remains the normal Telegram flow. On 2026-08-01 this was verified on CPH
(`636567fd`): a caption was changed to `Secure_caption_test`, the viewer was
closed and reopened, and the new caption was still present; no Fork-Secure or
fatal runtime error appeared in the sampled logcat. This is an author-only
1:1/Saved Messages path; forwarded or non-authenticated media remains outside
the bridge.

The explicit editor also listens for the caption container's keyboard visibility
callback: when the keyboard is dismissed after the edit action, the secure edit
is committed and the input layer is removed, so a stale editor cannot remain over
the fullscreen viewer.

Secure album videos do not auto-start in the chat cell: the first frame/thumbnail
and play affordance are shown while browsing the album. A standalone video may
still autoplay in the chat, and opening any video in the fullscreen viewer uses
the regular autoplay preference. The in-chat upstream path has the same
boundary: `GroupMedia` computes autoplay as
`video && !album && SharedConfig.isAutoplayVideo()`, and `ChatMessageCell`
requires the single-message position flags before starting a video. The secure
overlay has an additional explicit guard, `ChatMessageCell.isForkSecureAlbumVideo`,
in both video-layout branches; it disables animation and requests a single frame
for authenticated album members even when Telegram's global autoplay preference
is enabled.

The authenticated album id is copied to the current UI message after background manifest
decryption, not only to the worker-side object. Completed media index entries persist the
album marker inside the encrypted caption metadata and strip it again before display. This
keeps grouping and the no-autoplay guard stable after a process restart; legacy index entries
without the marker remain usable as standalone media.

Album layout has an explicit metadata barrier. `ChatActivity` first remembers each carrier's
original Telegram `grouped_id`, keeps that native document group while any member is still
pending, and only then creates the secure visual group. A secure album is eligible only when all
members have the same authenticated album id, a positive width/height, and a photo or video
manifest. The member list is sorted by message id and `GroupedMessages.calculate()` runs only
when that ordered set changes. Later ciphertext/plaintext completion therefore fills existing
cells without recalculating the grid after every file. The sender records video dimensions while
building the manifest, so new albums do not wait for a decrypted file merely to discover their
aspect ratios.

Attachment manifests allow positive dimensions for authenticated `video/*` entries, including
`video/webm`; ordinary documents must keep both dimensions zero. Legacy video manifests with no
dimensions remain readable and fall back to dimensions discovered from the local plaintext file.
The secure viewer uses the local authenticated path, so WebM does not depend on Telegram's
server-side document MIME classification.

### Telegram visual/performance settings

Secure UI must follow existing Telegram controls instead of adding a parallel
performance preference. Relevant seams are `SharedConfig.animationsEnabled()`
and the global `view_animations` preference for transitions,
`SharedConfig.getDevicePerformanceClass()` for low-device fallbacks,
`LiteMode` flags for chat scale/blur and animated content, and
`SharedConfig.isAutoplayVideo()` for ordinary non-secure media. Secure album
viewers already use static cached thumbnails. The viewer also suppresses its
transition animation when global animations are disabled or Telegram classifies
the device as low performance. The next performance pass should measure these
settings on the CPH and low-class Redmi paths before changing blur, transition,
or cache behavior.

UI-точки медіа:

- `MessageObject.java` — класифікація виду і розмірів, grouped album state;
- `ChatMessageCell.java` — одна бульбашка, caption, shield/lock, actions;
- `DialogCell.java` — preview у списку чатів;
- `SharedPhotoVideoCell*.java` — профільний media grid;
- `PhotoViewer.java`, `PinchToZoomHelper.java` — full-screen і quick zoom;
- `MediaDataController.java` — Telegram media/shared-media loading.

Новий вид медіа треба додавати послідовно: manifest → crypto → send gate →
receive/decrypt → `MessageObject` → bubble/viewer/grid → positive/negative tests.
Не маскувати невідомий тип як звичайний файл: fail closed із локалізованим
повідомленням.

## 4. Saved Messages і резервування

Saved Messages не має remote peer-сесії, тому використовує окремі:
`SecureSavedMessagesKeyStore`, `SecureSavedMessageCrypto`, policy/settings.
Не підміняти цей ключ ключем 1:1 чату.

Ідентичність та історія — різні архіви:

- `SecureIdentityBackupCodec/Manager` — identity/session material;
- `SecureHistoryBackupCodec/Manager` — локальні display/content records;
- `ForkSecureSettingsActivity` — пароль, eye-toggle, import/export UI.

Restore не повинен мовчки відновлювати активний ratchet. Після імпорту історії
чат має залишатися paused до нового handshake/verification. Будь-який backup
має бути password-protected, versioned і перевірений до мутації Keystore.

## 5. Як виконувати типову зміну

### Додати новий secure action

1. Записати canonical payload та межі розміру в `SecureContentCodec`.
2. Додати RED-тести: malformed, duplicate/replay, wrong key, no state mutation.
3. Додати encrypt/decrypt у `SecureChatEngine` або `SecureMediaCrypto`.
4. Додати outbound guard у `SendMessagesHelper`.
5. Додати receive/display mapping у `ChatActivity` і `MessageObject`.
6. Перевірити caption/reply/forward/notification/list preview окремо.
7. Зібрати APK і перевірити на підключеному CPH; не називати функцію готовою
   без runtime-перевірки.

### Приклад пошуку причини UI-багу

Якщо ciphertext видно у reply preview: почати з `ChatActivity` (reply label),
потім `MessageObject` (локальний текст), далі `ChatMessageCell` (render). Якщо
помилка лише у списку чатів: почати з `DialogCell` та `SecureMediaIndex`, а не
з протоколу.

## 6. Перевірка та межі

```bash
cd telegram-secure-android
./scripts/check-local-mvp.sh
./scripts/build-local-mvp.sh
ANDROID_SERIAL=<serial> ./gradlew :SecureOverlay:connectedDebugAndroidTest --no-daemon --console=plain
./scripts/install-local-mvp.sh <serial>
adb -s <serial> shell monkey -p ua.securechat.telegram 1
```

Перед передачею APK виконати `git diff --check`, зафіксувати device/serial,
тестовий сценарій і відомі failures. Не комітити `local.properties`, API
credentials, keystores, decrypted media або device dumps. Поточна черга після
медіа-preview/albums: native voice/round/GIF/audio/document playback, Telegram
actions, повне recovery-фізичне тестування, потім performance/cache/privacy
аудит.
