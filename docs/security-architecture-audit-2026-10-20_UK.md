# Аудит безпеки та архітектури Fork-Secure (2026-10-20)

**Дата:** 2026-10-20
**Обсяг:** `telegram-secure-android/SecureOverlay/src/main` (криптографія, протокол, сховища, бекапи), точки інтеграції в `TMessagesProj` (`ChatActivity`, `SendMessagesHelper`, `MessageObject`, медіа‑шлях), конфігурація збірки та скрипти.
**Метод:** ручний code review (статичний аналіз). Це не формальний криптографічний аудит і не тестування на пристроях.
**Статус:** у процесі — знахідки додаються по мірі аналізу.

## Шкала серйозності

| Рівень | Значення |
| --- | --- |
| Critical | Пряма втрата конфіденційності/автентичності секретного контенту або ключів |
| High | Реалістична атака/збій, що порушує заявлені гарантії або призводить до витоку даних |
| Medium | Послаблення захисту, DoS, витік метаданих, крихка архітектура з ризиком регресій |
| Low | Defense‑in‑depth, гігієна коду, документація |
| Info | Спостереження без прямого ризику |

## Зведена таблиця

| ID | Серйозність | Область | Коротко |
| --- | --- | --- | --- |
| SA-01 | Critical | Групи / SenderKey | `SenderKeyDistributionMessage` надсилається в групу відкритим carrier‑повідомленням, без pairwise‑шифрування |
| SA-02 | Critical | Групи / автентичність | Distribution приймається від будь‑кого; відправник визначається лише за `from_id` Telegram |
| SA-03 | High | Pairing / TOFU | Перший pairing offer автоматично приймається без перевірки fingerprint — MITM з боку сервера Telegram |
| SA-04 | High | Прив'язка відправника | Адреса сесії для дешифрування береться з `from_id` повідомлення; результат кешується в чужому чаті |
| SA-05 | High | Ratchet rollback | Відкат Signal‑сесії після «відхиленого» edit може повторно використати message key |
| SA-06 | High | Конкурентність | Encrypt і decrypt однієї сесії не серіалізовані (різні lock'и, `encryptText` без lock) — lost update ratchet‑стану |
| SA-07 | High | Pairing bypass | Вхідний `PreKeySignalMessage` для peer без trusted identity мовчки встановлює сесію і вмикає `PROTECTED` |
| SA-08 | Medium | Обробка помилок | `DuplicateMessageException` перетворюється на «видалене повідомлення» і стирає локальний запис |
| SA-09 | Medium | Ключова гігієна | Signed pre‑key (id 2) і Kyber last‑resort key (id 3) ніколи не ротуються; one‑time pre‑key публікується повторно |
| SA-10 | Medium | Прив'язка identity | Pairing offer не прив'язаний до Telegram user ID відправника/отримувача; legacy v1 offer без підпису метаданих досі приймається |

## Детальні знахідки

### SA-01 (Critical): груповий SenderKey розсилається відкритим текстом

**Де:**
- [ChatActivityEnterView.java:7935-7976](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/Components/ChatActivityEnterView.java#L7935-L7976) — `/secure-start`, `/secure-group-key`, `/secure-group-rotate` і автоматична redistribution перед кожним повідомленням надсилають `createGroupSenderKeyDistributionCarrier(dialog_id)` як звичайний текст у груповий `dialog_id`.
- [SendMessagesHelper.java:3596](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java#L3596) — те саме на шляху надсилання.
- [SecureChatEngine.java:199-208](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L199-L208) — carrier `TYPE_SENDERKEY_DISTRIBUTION` = сирі байти distribution message без жодного шифрування.

**Суть:** `SenderKeyDistributionMessage` у libsignal містить chain key та публічний ключ підпису у відкритому вигляді; Signal покладається на те, що він доставляється всередині pairwise‑сесії. Коментар у [SecureCarrierCodec.java:17](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureCarrierCodec.java#L17) прямо це декларує («sent via 1:1 pairwise secure session»), але реалізація публікує його в саму групу.

**Наслідки:** сервер Telegram, кожен учасник групи (включно з тими, хто не використовує форк, ботами, новими учасниками з доступом до історії) може вивести всі message keys і розшифрувати **всі** групові повідомлення. UI при цьому показує групу як захищену.

**Рекомендація:** негайно вимкнути групове шифрування (feature flag / fail‑closed у `SendMessagesHelper`). Перед поверненням: доставляти distribution лише через встановлені й верифіковані 1:1 сесії (`encrypt(peerAddress, distribution)`), ротація sender key при зміні складу групи, тести, що carrier type 5 ніколи не відправляється в `dialog_id < 0`. Також узгодити документацію: [TELEGRAM-ANDROID-FORK-MAP.md](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/docs/TELEGRAM-ANDROID-FORK-MAP.md) стверджує, що групи лишаються стандартним Telegram.

### SA-02 (Critical): неавтентифіковане прийняття group distribution

**Де:** [SecureChatEngine.java:211-228](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L211-L228), [ChatActivity.java:21344-21351](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L21344-L21351), `NotificationsController.java:1884-1889`.

**Суть:** `processGroupSenderKeyDistributionCarrier(message.getFromChatId(), carrier)` зберігає distribution під адресою `telegram-user-<from_id>`. `from_id` — метадані сервера; distribution ніяк не прив'язаний до identity key відправника. Крім того, будь‑який прийнятий distribution автоматично вмикає групу (`enableGroup()` → `markPaired`) і очищує глобальний `failedDecryptCarriers`.

**Наслідки:** сервер або учасник може підробити distribution від імені будь‑якого користувача і далі надсилати «перевірені» (`forkSecureVerified = true`) повідомлення від його імені; також може примусово увімкнути secure‑режим групи.

**Рекомендація:** приймати distribution лише як вміст розшифрованого pairwise‑повідомлення від верифікованого peer, де адреса відправника = адреса сесії; не змінювати режим чату з вхідних даних без дії користувача.

### SA-03 (High): TOFU‑автоприйняття першого pairing offer

**Де:** [SecureChatEngine.java:266-396](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L266-L396) (`canAutoAcceptPairingOffer()` → `ACCEPTED_INITIAL`), [ChatActivity.java:21305-21315](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L21305-L21315) — автоматично викликається при рендері історії і одразу відправляє ack.

**Суть:** pre‑key bundle передається через хмарний чат Telegram, тобто через сервер, який і є основним супротивником у моделі загроз. Якщо режим `OFF`, перший offer приймається без участі користувача, сесія встановлюється, чат переходить у `PROTECTED`, а ack відправляється автоматично. Порівняння fingerprint (`getOwnFingerprint`/`getTrustedFingerprint`) лише опційне.

**Наслідки:** сервер (або будь‑хто з контролем доставки) може підмінити обидва bundle і бути MITM; користувач бачить «захищений» статус. Додатково, будь‑який співрозмовник може примусово «увімкнути» secure‑режим простим повідомленням.

**Рекомендація:** розрізняти стани `PROTECTED_UNVERIFIED` і `VERIFIED`; вимагати явного підтвердження користувача для прийняття offer; показувати постійний індикатор неверифікованої сесії; бажано — QR/safety number на основі обох identity ключів.

### SA-04 (High): адреса Signal‑сесії визначається з `from_id`

**Де:** [SecureChatEngine.java:1076-1079](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L1076-L1079), аналогічно `decryptAttachmentManifest` (834-840) і `decryptStaticStickerManifest` (487-493); виклик з [ChatActivity.java:21414](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L21414).

**Суть:** движок, створений для peer `P`, дешифрує повідомлення сесією `telegram-user-<senderUserId>`, якщо `senderUserId > 0`, але кешує результат, застосовує delete‑control і викликає `markPaired` у сховищах, прив'язаних до `P`. Контент Signal‑повідомлень не містить associated data з ідентифікатором чату/отримувача.

**Наслідки:** повідомлення, валідне для сесії з `X`, може бути перенесене в чат з `P` і показане як перевірене; `TYPE_CONTROL_DELETE` від `X` видаляє записи в чаті `P`; message key у сесії `X` витрачається → справжнє повідомлення в чаті `X` не розшифрується (DoS). Також `markPaired(P)` при відсутній сесії з `P`.

**Рекомендація:** для 1:1 завжди використовувати `peerAddress` і відхиляти `senderUserId != peerUserId`; додати до plaintext‑конверта `FSC1` автентифіковані поля `sender`, `recipient`, `conversation id`.

### SA-05 (High): відкат ratchet після edit може повторно використати message key

**Де:** [SecureChatEngine.java:619-708](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L619-L708) (`rollbackAttachmentEdit`, `rollbackTextEdit`).

**Суть:** після створення carrier сесія повертається до попереднього стану, якщо Telegram «відхилив» edit. Перевірка «ніхто не використав сесію пізніше» лише локальна. Якщо помилка неоднозначна (таймаут, обрив з'єднання після прийняття сервером, `FLOOD_WAIT` після доставки), carrier з ключем `N` міг бути доставлений, а наступне повідомлення знову зашифрується ключем `N` з іншим plaintext.

**Наслідки:** повторне використання message key/IV (AES‑CBC + HMAC у Signal) — порушення властивостей протоколу, витік рівності префіксів, а на боці отримувача — `DuplicateMessageException` і втрата повідомлення (див. SA‑08).

**Рекомендація:** ніколи не відкочувати ratchet після того, як carrier покинув процес; при помилці edit просто вважати ключ спаленим. Відкат допустимий лише до передачі в мережевий шар (як у перевірці довжини caption).

Виклики: [SendMessagesHelper.java:5887-5915](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java#L5887-L5915) відкочує сесію на **будь‑яку** `error` від `messages.editMessage`, включно з internal/timeout помилками; [SendMessagesHelper.java:1531-1562](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/messenger/SendMessagesHelper.java#L1531-L1562) — також при скасуванні редагування.

### SA-06 (High): гонка між encrypt і decrypt на одному `SessionRecord`

**Де:** [SecureChatEngine.java:56-57](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L56-L57) — окремі `DECRYPT_LOCK` і `ENCRYPT_LOCK`; [SecureChatEngine.java:431-435](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L431-L435) — `encryptText`, `encryptContact`, `encryptLocation`, `encryptDeleteControl`, `createPairingAcknowledgement` взагалі без lock; [KeystoreSignalProtocolStore.java:250-270](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/KeystoreSignalProtocolStore.java#L250-L270) — `loadSession`/`storeSession` без синхронізації на рівні запису.

**Суть:** `SessionCipher` у libsignal 0.86.6 не має внутрішніх monitor'ів (перевірено `javap` — жодного `monitorenter`), тобто виконує load → modify → store і очікує, що виклики для однієї адреси серіалізує застосунок. Decrypt викликається з UI (`ChatActivity`) і з фонової черги (`NotificationsController`, `DialogCell` preview), encrypt — з UI і `SendMessagesHelper`.

**Наслідки:** якщо decrypt і encrypt перетинаються, пізніший `storeSession` перезаписує результат іншого: (а) відкат лічильника sending chain → повторне використання message key (як у SA‑05); (б) втрата receiving chain/skipped keys → наступні повідомлення не розшифровуються; (в) втрата нового DH ratchet step.

**Рекомендація:** один lock на адресу (або глобальний) для **всіх** операцій, що читають/пишуть сесію, identity, pre‑keys і sender keys, включно з `establish`, rollback і `acceptPendingIdentity`; додати стрес‑тест паралельних encrypt/decrypt.

### SA-07 (High): обхід явного pairing через вхідний PreKey‑повідомлення

**Де:** [KeystoreSignalProtocolStore.java:173-178](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/KeystoreSignalProtocolStore.java#L173-L178) (`isTrustedIdentity` → `true`, якщо identity ще не збережено), [SecureChatEngine.java:1076-1144](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L1076-L1144) (`markPaired` після будь‑якого успішного decrypt).

**Суть:** наш pre‑key bundle публікується у хмарних повідомленнях і доступний серверу. Сервер (або будь‑хто, хто бачив offer) може сформувати `PreKeySignalMessage` від власного identity і доставити його в чат з peer, з яким ще немає trusted identity. libsignal збереже нову identity (TOFU), створить сесію, а движок викличе `markPaired` — без offer від peer, без `PairingOfferResult`, без жодного UI‑підтвердження. Разом із SA‑04 це працює навіть з довільним `from_id`.

**Наслідки:** повний обхід механізму «pending identity / fingerprint»; MITM на першому контакті без участі користувача.

**Рекомендація:** `isTrustedIdentity` має повертати `true` лише для identity, явно прийнятої через `receivePairingOffer`/`acceptPendingIdentity` (окремий allow‑list); decrypt не повинен змінювати режим чату; PreKey‑повідомлення приймати лише в стані `WAITING` для нашого власного відправленого offer.

### SA-08 (Medium): `DuplicateMessageException` маскується під видалення

**Де:** [SecureChatEngine.java:1149-1159](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecureChatEngine.java#L1149-L1159), обробка в [ChatActivity.java:21421-21432](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/TMessagesProj/src/main/java/org/telegram/ui/ChatActivity.java#L21421-L21432).

**Суть:** повторно отримане повідомлення (replay сервером, втрачений кеш після відновлення/очищення, або наслідок SA‑05/SA‑06) повертає `CONTROL_DELETE_DISPLAY`, викликає `forgetByDigest` для свого digest, а `ChatActivity` після цього **видаляє Telegram‑повідомлення** (`deleteMessages`).

**Наслідки:** сервер може змусити клієнта приховати/видалити довільне раніше отримане повідомлення, просто повторно доставивши його carrier; помилки протоколу маскуються як легітимна дія співрозмовника, що ускладнює діагностику.

**Рекомендація:** показувати окремий статус «дублікат/повтор» без деструктивних дій; видалення — лише за автентифікованим `TYPE_CONTROL_DELETE`.

### SA-09 (Medium): відсутня ротація signed/Kyber pre‑key

**Де:** [KeystoreSignalProtocolStore.java:116-151](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/KeystoreSignalProtocolStore.java#L116-L151).

**Суть:** `signedPreKeyId = 2` і `kyberPreKeyId = 3` створюються один раз і не замінюються до скидання identity. One‑time pre‑keys видаються по колу (`prekey_offer_offset`), тож один ключ може опинитися в кількох offer.

**Наслідки:** компрометація signed pre‑key (наприклад, через бекап/форензику) зачіпає всі майбутні й минулі початкові обміни; повторно виданий one‑time pre‑key ламає встановлення сесії другому peer (`InvalidKeyIdException`).

**Рекомендація:** періодична ротація signed і Kyber pre‑key з утриманням попередніх на обмежений період; одноразова видача one‑time pre‑key (видаляти з пулу «доступних» після публікації).

### SA-10 (Medium): pairing offer не прив'язаний до учасників

**Де:** [SecurePreKeyBundleCodec.java:93-126](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecurePreKeyBundleCodec.java#L93-L126), [SecurePreKeyBundleCodec.java:139-172](file:///home/sommelier/projects/telegram-encryption/telegram-secure-android/SecureOverlay/src/main/java/org/telegram/secureoverlay/SecurePreKeyBundleCodec.java#L139-L172).

**Суть:** підпис v2 покриває ключі та recovery‑метадані, але не Telegram user ID власника і не адресата. Формат v1 (без підпису метаданих) досі приймається для нових peer.

**Наслідки:** unknown‑key‑share: сервер може переслати offer користувача A в чат з користувачем M; downgrade до v1 знімає захист recovery generation для першого контакту.

**Рекомендація:** включити `owner_user_id`, `intended_peer_id`, час/nonce у підписане тіло; відхиляти v1 після міграції.

