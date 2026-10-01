# Протокол захищеного оверлею Telegram v1 — специфікація

> [!NOTE]
> [The English version of this documentation is available in secure-overlay-protocol-v1.md](secure-overlay-protocol-v1.md).

**Статус:** ТІЛЬКИ ДЛЯ РЕВ'Ю — `changes required` до моменту отримання письмового підтвердження від незалежного аудитора у `protocol-review/REVIEW-DECISION.md`.

Цей документ визначає вимоги до MVP: один верифікований пристрій Android на користувача Telegram та наскрізне шифрування 1:1 чатів. Специфікація описує оверлей корисного навантаження додатку; вона не змінює MTProto, семантику TDLib, маршрутизацію або звичайні повідомлення Telegram.

Нормативні терміни **MUST**, **MUST NOT**, **SHOULD** та **MAY** використовуються згідно з RFC 2119. Декодер ПОВИНЕН відхиляти, а не намагатися виправити неканонічні вхідні дані.

---

## 1. Профіль та криптографічні обмеження

`protocol_version = 1`; набір криптографічних алгоритмів `suite_id = 0x0001` визначає комбінацію:
`Ed25519 + X25519 + HKDF-SHA-256 + XChaCha20-Poly1305 + Signal Double Ratchet`. Жодні інші алгоритми у v1 не підтримуються. Непідтримуване значення повертає `UNSUPPORTED_VERSION` або `UNSUPPORTED_SUITE` і ніколи не переходить на відкритий текст.

| Параметр | Максимальний або точний розмір |
|---|---:|
| Байти UTF-8 носія Telegram, включаючи префікс | 8,192 |
| Текст конверта Base64url після `TGS1:` | 8,187 |
| Розкодований конверт | 6,144 байтів |
| Будь-яке службове навантаження | 2,048 байтів |
| Зашифрований відкритий текст UTF-8 | 4,096 байтів |
| ID пристрою / ID сесії | Рівно 16 байтів |
| Публічний ключ Ed25519 / X25519 | Рівно 32 байти |
| Підпис Ed25519 | Рівно 64 байти |
| Нонс XChaCha / тег AEAD | Рівно 24 / 16 байтів |
| Номер повідомлення ратчета / довжина попереднього ланцюга | 0…2^32-1 |
| Збережені пропущені ключі / допустимий розрив ланцюга | 256 / 256 |
| Валідність бандла / тривалість життя сесії | 90 днів / 30 днів або 65,536 повідомлень |

Усі часові мітки задаються у беззнакових секундах Unix. Бандл приймається тільки якщо `created_at <= now + 300` та `now <= expires_at`. Збій системного годинника або стрибок назад понад 300 секунд блокує роботу зі статусом `CLOCK_UNTRUSTED`.

---

## 2. Канонічне бінарне кодування (CFS)

Кожен бінарний об'єкт є канонічною послідовністю полів (**Canonical Field Sequence — CFS**):

```
object := magic[4] || version:u8 || type:u8 || fields
field  := tag:u8 || length:u16be || value[length]
```

Поля розташовані у суворо зростаючому порядку тегів, зустрічаються рівно один раз і мають фіксовані мінімальні розміри. Невідомі поля, надлишкові байти або дублікати призводять до відхилення пакета. Цілі числа кодуються у форматі big-endian; текст має бути валідним найкоротшим UTF-8 без нульових байтів.

Носій Telegram містить маркер `TGS1:` плюс RFC 4648 base64url без вирівнювання (`=`) для одного CFS-конверта. Маркер зарезервовано: текст, що починається з нього, вважається захищеним носієм навіть у разі пошкодження, і ПОВИНЕН відображатися як помилка замість звичайного тексту.

---

## 3. Реєстр об'єктів

| Тип | Magic/тип | Обов'язкові поля CFS (тег: значення) |
|---|---|---|
| Identity bundle | `TGSB/0x01` | 1 suite U16, 2 owner U64, 3 device ID, 4 key version U32, 5 created U64, 6 expires U64, 7 Ed key KEY, 8 X key KEY, 9 rotation HASH, 10 signature SIG |
| Capability request | `TGSC/0x01` | 1 request ID, 2 initiator bundle bytes, 3 target owner U64, 4 target device ID, 5 issued U64, 6 expires U64 |
| Capability response | `TGSC/0x02` | 1 request ID, 2 responder bundle bytes, 3 initiator owner U64, 4 initiator device ID, 5 issued U64, 6 expires U64, 7 signature SIG |
| Handshake init | `TGSH/0x01` | 1 handshake ID, 2 initiator bundle bytes, 3 responder bundle hash HASH, 4 initiator ephemeral KEY, 5 issued U64, 6 expires U64, 7 signature SIG |
| Handshake response | `TGSH/0x02` | 1 handshake ID, 2 responder bundle bytes, 3 init hash HASH, 4 responder ephemeral KEY, 5 issued U64, 6 expires U64, 7 transcript HASH, 8 signature SIG |
| Handshake confirm | `TGSH/0x03` | 1 handshake ID, 2 role (`0x49` I або `0x52` R), 3 transcript HASH, 4 confirmation 32 bytes |
| Secure envelope | `TGSE/0x01` | §6 |

---

## 4. Конверт Signal Double Ratchet

Поля `TGSE/0x01`: 1 suite U16; 2 sender owner U64; 3 sender device ID; 4 recipient owner U64; 5 recipient device ID; 6 session ID; 7 session expiry U64; 8 ratchet public KEY; 9 previous-chain U32; 10 message number U32; 11 nonce (24); 12 ciphertext-with-tag (17…4112). Відкритий текст — валідний UTF-8 від 1 до 4096 байтів.

Шифрування здійснюється за допомогою `XChaCha20-Poly1305(message_key, nonce, plaintext, AD)`, де `AD` обчислюється як SHA-256 від CFS-конверта без полів 11 та 12. Для кожного ключа повідомлення генерується новий випадковий 24-байтний нонс.

---

## 5. Довговічний стан та обробка помилок

Сховище захищене ключем Android Keystore та містить монотонний лічильник `state_generation`.

| Код помилки | Обов'язковий результат |
|---|---|
| `NOT_SECURE_CARRIER` | Звичайний текст лише якщо маркер відсутній |
| `MALFORMED_CARRIER`, `RESOURCE_LIMIT`, `NON_CANONICAL` | Повідомлення про відхилення носія; жодних змін стану |
| `UNSUPPORTED_VERSION`, `UNSUPPORTED_SUITE`, `DOWNGRADE_DETECTED` | Блокування; без повернення до відкритого тексту |
| `PEER_BINDING_FAILED`, `BUNDLE_INVALID`, `AUTH_FAILED` | Відхилення; без мутацій сесії |
| `REPLAY`, `OUT_OF_ORDER_LIMIT`, `SESSION_EXPIRED` | Відхилення та блокування/пересинхронізація |
| `STORAGE_FAILED`, `KEYSTORE_INVALIDATED`, `KEYSTORE_CORRUPT` | Постійне скидання безпеки |
| `SEND_OUTCOME_UNKNOWN`, `CLOCK_UNTRUSTED` | Блокування відправлення; явне ручне відновлення |
