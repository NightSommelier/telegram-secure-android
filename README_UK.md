# Telegram Fork-Secure [![Android CI](https://github.com/NightSommelier/telegram-secure-android/actions/workflows/android.yml/badge.svg?branch=main)](https://github.com/NightSommelier/telegram-secure-android/actions/workflows/android.yml) [![License: GPL v2 or later](https://img.shields.io/badge/License-GPL--2.0--or--later-blue.svg)](LICENSE) [![Latest Release](https://img.shields.io/github/v/release/NightSommelier/telegram-secure-android?include_prereleases&label=release)](https://github.com/NightSommelier/telegram-secure-android/releases)

Telegram Fork-Secure — це захищений форк офіційного клієнта Telegram для Android (версія **v12.10.5**). Він додає прозорий шар наскрізного шифрування (E2EE) для звичайних 1:1 хмарних чатів та режиму «Збережені повідомлення» (Saved Messages) на базі протоколу Signal Double Ratchet (`SecureOverlay`), без потреби у змінах серверної частини Telegram та зі збереженням звичної маршрутизації повідомлень.

> [!NOTE]
> [The English version of this documentation is available in README.md](README.md).

---

## Ключові можливості

- **E2EE на базі протоколу Signal (`SecureOverlay`)**: Наскрізне шифрування повідомлень із використанням X3DH, Double Ratchet, ключів Ed25519/X25519 та автентифікованого шифрування XChaCha20-Poly1305 поверх стандартних носіїв (carriers) 1:1 чатів Telegram.
- **Шифрування медіафайлів**: Повне шифрування фотографій, голосових повідомлень, круглих відеонотаток, музики/аудіо, документів та стікерів. Відтворення здійснюється безпосередньо з розшифрованого локального кешу зі збереженням форми хвилі звуку та метаданих.
- **Шифрування контактів та геопозиції**: Окремі захищені кодеки корисного навантаження для `TYPE_CONTACT` (vCard / телефон / ім'я) та `TYPE_GEO_LOCATION` із захищеним попереднім переглядом карти в секретному режимі.
- **Автентифіковане дистанційне видалення**: Криптографічно підписані пакети віддаленого видалення (`TYPE_CONTROL_DELETE`) з верифікацією дайджесту носія та автоматичним очищенням шифротексту, розшифрованого кешу та файлів на диску.
- **Безпечне пересилання медіа**: Пересилання захищеного контенту між сесіями: медіа локально розшифровується і повторно шифрується під ланцюг ратчета отримувача зі збереженням підписів, аудіохвиль та пропорцій.
- **Захист від фішингу та спуфінгу посилань (`SecureLinkGuard`)**: Виявлення омогліфів IDN (змішування кирилиці/латини/грецьких літер), Punycode (`xn--`), невидимих символів та BiDi-керування, спуфінгу authority (`user:pass@host`), з обов'язковим підтвердженням користувача перед відкриттям зовнішнього браузера.
- **Захист екрана та запобігання витоку даних**: Примусовий `FLAG_SECURE` для вікон чату, профілю та переглядача медіа; блокування експорту до галереї, зняття скріншотів та поширення розшифрованих файлів; придушення хмарних чернеток та прев'ю посилань у захищених діалогах; блокування незашифрованих реакцій.

---

## Завантаження (v12.10.5)

Підписані пакунки для підтримуваних архітектур:

| Архітектура | Пакунок | Контрольна сума |
| :--- | :--- | :--- |
| **arm64-v8a** | [`telegram-fork-secure-12.10.5-arm64-v8a.apk`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-arm64-v8a.apk) | [`SHA-256`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-arm64-v8a.apk.sha256) |
| **universal** | [`telegram-fork-secure-12.10.5-universal.apk`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-universal.apk) | [`SHA-256`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-universal.apk.sha256) |
| **armeabi-v7a** | [`telegram-fork-secure-12.10.5-armeabi-v7a.apk`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-armeabi-v7a.apk) | [`SHA-256`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-armeabi-v7a.apk.sha256) |
| **x86_64** | [`telegram-fork-secure-12.10.5-x86_64.apk`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-x86_64.apk) | [`SHA-256`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-x86_64.apk.sha256) |
| **x86** | [`telegram-fork-secure-12.10.5-x86.apk`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-x86.apk) | [`SHA-256`](https://github.com/NightSommelier/telegram-secure-android/releases/download/v12.10.5%2B965ecc7/telegram-fork-secure-12.10.5-x86.apk.sha256) |

Примітки до релізу та параметри верифікації: [Releases](https://github.com/NightSommelier/telegram-secure-android/releases/tag/v12.10.5%2B965ecc7).

---

## Структура репозиторію та документація

```text
telegram-secure-android/
├── TMessagesProj/          # Кодова база клієнта Telegram (UI, мережа, медіа, база даних)
├── TMessagesProj_App/      # Складання додатка Android, флейвори та конфігурація збірки
├── SecureOverlay/          # Ізольований шар протоколу Signal, кодеки, сховище та тести
├── docs/                   # Архітектурні описи, аудити безпеки та інструкції розробника
├── scripts/                # Скрипти локальної перевірки, збірки та деплою
└── .github/workflows/      # Робочі процеси CI/CD для збірки та релізів
```

- [**FORK_UK.md**](FORK_UK.md): Базовий стан форку, взаємодія з апстрімом та межі архітектури.
- [**CONTRIBUTING_UK.md**](CONTRIBUTING_UK.md): Модель гілок (`dev`, `feature/*`, `main`), стиль коду та процес Pull Request.
- [**SECURITY_UK.md**](SECURITY_UK.md): Політика безпеки, повідомлення про вразливості та межі довіри.
- [**docs/LOCAL-MVP_UK.md**](docs/LOCAL-MVP_UK.md): Швидке налаштування, середовище розробки Nix, команди збірки та перевірка на фізичних пристроях.
- [**docs/TELEGRAM-ANDROID-FORK-MAP_UK.md**](docs/TELEGRAM-ANDROID-FORK-MAP_UK.md): Карта навігації по кодовій базі, маршрути проходження повідомлень та ключові точки входу.
- [**docs/fork-secure-feature-security-audit_UK.md**](docs/fork-secure-feature-security-audit_UK.md): Детальний аудит безпеки функцій месенджера, аналіз метаданих та захисні механізми fail-closed.
- [**docs/secure-overlay-protocol-v1_UK.md**](docs/secure-overlay-protocol-v1_UK.md): Специфікація бінарного протоколу Canonical Field Sequence (CFS), рукостискання та стан ратчета.

---

## Модель розробки та робота з гілками (Branching Workflow)

Для розробки застосовується чітка модель гілок:

1. **`dev`**: Основна робоча гілка для щоденної розробки та інтеграції. Усі PR з новими фічами спрямовуються сюди.
2. **`feature/<назва>`**: Гілки окремих фіч або виправлень, які створюються від `dev` і зливаються назад у `dev`.
3. **`main` / `master`**: Гілки стабільних релізів із тегами версій (`v<version>`).

---

## Локальна збірка та тестування

Репозиторій містить середовище розробки Nix (`shell.nix`), яке надає JDK 21, Android SDK платформи 35 і 36, NDK 27.2.12479018 та CMake 3.22.1.

### Попередні вимоги

1. Отримайте власні `api_id` та `api_hash` на [my.telegram.org](https://my.telegram.org/apps).
2. Налаштуйте `local.properties` (див. приклад `local.properties.example`).

### Основні команди

```bash
# Перевірка оточення та залежностей
./scripts/check-local-mvp.sh

# Локальна збірка ARM64 debug APK
./scripts/build-local-mvp.sh

# Запуск інструментальних тестів на підключеному пристрої
nix-shell --run 'ANDROID_SERIAL=<device_serial> ./gradlew :SecureOverlay:connectedDebugAndroidTest --console=plain'

# Збірка підписаних production APK для всіх архітектур
./gradlew :TMessagesProj_App:assembleAfatRelease --console=plain
```

---

## Статус аудиту безпеки

> [!WARNING]
> Fork-Secure є бета-версією для тестування та досліджень. Статус незалежного криптографічного аудиту залишається **`CHANGES REQUIRED`** (див. [`docs/protocol-review/REVIEW-DECISION.md`](docs/protocol-review/REVIEW-DECISION.md)). Не покладайтеся на цей клієнт для передачі критично конфіденційних даних до завершення офіційного аудиту.
