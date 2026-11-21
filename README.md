# Ecosystem Auth Service

Отдельный центральный сервис аккаунтов для независимых сайтов экосистемы. Это не часть сайта «Все проекты» и не требует встраивать остальные инструменты в его кодовую базу.

## Что реализовано

- Регистрация по email и паролю с подтверждением адреса.
- Вход в NEXORA ID по одноразовому шестизначному коду из письма (15 минут), с сохранением входа для OAuth-подключённых сервисов.
- Альтернативный вход по паролю для существующих аккаунтов, выход и восстановление пароля.
- После подтверждения email при регистрации сессия создаётся автоматически.
- Хеширование паролей Argon2id.
- HttpOnly-сессия на домене auth-сервиса.
- OAuth 2.0 Authorization Code + PKCE (S256) для входа с независимых доменов.
- Общий счётчик: первые 3 успешных запроса пользователя на всю экосистему.
- Резервирование запроса и возврат списания, если генерация завершилась ошибкой.
- Начисление общих кредитов по подтверждённому событию оплаты: Mini 200 ₽ / 3 кредита, Pro 500 ₽ / 5 кредитов, Max 1 000 ₽ / 10 кредитов.
- PostgreSQL, Docker Compose, базовые тесты и rate limiting.

## Важно перед публикацией

Сервис не готов к реальному запуску без настроек UniSender Go (API-ключ и подтверждённый адрес отправителя), PostgreSQL, публичного HTTPS-домена и зарегистрированных OAuth-клиентов. Реальный платёжный провайдер ещё не подключён: endpoint начисления кредитов принимает только серверный webhook с секретом, но не создаёт платёжные ссылки и не проверяет платёж у банка. Не выставляйте тестовый endpoint в интернет до настройки webhook-подписей/секретов и HTTPS.

## Развёртывание на Render (первый этап)

В репозитории есть `render.yaml` для Render Blueprint. Он создаёт отдельный Web Service и PostgreSQL. Для первого тестового развёртывания заданы бесплатные планы. Бесплатная база Render имеет ограничения и не подходит для хранения реальных пользовательских аккаунтов на постоянной основе; перед публичным запуском нужно выбрать постоянный тариф PostgreSQL и настроить резервное копирование. Не подключайте реальные платежи к тестовому развёртыванию.

1. Создайте **отдельный приватный GitHub-репозиторий** для этого проекта и загрузите в него содержимое архива. Не помещайте файлы в репозиторий `vse-proekty-ian`.
2. В Render выберите **New → Blueprint**, подключите новый репозиторий и проверьте ресурсы из `render.yaml` до подтверждения. Blueprint не должен менять существующий сайт.
3. После создания сервиса откройте Environment и задайте `AUTH_PUBLIC_URL` как выданный Render адрес `https://...onrender.com`.
4. Заполните `UNISENDER_API_KEY` и `UNISENDER_FROM_EMAIL` данными UniSender Go. `UNISENDER_FROM_EMAIL` должен быть адресом на подтверждённом домене отправки с активными SPF/DKIM. API работает по HTTPS через `UNISENDER_API_URL` (по умолчанию `https://goapi.unisender.ru/ru/transactional/api/v1`), а не через SMTP. Для тестов можно включить `UNISENDER_USE_SANDBOX=true`: сервис автоматически получит sandbox-домен API. С него можно отправлять только на вручную подтверждённые адреса; для публичной регистрации выключите тестовый режим и укажите собственный подтверждённый домен. Без почтовой настройки регистрация с подтверждением email не завершится. Не добавляйте ключ в GitHub.
5. На первом этапе оставьте `OAUTH_CLIENTS_JSON=[]`: сайты ещё не зарегистрированы как OAuth-клиенты.
6. Проверьте `/health`, регистрацию тестового аккаунта, письмо с кодом, подтверждение, вход и восстановление пароля. Используйте только тестовую почту.
7. До подключения реальных пользователей замените бесплатную базу на постоянную PostgreSQL, включите резервные копии, проверьте восстановление и настройте мониторинг.

`autoDeploy: false` оставлен намеренно: изменения не будут автоматически публиковаться при каждом push. Запуск миграций выполняется перед стартом сервиса; SQL миграция использует `IF NOT EXISTS`.

## Второй этап: перенос генерации на Mac

Центральная авторизация останется отдельным постоянно доступным сервисом на Render. Позже на MacBook можно разместить только вычислительные backend-сервисы генерации, а не базу аккаунтов и не SMTP. Подключение генераторов будет идти через защищённый API с отдельными ключами сервисов. Если Mac выключен, вход и управление аккаунтом останутся доступны, но генерация на Mac будет временно недоступна.

## Локальный запуск

1. Установите Node.js 22+ и Docker.
2. Скопируйте `.env.example` в `.env`.
3. В `.env` задайте `DATABASE_URL`, параметры UniSender Go API (`UNISENDER_API_KEY`, `UNISENDER_FROM_EMAIL`, при необходимости `UNISENDER_API_URL`), `TOKEN_PEPPER` и `OAUTH_CLIENTS_JSON`. Для каждого сайта укажите отдельные `clientId`, `clientSecret`, `serviceApiKey` и точные callback URL.
4. Запустите `docker compose up --build`.
5. В отдельном терминале выполните миграцию: `npm install && npm run migrate` (команда подключается к адресу БД из `.env`; при запуске с хоста используйте `localhost:5432`).
6. Откройте `http://localhost:4000/login`.

## Подключение «Все проекты #Ian» к NEXORA ID

Для сайта генератора предусмотрен OAuth-клиент `projects-ian`. Его можно зарегистрировать, не меняя существующий объект NEXORA в `OAUTH_CLIENTS_JSON`.

В Render у центрального сервиса `ecosystem-auth-service` добавьте:

- `PROJECTS_OAUTH_CLIENT_SECRET` — случайная строка не короче 32 символов.
- `PROJECTS_SERVICE_API_KEY` — другая случайная строка не короче 32 символов.
- `PROJECTS_REDIRECT_URI` — `https://vse-proekty-ian-1.onrender.com/auth/callback`.

В Render у сервиса сайта «Все проекты #Ian» добавьте:

- `AUTH_PUBLIC_URL=https://ecosystem-auth-service.onrender.com`
- `OAUTH_CLIENT_ID=projects-ian`
- `OAUTH_CLIENT_SECRET` — то же значение, что `PROJECTS_OAUTH_CLIENT_SECRET` у центрального сервиса.
- `PROJECT_SESSION_SECRET` — отдельная случайная строка не короче 32 символов.
- `APP_URL=https://vse-proekty-ian-1.onrender.com`

Не используйте один и тот же секрет для `PROJECTS_SERVICE_API_KEY` и `PROJECT_SESSION_SECRET`. Секреты не добавляйте в GitHub и не отправляйте в переписке. После сохранения переменных перезапустите оба Render-сервиса. Центральный сервис зарегистрирует OAuth-клиент автоматически при старте.

Кнопка входа генератора открывает центральную страницу NEXORA ID. После входа пользователь возвращается на исходный сайт; имя и email доступны сайту через подписанную HttpOnly-сессию. Выход завершает центральную сессию и возвращает пользователя на сайт.

## OAuth-подключение отдельного сайта

1. На сервере сайта создайте случайные `state` и `code_verifier` (43–128 символов), а также `code_challenge = BASE64URL(SHA256(code_verifier))`.
2. Перенаправьте браузер на:

   ```text
   AUTH_PUBLIC_URL/oauth/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_EXACT_CALLBACK&state=YOUR_RANDOM_STATE&code_challenge=YOUR_CHALLENGE&code_challenge_method=S256
   ```

3. На callback сервер сайта проверяет `state` и меняет `code` на профиль через `POST /oauth/token` с `application/x-www-form-urlencoded`: `grant_type=authorization_code`, `client_id`, `client_secret`, `redirect_uri`, `code`, `code_verifier`.
4. Получив `user.id`, сайт создаёт собственную безопасную сессию. Не передавайте `clientSecret` браузеру.

Пример `OAUTH_CLIENTS_JSON`:

```json
[
  {
    "clientId": "text-studio",
    "clientSecret": "REPLACE_WITH_32_PLUS_RANDOM_CHARACTERS",
    "serviceApiKey": "REPLACE_WITH_ANOTHER_32_PLUS_RANDOM_CHARACTERS",
    "redirectUris": ["https://text.example.com/auth/callback"]
  }
]
```

## Общие лимиты

Сервис сайта после успешной OAuth-авторизации получает `user.id`. Перед генерацией он вызывает `POST /v1/internal/usage/reserve` с заголовками `x-service-id` и `x-service-api-key` и телом `{ "userId": "...", "idempotencyKey": "уникальный-id-запроса" }`. Если генерация завершилась, сайт вызывает `/v1/internal/usage/:reservationId/finalize` с `{ "outcome": "success" }`; при сбое передаёт `failure`, и кредит возвращается. Такой учёт общий для всех `clientId`.

## Выдача оплаченных кредитов

Платёжный адаптер после подтверждения оплаты сервером вызывает `POST /v1/internal/payments/grant` с заголовком `x-payment-webhook-secret` и телом `{ "eventId": "уникальный-id-платежа", "userId": "UUID", "packageId": "mini|pro|max", "amountRub": 200 }`. `eventId` идемпотентный. Этот endpoint не заменяет интеграцию с банком и должен вызываться только доверенным backend.

## API

- `GET /health`
- `POST /v1/auth/register`
- `POST /v1/auth/send-login-code`
- `POST /v1/auth/verify-login-code`
- `POST /v1/auth/verify-email`
- `POST /v1/auth/resend-verification`
- `POST /v1/auth/login`
- `POST /v1/auth/logout`
- `POST /v1/auth/forgot-password`
- `POST /v1/auth/reset-password`
- `GET /v1/me`
- `GET /logout`
- `GET /oauth/authorize`
- `POST /oauth/token`
- `GET /v1/internal/users/:userId/summary`
- `POST /v1/internal/usage/reserve`
- `POST /v1/internal/usage/:reservationId/finalize`
- `POST /v1/internal/payments/grant`

## Проверки

```bash
npm install
npm run check
npm test
```

Для production также добавьте почасовую очистку истёкших `sessions`, `oauth_codes` и `email_tokens`, централизованный rate-limit store (например, Redis) при нескольких экземплярах, мониторинг и резервные копии PostgreSQL.
