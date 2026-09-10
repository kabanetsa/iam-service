# IAM Service как OAuth 2.1 / OIDC Authorization Server (plan3)

> Статус: этапы 0–7 выполнены (код, миграции, инфраструктура, тесты, сквозная проверка).
> Заменяет собой `plan.md` и `plan2.md` в части протокола аутентификации.
>
> Реализовано: OAuth 2.1 Authorization Code + PKCE (S256), Refresh Token с ротацией
> и reuse-detection, Client Credentials, OIDC (`id_token`, `/userinfo`, discovery,
> JWKS), RS256/JWKS, `/verify` для Nginx `auth_request`, лимиты и анти-брутфорс на
> Redis, аудит в Postgres, метрики Prometheus, unit- и интеграционные тесты,
> `scripts/smoke-oauth.sh` (сквозная проверка всех потоков и негативных сценариев).
>
> Отличия от плана, зафиксированные по ходу реализации:
> * в схему `users` добавлена колонка `display_name` (нужна для scope `profile`);
> * refresh-токены — непрозрачные (`rt_...`), а не JWT: они всегда проверяются на сервере;
> * сессии и refresh-семейства создаются в момент обмена кода (брошенный логин не оставляет состояния);
> * `/verify` отвечает только 401/200 (Nginx понимает лишь 2xx/401/403), а причина
>   «зависимость недоступна» передаётся заголовком `X-Auth-Reason`, который Nginx
>   превращает в 503 для клиента;
> * от cookie-режима для клиентов отказались: только Bearer (клиенты получают токены по code-flow).

## 1. Что берём из plan.md / plan2.md и что отбрасываем

Оба плана описывают **не OAuth, а «логин по паролю + свой JWT»** (grep по `oauth|oidc|pkce|jwks|introspect` в `docs/` — 0 совпадений). Конкретные дефекты, которые новый план устраняет:

| Из плана | Берём | Отбрасываем и почему |
|---|---|---|
| `plan.md` | Структуру `cmd/internal/{api,service,repository,model,pkg}`, Gin, Viper, Zap, Prometheus, Nginx `auth_request`, graceful shutdown, таймауты сервера | HS256 с симметричными секретами (нельзя отдать JWKS клиентам и внешним RS); GORM + авто-миграции (непрозрачная схема); `POST /auth/login`, выдающий токены напрямую (нет стандартного OAuth-потока) |
| `plan.md` код | Идею `Session` в Redis + хеш refresh | `refresh:<userID>` — **один refresh на пользователя**, ломает мультидевайс и ротацию; `VerifyToken` не смотрит в Redis → **отзыв токена невозможен**; `RefreshAccessToken` не имеет конструктора/`ctx`, а `defer redis.Del(lockKey)` может снять чужой лок после истечения TTL 5s (нужен compare-and-delete через Lua); `cleanupExpiredSessions` — SCAN по `user_sessions:*` на каждом тике, O(все пользователи) |
| `plan2.md` | `pgx/pgxpool`, `goose` + SQL-миграции, явный SQL, отказ от ORM, `http.Server` с таймаутами | `generateTokenID()` из `time.Now().UnixNano() >> (i*8)` — **не криптослучайный** jti/session id; `slog` вместо Zap (выбран Zap); ручной парсинг форм/валидация |

Итоговый стек: **Gin + pgx/pgxpool + goose + Redis 7 + Viper + Zap + Prometheus**. GORM и OpenTelemetry из `go.mod` удаляются (в v1 не нужны, тянут транзитивные зависимости).

## 2. Цель и критерии успеха

**Цель:** сервис — OAuth 2.1/OIDC Authorization Server для клиентов ERP Lite (SPA, mobile, интеграторы) и точка принятия решений для Nginx (`auth_request`) для всех внутренних бэкендов. Пользователи/профили — в Postgres, сессии/коды/счётчики — в Redis.

**Критерии успеха (проверяемые):**
1. `go build ./... && go vet ./... && go test ./...` — зелёные; сборка перестаёт падать на пустых файлах скелета.
2. `docker compose -f deployments/docker-compose.yaml up` поднимает Postgres 16 + Redis 7 + iam + Nginx; `scripts/smoke-oauth.sh` проходит полный **authorization_code + PKCE** цикл (verifier/challenge → `/authorize` → code → `/token` → access+refresh+id_token), затем `GET /api/ping` через Nginx: 200 + `X-User-ID`, без токена — 401 с `WWW-Authenticate: Bearer`.
3. `/.well-known/openid-configuration` отдаёт issuer/endpoints/`jwks_uri`; `id_token` валидируется **независимой библиотекой** (`github.com/coreos/go-oidc/v3`, только в тестах) по опубликованному JWKS.
4. Повторное использование старого refresh: второй обмен → `invalid_grant`, **вся цепочка семейства отзывается**, ранее выданные access-токены перестают проходить `/verify`.
5. 5 неудачных логинов с одного IP/аккаунта → 429 + запись в `auth_events`; ни один пароль/токен не попадает в лог.
6. Прод-режим не стартует с dev-ключами, отсутствующим `issuer_url` или плейсхолдерными секретами (fail-fast в config).

## 3. Архитектура и потоки

```
Browser/SPA ──HTTPS──▶ Nginx ──/oauth/*,/login──▶ iam-service ──▶ Postgres (users, clients, audit)
                         │                              └─────▶ Redis (session, code, refresh family, rate limit)
                         └──auth_request /_verify──▶ iam-service  (200 + X-User-ID/X-Scopes/X-Session-ID | 401)
                         └──/api/*──▶ backend-сервисы (получают X-User-* от Nginx)
```

**Поток A. Authorization Code + PKCE (SPA/mobile):**
`GET /authorize?response_type=code&client_id&redirect_uri&scope&state&code_challenge&code_challenge_method=S256&nonce`
→ валидация клиента и точного совпадения `redirect_uri` → создаём **interaction** в Redis (`iam:interaction:<id>`, TTL 15m) → 302 на `/login?interaction=<id>` → POST `/login` (пароль, CSRF, rate limit, аудит) → при `require_consent` шаг `/consent` → генерация code (хранится в Redis хешем, TTL 60s, **single-use**) → 302 на `redirect_uri?code&state`.
`POST /token` (`grant_type=authorization_code`) → проверка client auth + `code_verifier` (S256) + `redirect_uri` → access (RS256, TTL 10m, claims `sub/sid/jti/scope/aud/iss/exp/iat/auth_time`) + id_token (если `openid`) + refresh (если `offline_access`).

**Поток B. Refresh с ротацией и reuse-detection:** у каждого логина своё **семейство** `family_id`, привязанное к `sid`. Обмен → новый refresh, старый хеш помечается использованным. Приход использованного хеша → удаление `iam:session:<sid>` и всего семейства → все access-токены с этим `sid` сразу невалидны на `/verify`.

**Поток C. Client Credentials:** `POST /token` с `grant_type=client_credentials` для интеграторов; токен без `sid`, `sub = client_id`, TTL 5m; отзыв — через disable клиента (≤ TTL).

**Поток D. Nginx verify:** на каждый запрос к защищённой зоне — subrequest на внутренний `GET /verify`: подпись RS256 + `kid` из JWKS + **наличие `iam:session:<sid>` в Redis** (сразу видно отзыв) + `users.status='active'` (кэш в Redis `iam:userstatus:<uid>` TTL 60s, чтобы не ходить в PG на каждый запрос). Для M2M-токенов сессия не требуется.

**Поток E. OIDC:** `/userinfo` по access-токену, `id_token` с `nonce`/`auth_time`, `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/revoke` (RFC 7009), `/oauth/logout` + `end_session` (logout everywhere через ZSET сессий пользователя).

## 4. Структура проекта

```
cmd/iam-service/main.go                  subcommands: serve | migrate | seed | keys generate
internal/config/config.go                + OAuth, Issuer, Keys, TTL, RateLimit, Cookie, TrustedProxies
internal/model/{user,session,token,client,audit}.go
internal/repository/{postgres,user_repo,client_repo,audit_repo,redis_client,session_repo,ratelimit_repo}.go
internal/service/{auth_service,token_service,grant_service,client_service,session_service,oidc_service}.go
internal/api/routes.go
internal/api/handlers/{auth,middleware,session,web}.go        # verify для Nginx, HTML login/consent
internal/api/oauth/{authorize,token,userinfo,jwks,discovery,revoke}.go
internal/pkg/jwt/       keyring, sign/verify, kid (RFC 7638)
internal/pkg/password/  bcrypt cost 12, constant-time compare, rehash-on-login
internal/pkg/errors/    OAuth-ошибки (RFC 6749 §5.2) → HTTP/JSON
internal/web/templates/{login,consent,error}.html
pkg/observability/      zap, Prometheus, healthz/readyz
migrations/000{1..4}_*.sql
deployments/{docker-compose.yaml,Dockerfile,nginx/nginx.conf}
scripts/{smoke-oauth.sh,test-env.sh}
Makefile, .env.example, .env.example
```

## 5. API-контракты

| Метод | Путь | Доступ | Назначение |
|---|---|---|---|
| GET | `/oauth/authorize` | публично | Начало code-flow, создаёт interaction |
| POST | `/oauth/token` | client auth | `authorization_code`, `refresh_token`, `client_credentials`; `application/x-www-form-urlencoded` |
| GET | `/oauth/userinfo` | Bearer | OIDC-профиль по scope |
| POST | `/oauth/revoke` | client auth | RFC 7009 |
| POST | `/oauth/logout` | Bearer | Текущая сессия |
| POST | `/api/v1/sessions/logout-all` | Bearer | Все сессии пользователя |
| GET | `/.well-known/openid-configuration` | публично | Discovery |
| GET | `/.well-known/jwks.json` | публично | Открытые ключи, `Cache-Control: max-age=3600` |
| GET | `/oauth/end_session` | Bearer/cookie | RP-initiated logout |
| GET | `/verify` | только internal (Nginx) | 200 + `X-User-ID`, `X-User-Scopes`, `X-Session-ID`, `X-Client-ID`; 401 + `WWW-Authenticate` |
| GET/POST | `/login`, `/consent` | публично | HTML-формы, CSRF |
| GET | `/healthz`, `/readyz`, `/metrics` | internal-порт 9090 | Пробы и метрики (в Nginx не публикуются) |

Ошибки — RFC 6749 §5.2 / RFC 9457: `{"error":"invalid_grant","error_description":"..."}`; `invalid_client` → 401, `invalid_request` → 400, `server_error` → 500, rate limit → 429 + `Retry-After`. `Cache-Control: no-store` на всех ответах `/token`.

## 6. Данные

**Postgres (goose, 4 миграции):**
```sql
CREATE EXTENSION IF NOT EXISTS citext;
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email citext NOT NULL UNIQUE,
  email_verified boolean NOT NULL DEFAULT false,
  password_hash text NOT NULL,
  status text NOT NULL DEFAULT 'active',         -- active|disabled|locked
  failed_logins int NOT NULL DEFAULT 0,
  locked_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE TABLE roles (name text PRIMARY KEY);
CREATE TABLE user_roles (user_id uuid REFERENCES users(id) ON DELETE CASCADE,
                         role text REFERENCES roles(name), PRIMARY KEY(user_id, role));
CREATE TABLE oauth_clients (
  client_id text PRIMARY KEY,
  client_secret_hash text,                        -- NULL для public (PKCE)
  name text NOT NULL,
  is_public boolean NOT NULL DEFAULT false,
  token_endpoint_auth_method text NOT NULL DEFAULT 'client_secret_basic',
  redirect_uris text[] NOT NULL DEFAULT '{}',
  allowed_scopes text[] NOT NULL DEFAULT '{openid}',
  grant_types text[] NOT NULL DEFAULT '{authorization_code,refresh_token}',
  require_consent boolean NOT NULL DEFAULT false, -- first-party = false
  access_token_ttl_seconds int, refresh_token_ttl_seconds int,
  disabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE auth_events (
  id bigserial PRIMARY KEY, event_type text NOT NULL, user_id uuid, client_id text,
  session_id text, ip inet, user_agent text, success boolean NOT NULL, error_code text,
  request_id text, created_at timestamptz NOT NULL DEFAULT now()
);
```
Обращения — явный SQL через pgx (`pgx.CollectOneRow(rows, pgx.RowToStructByName[model.User])`), GORM не нужен.

**Redis (префикс `iam:`):**

| Ключ | Значение | TTL |
|---|---|---|
| `iam:session:<sid>` | JSON сессии (user_id, client_id, family_id, auth_time, ip, ua) | refresh TTL |
| `iam:user_sessions:<uid>` | ZSET `sid` → score = unix-время истечения | refresh TTL |
| `iam:code:<sha256(code)>` | JSON кода (client_id, uid, redirect_uri, scope, challenge, method, nonce, sid, auth_time) | 60s, single-use |
| `iam:interaction:<id>` | JSON незавершённого `/authorize` | 15m |
| `iam:rf:current:<family_id>` | хеш текущего refresh | до absolute cap |
| `iam:rf:used:<sha256(old)>` | `family_id` (reuse detection) | absolute cap |
| `iam:rf:replay:<sha256(old)>` | JSON последней выданной пары (grace) | 10s |
| `iam:userstatus:<uid>` | `active`/`disabled` | 60s |
| `iam:rl:*` | счётчики окна | окно |
| `iam:lock:refresh:<family_id>` | случайное значение | 5s |

Лимиты: логин — 5/15m на аккаунт и 20/15m на IP; `/token` — 60/1m на client_id; `/authorize` — 120/1m на IP.

## 7. Безопасность

- **Ключи:** RS256, RSA-2048, PEM из файла/секрета, `kid` = RFC 7638 thumbprint; keyring поддерживает ротацию; в dev — генерация с WARN, в prod — fail-fast.
- **PKCE:** только `S256`, обязателен для всех клиентов; `code_verifier` 43–128.
- **redirect_uri:** точное совпадение, без wildcard/фрагментов; http только для localhost.
- **client_secret:** SHA-256 от high-entropy секрета, `subtle.ConstantTimeCompare`; `client_secret_basic|post|none`.
- **Пароли:** bcrypt cost 12, dummy-compare при отсутствии пользователя, rehash-on-login.
- **CSRF:** signed double-submit cookie на `/login` и `/consent`.
- **Cookie:** `__Host-iam_session` (`Secure`, `HttpOnly`, `SameSite=Lax`).
- **Логи:** без паролей, `code`, refresh, `Authorization`, `client_secret`; `request_id` из Nginx.
- **Fail-closed:** Redis недоступен → `/verify` 503, `/token` 503 `temporarily_unavailable`; Postgres недоступен → `/token` 503, `/verify` продолжает работать.
- **Аудит:** `login_success`, `login_failure`, `account_locked`, `rate_limited`, `code_issued`, `code_reused`, `token_issued`, `token_refreshed`, `refresh_reuse_detected`, `client_auth_failure`, `logout`, `consent_denied`.

## 8. Интеграция с Nginx

```nginx
location = /_verify {
  internal;
  proxy_pass http://iam:8080/verify;
  proxy_pass_request_body off;
  proxy_set_header Content-Length "";
  proxy_set_header X-Original-URI $request_uri;
  proxy_set_header X-Request-ID $request_id;
}
location /api/ {
  auth_request /_verify;
  auth_request_set $uid $upstream_http_x_user_id;
  proxy_set_header X-User-ID $uid;
  proxy_set_header Authorization "";
  error_page 401 = @api_unauthorized;
  proxy_pass http://backend;
}
location /app/ { auth_request /_verify; error_page 401 = @web_login; }
location = /metrics { deny all; }
```

## 9. Этапы

| # | Этап | Готово, когда |
|---|---|---|
| 0 | Гигиена сборки: go.mod, Makefile, `.env.example`, Dockerfile | `go build ./... && go vet ./...` зелёные |
| 1 | Инфраструктура: compose, config, zap, pgxpool, миграции 0001–0003, `serve/migrate/seed`, healthz/readyz | `migrate up` создаёт схему; `/readyz` 200/503 |
| 2 | Ключи, JWT, JWKS, discovery | JWKS валиден; `alg:none` отклоняется; prod fail-fast |
| 3 | Логин и `/authorize`: interaction, login/consent, CSRF, лимиты, аудит, code | цикл до редиректа с `code`; 6-я попытка → 429 |
| 4 | `/token`: 3 grant'а, ротация refresh, reuse-detection, id_token | тесты ротации и отзыва семейства |
| 5 | `/verify` + Nginx + smoke | `/api/ping` 200 с `X-User-ID`; после logout 401 |
| 6 | `/userinfo`, `/revoke`, logout, logout-all | logout-all инвалидирует все сессии |
| 7 | Метрики, тесты, `docs/oauth.md`, README | unit + integration зелёные |

## 10. Явные допущения и отложенное

Админ-HTTP-API, CRUD пользователей, регистрация OAuth-клиентов и MFA **не входят в v1** — пользователи и клиенты провижнятся миграциями и командой `iam-service seed`. Email-верификация и сброс пароля по SMTP — вне v1. Мультитенантности нет (`tenant_id`/RLS отложены). OTel-трейсинг отложен; `device_code`, `implicit`, ROPC не реализуются. Тестовые зависимости (`go-oidc`, `x/oauth2`, `miniredis`) — только в `_test.go`.

## 11. Крайние случаи

Параллельный refresh одним токеном → лок на family (случайное значение + Lua compare-and-delete), проигравший получает `invalid_grant`; сетевой ретрай сразу после ротации → grace-окно 10s возвращает ту же пару, ложного reuse-detection нет; повторное использование `code` → отзыв семейства; истёкшие `code`/`interaction`/`session` → `invalid_grant`/повторный логин; отключённый пользователь → refresh не проходит, `/verify` отказывает ≤60s; clock skew 60s; `issuer_url` строго из конфига (не из заголовков); Redis `maxmemory-policy noeviction` + `appendonly yes`, иначе сессии вытесняются.
