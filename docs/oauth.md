# OAuth 2.1 / OIDC: как пользоваться сервисом

`iam-service` — это authorization server. Он не хранит бизнес-данные: он выдаёт
токены клиентам приложения и принимает решение «пускать или нет» для Nginx.

```
клиент (SPA / mobile / интегратор)
        │  код авторизации + PKCE
        ▼
   Nginx ──/oauth/*,/login,/consent──▶ iam-service ──▶ Postgres (users, clients, audit)
        │                                    └───────▶ Redis (sessions, codes, refresh families)
        └──auth_request /_verify──▶ iam-service ──200 + X-User-*──▶ backend
```

## Эндпойнты

| Метод | Путь | Назначение |
|---|---|---|
| GET | `/oauth/authorize` | Начало code-flow (создаёт interaction, редиректит на `/login`) |
| POST | `/oauth/token` | `authorization_code` + PKCE, `refresh_token`, `client_credentials` |
| GET | `/oauth/userinfo` | OIDC-claims по access-токену (нужен scope `openid`) |
| POST | `/oauth/revoke` | Отзыв токена (RFC 7009) |
| POST | `/oauth/logout` | Завершить текущую сессию |
| GET | `/oauth/end_session` | RP-initiated logout с `post_logout_redirect_uri` |
| GET | `/.well-known/openid-configuration` | Discovery |
| GET | `/.well-known/jwks.json` | Публичные ключи подписи |
| GET | `/verify` | Внутренний: используется только Nginx (`auth_request`) |
| POST | `/api/v1/sessions/logout-all` | Завершить все сессии пользователя |
| GET | `/login`, `/consent` | Страницы сервиса (HTML) |

## Поток Authorization Code + PKCE

1. Клиент генерирует `code_verifier` (43–128 символов) и
   `code_challenge = BASE64URL(SHA256(code_verifier))`.
2. `GET /oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=openid%20email%20offline_access&state=...&code_challenge=...&code_challenge_method=S256`
   → 302 на `/login?interaction=...`.
3. Пользователь вводит email/пароль на странице сервиса (форма защищена CSRF-токеном,
   привязанным к interaction).
4. Сервис редиректит на `redirect_uri?code=...&state=...`.
5. `POST /oauth/token` (`application/x-www-form-urlencoded`) с
   `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier`.

Ответ:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6...",
  "token_type": "Bearer",
  "expires_in": 600,
  "refresh_token": "rt_...",
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6...",
  "scope": "openid email offline_access"
}
```

Правила, которые важно знать клиенту:

* PKCE обязателен для всех клиентов, поддерживается только `S256`.
* `refresh_token` выдаётся, только если запрошен scope `offline_access` и клиент
  зарегистрирован с grant `refresh_token`.
* `id_token` выдаётся, только если запрошен scope `openid`.
* Каждый refresh-токен одноразовый: обмен возвращает новую пару. Повторная отправка
  того же токена в пределах 10 секунд возвращает ту же пару (идемпотентный ретрай),
  позже — расценивается как кража: отзывается вся цепочка и все access-токены этой
  сессии перестают работать немедленно.

## Машинные токены (client_credentials)

```
curl -u erplite-integration:$CLIENT_SECRET \
     -d grant_type=client_credentials -d 'scope=api.read' \
     https://iam.example.com/oauth/token
```

Токен не привязан к сессии: он живёт 5 минут (по умолчанию) и перестаёт выдаваться
сразу после отключения клиента (`oauth_clients.disabled = true`).

## Claims access-токена

| Claim | Значение |
|---|---|
| `iss` | issuer из конфигурации (`oauth.issuer_url`) |
| `sub` | id пользователя или `client_id` для машинного токена |
| `aud` | `oauth.audience` (по умолчанию `erplite-api`) |
| `exp`, `iat`, `nbf`, `jti` | стандартные |
| `scope` | выданные scope через пробел |
| `client_id` | клиент, получивший токен |
| `sid` | id сессии; отсутствует у машинных токенов |
| `token_use` | `access` (у `id_token` — `id`) |
| `auth_time` | время фактической аутентификации |
| `roles` | роли пользователя |
| `email`, `email_verified`, `name` | только в `id_token`, по scope `email`/`profile` |

Проверять подпись нужно по `kid` из `/.well-known/jwks.json`; алгоритм — только
`RS256`. `id_token` нельзя использовать как access-токен: у него `aud = client_id` и
`token_use = id`, поэтому `/verify` и `/userinfo` его отклонят.

## Отзыв

| Что нужно | Как |
|---|---|
| Выход на одном устройстве | `POST /oauth/logout` с access-токеном |
| Выход везде | `POST /api/v1/sessions/logout-all` |
| Отозвать токены клиента | `POST /oauth/revoke` (RFC 7009), требуется аутентификация клиента |
| Заблокировать пользователя | `UPDATE users SET status='disabled'` — действует ≤ 60 с (кэш статуса) |
| Отключить интеграцию | `UPDATE oauth_clients SET disabled=true` — машинные токены перестают работать ≤ 5 мин |

Access-токен — JWT, но решение всё равно принимается по сессии в Redis: каждый
запрос к защищённой зоне проходит через `/verify`, который проверяет и подпись, и
наличие сессии. Поэтому «немедленный отзыв» здесь не приблизительный, а точный.

## Интеграция с Nginx

```nginx
location = /_verify {
    internal;
    proxy_pass http://iam/verify;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
}

location /api/ {
    auth_request /_verify;
    auth_request_set $uid $upstream_http_x_user_id;
    proxy_set_header X-User-ID $uid;
    proxy_set_header Authorization "";   # наружу токен не уходит
    error_page 401 = @api_unauthorized;
    proxy_pass http://backend;
}
```

`/verify` отвечает `200` и заголовками `X-User-ID`, `X-Client-ID`, `X-Scopes`,
`X-Session-ID`, `X-Auth-Time`, `X-User-Roles` — либо `401` с `WWW-Authenticate`.
Если Redis недоступен, ответ — `503` (fail-closed), чтобы сбой зависимости не
превращался в разрешение.

## Демо-клиент в браузере

Для ручной проверки всего цикла есть готовая страница:

```
http://localhost:8088/demo/
```

Это публичный клиент `erplite-demo-spa` (PKCE, `require_consent = true`,
`redirect_uri = http://localhost:8088/demo/callback`). Она делает ровно то, что
описано выше: генерирует `code_verifier`, считает `code_challenge` через WebCrypto,
уводит на `/oauth/authorize`, показывает экран согласия, обменивает код на токены и
дальше позволяет обновлять токен, вызывать `/oauth/userinfo`, `/api/ping` (через
Nginx) и `/oauth/logout`. Все шаги с ответами сервиса видны в журнале на странице.

Пара предупреждений, которые демонстрирует эта страница:

* `crypto.subtle` доступен только в secure context, поэтому открывать её надо по
  `http://localhost:8088/`, а не по IP-адресу;
* повторный обмен одного и того же refresh-токена вне 10-секундного окна — это
  сигнал кражи: сервис отзовёт всю цепочку, и ранее выданный access-токен тоже
  перестанет работать.

## Проверка вручную

```bash
BASE_URL=http://localhost:8088 EMAIL=admin@erplite.local PASSWORD=... ./scripts/smoke-oauth.sh
```

Скрипт проходит весь цикл, включая негативные сценарии: повторное использование
кода, неверный `code_verifier`, повтор refresh-токена, доступ к `/api` без токена и
защита от подбора пароля.
