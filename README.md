# iam-service

OAuth 2.1 / OpenID Connect authorization server для ERP Lite: выдаёт токены клиентам
приложения (SPA, mobile, интеграторы) и принимает решение о доступе для Nginx через
`auth_request`.

| Компонент | Технология | Роль |
|---|---|---|
| HTTP / протокол | Go 1.25, Gin | `/oauth/*`, `/.well-known/*`, `/login`, `/consent`, `/verify` |
| Пользователи, клиенты, аудит | PostgreSQL 16 + pgx + goose | Источник истины по учётным записям и регистрации клиентов |
| Сессии, коды, refresh-семейства, лимиты | Redis 7 | Быстрое состояние с TTL, немедленный отзыв |
| Подпись токенов | RS256 + JWKS | Клиенты и бэкенды проверяют подпись по `kid` |
| Шлюз | Nginx (`auth_request`) | Аутентификация на входе, инъекция `X-User-*` в бэкенды |

Полное описание протокола — в [`docs/oauth.md`](docs/oauth.md), план и принятые
решения — в [`docs/plan3.md`](docs/plan3.md).

## Быстрый старт

```bash
cp .env.example .env          # только для запуска вне Docker
scripts/dev-up.sh             # поднимает стек, применяет миграции, сидирует клиентов
```

Скрипт печатает сгенерированный пароль администратора и `client_secret`
интеграционного клиента — сохраните их. Дальше:

```bash
BASE_URL=http://localhost:8088 \
EMAIL=admin@erplite.local \
PASSWORD='<пароль из вывода dev-up.sh>' \
./scripts/smoke-oauth.sh
```

`smoke-oauth.sh` проходит весь цикл через Nginx, включая негативные проверки:
повторное использование кода, неверный `code_verifier`, повтор refresh-токена
(отзыв всей цепочки), доступ к `/api` без токена, `/verify` снаружи и защита от
подбора пароля.

Что поднимается на `docker compose -f deployments/docker-compose.yaml up`:

| Сервис | Порт на хосте | Назначение |
|---|---|---|
| nginx | 8088 | Единая точка входа (issuer в dev: `http://localhost:8088`) |
| iam | — (только внутри сети) | Сам сервис, публичный 8080 и админский 9090 |
| postgres | 5432 | База |
| redis | 6379 | Состояние сессий и лимитов |
| backend | — | demo echo-сервис за `auth_request` |

## Демо-клиент в браузере

Чтобы пройти весь цикл мышкой (PKCE → вход → согласие → токены → защищённый API),
откройте после `scripts/dev-up.sh`:

```
http://localhost:8088/demo/
```

Страница — обычный публичный OAuth-клиент `erplite-demo-spa` (PKCE, без секрета,
`require_consent = true`, `redirect_uri = http://localhost:8088/demo/callback`).
Она показывает `code_verifier`/`code_challenge`, декодированные claims `access_token`
и `id_token`, ответы `/oauth/userinfo` и `/api/ping` (с заголовками, которые добавил
Nginx), а также умеет:

* **обновить** токен (ротация refresh с показом новой пары);
* **повторить старый refresh** — в первые 10 секунд вернётся та же пара, позже
  сервис ответит `invalid_grant` и отзовёт всю цепочку, после чего и access-токен
  перестанет проходить `/verify`;
* **выйти** (`POST /oauth/logout`) и убедиться, что токен сразу перестал работать.

Статика лежит в `deployments/demo/` и монтируется в Nginx только для локального
стенда (`./demo:/usr/share/nginx/demo:ro`), отдаётся с CSP и `Cache-Control: no-store`.
Это инструмент отладки: страница печатает токены в открытом виде, поэтому в
production её публиковать не нужно — удалите монтирование из
`deployments/docker-compose.yaml` и блок `/demo/` из `deployments/nginx/nginx.conf`.

## Основные команды

```bash
make help              # список целей
make build             # bin/iam-service и bin/echo-backend
make test              # unit-тесты
make test-integration  # интеграционные тесты (нужны Postgres и Redis)
make up / make down    # стек целиком
make seed              # создать администратора и dev-клиентов
make smoke             # сквозная проверка OAuth-цикла
make demo              # открыть демо-клиент в браузере
make keys              # сгенерировать RS256-ключ подписи
make migrate-status    # состояние миграций
```

Если Docker CLI настроен на удалённый контекст, а демон локальный:

```bash
DOCKER_HOST=unix:///var/run/docker.sock make up
```

## CLI сервиса

```bash
iam-service serve   [--migrate-on-start]     # HTTP-сервер
iam-service migrate [up|down|status]         # миграции (goose, встроены в бинарник)
iam-service seed    [--force]                # администратор + dev-клиенты
iam-service keys    generate --path <file>   # RS256-ключ (PEM, 0600)
iam-service version
```

## Конфигурация

`CONFIG_PATH` (по умолчанию `configs/config.yaml`) плюс переопределение через
переменные окружения: ключ `redis.addr` → `REDIS_ADDR`, `database.dsn` →
`DATABASE_URL` и так далее. Значения по умолчанию — в
[`configs/config.yaml`](configs/config.yaml).

Ключевые настройки:

| Ключ | По умолчанию | Смысл |
|---|---|---|
| `oauth.issuer_url` | `http://localhost:8088` | `iss` токенов; в production обязателен https |
| `oauth.signing_key_path` | `/var/lib/iam/keys/signing.pem` | Приватный ключ; в dev генерируется, в prod обязателен |
| `oauth.access_ttl` | `10m` | Время жизни access-токена |
| `oauth.refresh_ttl` / `refresh_absolute_ttl` | `720h` / `2160h` | Простой и абсолютный срок жизни цепочки refresh |
| `oauth.refresh_replay_grace` | `10s` | Окно идемпотентного повтора refresh |
| `redis.fail_closed` | `true` | Недоступность Redis → `/verify` отказывает (через Nginx — 503) |
| `ratelimit.*` | 5/15m на аккаунт, 20/15m на IP | Защита от подбора пароля |

Секретов в конфиге нет: ключ подписи — файл, пароли пользователей — bcrypt,
секреты клиентов — SHA-256, refresh-токены хранятся только в виде хеша.

## Архитектура

```
cmd/iam-service        точка входа и подкоманды
cmd/echo               demo-бэкенд для проверки auth_request
internal/api           маршруты, middleware, страницы, /verify
internal/api/oauth     протокольные эндпойнты (authorize, token, userinfo, revoke)
internal/service       доменная логика: логин, гранты, сессии, OIDC, клиенты
internal/repository    pgx-репозитории и Redis-хранилище состояния
internal/pkg/{jwt,password,errors}
internal/web           встроенные HTML-шаблоны
pkg/observability      zap, Prometheus, healthz/readyz
migrations             SQL-миграции goose (встроены через embed)
```

Принятые решения, отличающие сервис от «просто логина с JWT»:

* **PKCE обязателен** для всех клиентов, только `S256`; `plain`, `implicit` и ROPC
  не поддерживаются.
* **Одна сессия — одно refresh-семейство.** Обмен refresh-токена одноразовый; при
  повторе старого токена (вне 10-секундного окна ретраев) отзывается вся цепочка.
* **Отзыв немедленный:** решение принимается не только по подписи, но и по наличию
  сессии в Redis, поэтому access-токен умирает сразу после logout.
* **`/verify` fail-closed:** недоступность Redis/Postgres не превращается в
  разрешение; Nginx отдаёт клиенту 503.
* **Аудит в Postgres:** каждое событие аутентификации фиксируется
  (`auth_events`), секреты и токены туда не попадают.

## Наблюдаемость

* `/healthz` — liveness (доступен и через Nginx).
* `/readyz` — readiness с проверкой Postgres и Redis (админский порт 9090).
* `/metrics` — Prometheus **только** на админском порту; Nginx отдаёт 404.
  Метрики: `iam_http_requests_total`, `iam_http_request_duration_seconds`,
  `iam_token_issued_total{grant_type,client_id}`, `iam_token_failures_total{error}`,
  `iam_verify_total{result}`, `iam_refresh_reuse_detected_total`,
  `iam_active_sessions`, `iam_login_attempts_total{result}`.
* Логи — структурированные (zap, JSON в production) с `request_id` из Nginx.

## Разработка

```bash
make lint              # gofmt + go vet
make test              # unit
make test-integration  # против реальных Postgres и Redis
make fmt
```

Тесты, требующие инфраструктуры, помечены build-тегом `integration` и читают
`TEST_DATABASE_URL` / `TEST_REDIS_ADDR`.

## Что сознательно вне v1

Административного HTTP API, CRUD пользователей, самостоятельной регистрации
OAuth-клиентов, MFA, восстановления пароля по e-mail и мультитенантности нет:
пользователи и клиенты провижнятся командой `seed` или SQL. Подробнее — раздел
«Явные допущения» в [`docs/plan3.md`](docs/plan3.md).

## Эксплуатационные заметки

* Redis обязателен в режиме `maxmemory-policy noeviction` и с `appendonly yes`:
  вытеснение ключа сессии выглядит как самопроизвольный выход пользователя.
* Ключ подписи (`signing_key_path`) — файл с правами `0600`, вне git. Ротация:
  положить новый ключ рядом (каталог с `*.pem`) — сервис подписывает самым свежим,
  а старые ключи продолжают проверяться и публикуются в JWKS.
* Production не стартует без ключа, без https-issuer и с некорректными сроками
  жизни токенов: проверка выполняется при загрузке конфигурации.
