# IAM Микросервис на Go: Полное руководство

## 📋 Обзор архитектуры

Ваш IAM микросервис будет выполнять роль **централизованного сервиса аутентификации и управления сессиями**, интегрируясь с Nginx через механизм `auth_request`.

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│    Nginx    │ ← auth_request → IAM Service (проверка JWT)
└──────┬──────┘
       │ (валидный токен)
       ▼
┌─────────────┐
│  Backend    │
│  Services   │
└─────────────┘
```

### Компоненты системы

| Компонент | Технология | Назначение |
|-----------|------------|------------|
| **IAM Service** | Go + Gin | Выдача, проверка, продление JWT, управление сессиями |
| **База пользователей** | PostgreSQL | Хранение учетных данных, профилей пользователей |
| **Хранилище сессий** | Redis | Активные сессии, Refresh токены, черные списки |
| **Gateway** | Nginx + auth_request | Интеграция с IAM на входе запроса |

---

## 🏗️ Архитектура микросервиса

### Слои приложения (стандартная структура Go)

```
iam-service/
├── cmd/
│   └── iam-service/
│       └── main.go                 # Точка входа
├── internal/
│   ├── api/
│   │   ├── handlers/               # HTTP handlers
│   │   │   ├── auth.go
│   │   │   ├── session.go
│   │   │   └── middleware.go
│   │   └── routes.go               # Маршрутизация
│   ├── service/                    # Бизнес-логика
│   │   ├── auth_service.go
│   │   ├── session_service.go
│   │   └── token_service.go
│   ├── repository/                 # Доступ к данным
│   │   ├── user_repo.go
│   │   ├── session_repo.go
│   │   └── redis_client.go
│   ├── model/                      # Модели данных
│   │   ├── user.go
│   │   ├── session.go
│   │   └── token.go
│   └── pkg/                        # Внутренние утилиты
│       ├── jwt/
│       ├── password/
│       └── errors/
├── pkg/                            # Публичные пакеты
│   └── observability/
├── migrations/                     # SQL миграции
├── configs/
│   └── config.yaml
├── deployments/
│   ├── docker-compose.yaml
│   └── nginx/
│       └── nginx.conf
├── scripts/
├── go.mod
└── go.sum
```

### Взаимодействие с Nginx

Nginx использует `auth_request` для делегирования проверки JWT вашему микросервису:

```nginx
location / {
    auth_request /_auth;
    auth_request_set $user_id $upstream_http_x_user_id;
    proxy_set_header X-User-ID $user_id;
    proxy_pass http://backend;
}

location = /_auth {
    internal;
    proxy_pass http://iam-service:8080/auth/verify;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
}
```

---

## 📚 Библиотеки и инструменты

### Основные зависимости

| Назначение | Библиотека | Причина выбора |
|------------|------------|----------------|
| **JWT** | `github.com/golang-jwt/jwt/v5` | Форк jwt-go с исправленными уязвимостями (alg:none, kid injection) |
| **HTTP** | `github.com/gin-gonic/gin` | Высокая производительность, удобные middleware |
| **PostgreSQL** | `gorm.io/gorm` + `gorm.io/driver/postgres` | ORM с миграциями, удобные отношения |
| **Redis** | `github.com/redis/go-redis/v9` | Официальный клиент, поддержка Redis 7+, Pipeline |
| **Конфигурация** | `github.com/spf13/viper` | Поддержка YAML/ENV, watch изменений |
| **Логирование** | `go.uber.org/zap` | Высокая производительность, структурированные логи |
| **Валидация** | `github.com/go-playground/validator/v10` | Теги валидации в структурах |
| **Метрики** | `github.com/prometheus/client_golang` | Экспорт метрик для Prometheus |
| **Трейсинг** | `go.opentelemetry.io/otel` | Стандарт observability |

### Установка

```bash
go mod init iam-service
go get -u github.com/gin-gonic/gin
go get -u github.com/golang-jwt/jwt/v5
go get -u gorm.io/gorm
go get -u gorm.io/driver/postgres
go get -u github.com/redis/go-redis/v9
go get -u go.uber.org/zap
go get -u github.com/spf13/viper
go get -u github.com/prometheus/client_golang/prometheus
go get -u go.opentelemetry.io/otel
```

---

## 🔐 Реализация JWT и сессий

### Структуры данных

```go
// model/user.go
type User struct {
    ID           string    `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
    Email        string    `gorm:"uniqueIndex;not null"`
    PasswordHash string    `gorm:"not null"`
    CreatedAt    time.Time
    UpdatedAt    time.Time
    DeletedAt    gorm.DeletedAt `gorm:"index"`
}

// model/session.go
type Session struct {
    ID           string    `redis:"id"`
    UserID       string    `redis:"user_id"`
    RefreshToken string    `redis:"refresh_token"`
    DeviceID     string    `redis:"device_id"`
    IPAddress    string    `redis:"ip"`
    UserAgent    string    `redis:"user_agent"`
    CreatedAt    time.Time `redis:"created_at"`
    ExpiresAt    time.Time `redis:"expires_at"`
}
```

### Генерация JWT (Access + Refresh)

```go
// service/token_service.go
type TokenService struct {
    accessSecret  []byte
    refreshSecret []byte
    accessTTL     time.Duration
    refreshTTL    time.Duration
    redisClient   *redis.Client
}

type TokenPair struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    ExpiresIn    int64  `json:"expires_in"`
}

func (s *TokenService) GenerateTokenPair(userID string) (*TokenPair, error) {
    // Access Token (15-60 минут)
    accessClaims := &jwt.RegisteredClaims{
        Subject:   userID,
        ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.accessTTL)),
        IssuedAt:  jwt.NewNumericDate(time.Now()),
        Issuer:    "iam-service",
    }
    accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
    accessString, err := accessToken.SignedString(s.accessSecret)
    if err != nil {
        return nil, err
    }

    // Refresh Token (7-30 дней)
    refreshClaims := &jwt.RegisteredClaims{
        Subject:   userID,
        ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.refreshTTL)),
        IssuedAt:  jwt.NewNumericDate(time.Now()),
        ID:        uuid.New().String(), // Уникальный ID для ротации
    }
    refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
    refreshString, err := refreshToken.SignedString(s.refreshSecret)
    if err != nil {
        return nil, err
    }

    // Сохраняем Refresh Token в Redis с хешированием
    hashedRefresh := hashToken(refreshString)
    err = s.redisClient.SetEX(
        context.Background(),
        fmt.Sprintf("refresh:%s", userID),
        hashedRefresh,
        s.refreshTTL,
    ).Err()

    return &TokenPair{
        AccessToken:  accessString,
        RefreshToken: refreshString,
        ExpiresIn:    int64(s.accessTTL.Seconds()),
    }, err
}
```

### Продление Access Token через Refresh Token

Важно реализовать защиту от конкурентных запросов на обновление:

```go
func (s *TokenService) RefreshAccessToken(ctx context.Context, userID, oldRefreshToken string) (*TokenPair, error) {
    // 1. Атомарная блокировка для предотвращения race condition
    lockKey := fmt.Sprintf("refresh:lock:%s", userID)
    ok, err := s.redisClient.SetNX(ctx, lockKey, "1", 5*time.Second).Result()
    if err != nil || !ok {
        return nil, errors.New("refresh already in progress")
    }
    defer s.redisClient.Del(ctx, lockKey)

    // 2. Проверка существующего Refresh Token
    storedHash, err := s.redisClient.Get(ctx, fmt.Sprintf("refresh:%s", userID)).Result()
    if err == redis.Nil {
        return nil, errors.New("no active session")
    }
    if err != nil {
        return nil, err
    }

    if storedHash != hashToken(oldRefreshToken) {
        return nil, errors.New("invalid refresh token")
    }

    // 3. Генерация новой пары токенов (ротация)
    newPair, err := s.GenerateTokenPair(userID)
    if err != nil {
        return nil, err
    }

    // 4. Удаление старого Refresh Token (одноразовое использование)
    // Новый уже сохранен в GenerateTokenPair

    return newPair, nil
}

func hashToken(token string) string {
    hash := sha256.Sum256([]byte(token))
    return hex.EncodeToString(hash[:])
}
```

### Проверка JWT (для Nginx auth_request)

```go
// api/handlers/auth.go
func (h *AuthHandler) VerifyToken(c *gin.Context) {
    // Извлечение токена из заголовка Authorization
    authHeader := c.GetHeader("Authorization")
    if authHeader == "" {
        c.AbortWithStatusJSON(401, gin.H{"error": "missing authorization header"})
        return
    }

    tokenString := strings.TrimPrefix(authHeader, "Bearer ")
    if tokenString == authHeader {
        c.AbortWithStatusJSON(401, gin.H{"error": "invalid token format"})
        return
    }

    // Парсинг и валидация токена
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Проверка алгоритма подписи (защита от alg:none атак)
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return h.tokenService.GetAccessSecret(), nil
    })

    if err != nil || !token.Valid {
        c.AbortWithStatusJSON(401, gin.H{"error": "invalid token"})
        return
    }

    // Извлечение claims
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        c.AbortWithStatusJSON(401, gin.H{"error": "invalid claims"})
        return
    }

    userID, ok := claims["sub"].(string)
    if !ok {
        c.AbortWithStatusJSON(401, gin.H{"error": "missing user id"})
        return
    }

    // Передача user_id в бэкенд через заголовок
    c.Header("X-User-ID", userID)
    c.Status(200)
}
```

---

## 🗄️ Управление сессиями в Redis

### Инициализация и базовые операции

```go
// repository/redis_client.go
func NewRedisClient(cfg *config.RedisConfig) (*redis.Client, error) {
    client := redis.NewClient(&redis.Options{
        Addr:         fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
        Password:     cfg.Password,
        DB:           cfg.DB,
        PoolSize:     cfg.PoolSize,
        MinIdleConns: cfg.MinIdleConns,
        ReadTimeout:  cfg.ReadTimeout,
        WriteTimeout: cfg.WriteTimeout,
    })

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    if err := client.Ping(ctx).Err(); err != nil {
        return nil, err
    }
    return client, nil
}
```

### Создание и удаление сессий

```go
// service/session_service.go
type SessionService struct {
    redisClient *redis.Client
    ttl         time.Duration
}

func (s *SessionService) CreateSession(ctx context.Context, userID, deviceID, ip, userAgent string) (*model.Session, error) {
    session := &model.Session{
        ID:           uuid.New().String(),
        UserID:       userID,
        DeviceID:     deviceID,
        IPAddress:    ip,
        UserAgent:    userAgent,
        CreatedAt:    time.Now(),
        ExpiresAt:    time.Now().Add(s.ttl),
    }

    // Сохранение в Redis с TTL
    key := fmt.Sprintf("session:%s", session.ID)
    data, err := json.Marshal(session)
    if err != nil {
        return nil, err
    }

    err = s.redisClient.SetEX(ctx, key, data, s.ttl).Err()
    if err != nil {
        return nil, err
    }

    // Индекс для поиска сессий пользователя
    userSessionsKey := fmt.Sprintf("user_sessions:%s", userID)
    err = s.redisClient.SAdd(ctx, userSessionsKey, session.ID).Err()
    if err != nil {
        return nil, err
    }
    s.redisClient.Expire(ctx, userSessionsKey, s.ttl)

    return session, nil
}

func (s *SessionService) DeleteSession(ctx context.Context, sessionID string) error {
    // Получение session для user_id
    key := fmt.Sprintf("session:%s", sessionID)
    data, err := s.redisClient.Get(ctx, key).Bytes()
    if err == redis.Nil {
        return nil
    }
    if err != nil {
        return err
    }

    var session model.Session
    if err := json.Unmarshal(data, &session); err != nil {
        return err
    }

    // Удаление сессии и индекса
    pipe := s.redisClient.Pipeline()
    pipe.Del(ctx, key)
    pipe.SRem(ctx, fmt.Sprintf("user_sessions:%s", session.UserID), sessionID)
    _, err = pipe.Exec(ctx)
    
    return err
}
```

### Очистка просроченных сессий

Redis автоматически удаляет ключи с TTL, но для индексов нужна фоновая очистка:

```go
func (s *SessionService) StartCleanupWorker(ctx context.Context, interval time.Duration) {
    ticker := time.NewTicker(interval)
    go func() {
        for {
            select {
            case <-ticker.C:
                s.cleanupExpiredSessions(ctx)
            case <-ctx.Done():
                ticker.Stop()
                return
            }
        }
    }()
}

func (s *SessionService) cleanupExpiredSessions(ctx context.Context) {
    // Поиск ключей session:* без TTL (уже истекшие)
    // Альтернатива: использование Redis Keyspace notifications
    pattern := "user_sessions:*"
    iter := s.redisClient.Scan(ctx, 0, pattern, 100).Iterator()
    
    for iter.Next(ctx) {
        userSessionsKey := iter.Val()
        // Проверка и очистка "мертвых" session_id из множеств
        members := s.redisClient.SMembers(ctx, userSessionsKey).Val()
        for _, sessionID := range members {
            exists, _ := s.redisClient.Exists(ctx, fmt.Sprintf("session:%s", sessionID)).Result()
            if exists == 0 {
                s.redisClient.SRem(ctx, userSessionsKey, sessionID)
            }
        }
    }
}
```

---

## 📊 Логирование, трейсинг и метрики

### Логирование с Zap

```go
// pkg/logger/logger.go
import "go.uber.org/zap"

func NewLogger(cfg *config.LogConfig) (*zap.Logger, error) {
    var config zap.Config
    if cfg.Environment == "production" {
        config = zap.NewProductionConfig()
    } else {
        config = zap.NewDevelopmentConfig()
    }
    
    config.OutputPaths = []string{"stdout", cfg.LogFilePath}
    config.Encoding = "json"
    
    return config.Build()
}

// Использование в middleware
func LoggerMiddleware(logger *zap.Logger) gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        path := c.Request.URL.Path
        
        c.Next()
        
        logger.Info("request completed",
            zap.String("method", c.Request.Method),
            zap.String("path", path),
            zap.Int("status", c.Writer.Status()),
            zap.Duration("latency", time.Since(start)),
            zap.String("client_ip", c.ClientIP()),
        )
    }
}
```

### Метрики с Prometheus

```go
// pkg/metrics/metrics.go
import "github.com/prometheus/client_golang/prometheus"

var (
    httpRequestsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "http_requests_total",
            Help: "Total number of HTTP requests",
        },
        []string{"method", "endpoint", "status"},
    )
    
    httpRequestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "http_request_duration_seconds",
            Help:    "HTTP request duration in seconds",
            Buckets: prometheus.DefBuckets,
        },
        []string{"method", "endpoint"},
    )
    
    activeSessions = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "active_sessions_total",
            Help: "Total number of active sessions",
        },
    )
    
    tokenVerifications = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "token_verifications_total",
            Help: "Total number of token verifications",
        },
        []string{"result"}, // valid, invalid, expired
    )
)

func init() {
    prometheus.MustRegister(httpRequestsTotal, httpRequestDuration, activeSessions, tokenVerifications)
}
```

### Трейсинг с OpenTelemetry

```go
// pkg/tracing/tracing.go
import (
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
    "go.opentelemetry.io/otel/sdk/resource"
    sdktrace "go.opentelemetry.io/otel/sdk/trace"
    semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

func InitTracer(serviceName, otlpEndpoint string) (*sdktrace.TracerProvider, error) {
    exporter, err := otlptracegrpc.New(
        context.Background(),
        otlptracegrpc.WithEndpoint(otlpEndpoint),
        otlptracegrpc.WithInsecure(),
    )
    if err != nil {
        return nil, err
    }
    
    tp := sdktrace.NewTracerProvider(
        sdktrace.WithBatcher(exporter),
        sdktrace.WithResource(resource.NewWithAttributes(
            semconv.SchemaURL,
            semconv.ServiceName(serviceName),
        )),
        sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(0.1))),
    )
    
    otel.SetTracerProvider(tp)
    return tp, nil
}

// Gin middleware для трейсинга
func TracingMiddleware() gin.HandlerFunc {
    tracer := otel.Tracer("iam-service")
    return func(c *gin.Context) {
        ctx := c.Request.Context()
        ctx, span := tracer.Start(ctx, c.Request.URL.Path)
        defer span.End()
        
        span.SetAttributes(
            attribute.String("http.method", c.Request.Method),
            attribute.String("http.url", c.Request.URL.String()),
        )
        
        c.Request = c.Request.WithContext(ctx)
        c.Next()
        
        span.SetAttributes(attribute.Int("http.status_code", c.Writer.Status()))
    }
}
```

---

## 🚀 План разработки

### Этап 1: Базовая инфраструктура (День 1-2)
- [ ] Инициализация Go модуля, структура проекта
- [ ] Docker Compose (PostgreSQL, Redis)
- [ ] Конфигурация через Viper
- [ ] Настройка логирования (Zap)

### Этап 2: Работа с БД и Redis (День 3-4)
- [ ] Миграции БД (gorm)
- [ ] Репозиторий пользователей (CRUD)
- [ ] Подключение к Redis, базовые операции
- [ ] Модели данных

### Этап 3: JWT реализация (День 5-6)
- [ ] Генерация Access/Refresh токенов
- [ ] Валидация токенов
- [ ] Механизм обновления с блокировками
- [ ] Middleware для Gin

### Этап 4: HTTP API (День 7-8)
- [ ] Эндпоинты: `/auth/login`, `/auth/refresh`, `/auth/verify`
- [ ] Валидация запросов
- [ ] Обработка ошибок
- [ ] Интеграция с Nginx auth_request

### Этап 5: Управление сессиями (День 9-10)
- [ ] Создание/удаление сессий в Redis
- [ ] Фоновый worker очистки
- [ ] Завершение всех сессий пользователя (logout everywhere)
- [ ] Blacklist для токенов

### Этап 6: Observability (День 11-12)
- [ ] Prometheus метрики
- [ ] OpenTelemetry трейсинг
- [ ] Health check endpoints
- [ ] Grafana дашборды

### Этап 7: Тестирование и деплой (День 13-14)
- [ ] Unit тесты (моки для Redis/DB)
- [ ] Интеграционные тесты
- [ ] Load testing (wrk или vegeta)
- [ ] Helm chart для Kubernetes

---

## ⚠️ Важные моменты и best practices

### Безопасность

1. **JWT безопасность**:
   - Используйте `golang-jwt/jwt` вместо устаревшего `jwt-go`
   - Всегда проверяйте алгоритм подписи (защита от `alg: none`)
   - Короткое время жизни Access Token (15-60 минут)
   - Храните Refresh Token в Redis с хешированием

2. **Защита API**:
   - Rate limiting на эндпоинтах аутентификации
   - TLS 1.3 для всех коммуникаций
   - HTTP-only, Secure, SameSite cookies для токенов

3. **Обработка паролей**:
   - Используйте bcrypt или PBKDF2 с солью
   - Никогда не логируйте пароли

### Производительность

1. **Оптимизация Redis**:
   - Используйте Pipeline для множественных операций
   - Настройте пул соединений
   - Включите мониторинг медленных запросов

2. **База данных**:
   - Индексы на `email`, `user_id`
   - Connection pooling
   - Read replicas для масштабирования

3. **HTTP сервер**:
   - Таймауты Read/Write/Idle
   - Graceful shutdown
   - Ограничение размера тела запроса

### Надежность

1. **Graceful shutdown**:
```go
func main() {
    srv := &http.Server{Addr: ":8080", Handler: router}
    
    go func() {
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatalf("listen: %s\n", err)
        }
    }()
    
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    if err := srv.Shutdown(ctx); err != nil {
        log.Fatal("Server forced to shutdown:", err)
    }
}
```

2. **Circuit breakers** для зависимостей (Redis, PostgreSQL)
3. **Retry with backoff** при подключении к БД/Redis
4. **Мониторинг**:
   - Метрики: latency, error rate, throughput
   - Алерты на высокий 401/500 rate

---

## 🔧 Пример конфигурации

```yaml
# configs/config.yaml
server:
  port: 8080
  read_timeout: 10s
  write_timeout: 10s
  idle_timeout: 120s

database:
  host: postgres
  port: 5432
  user: iam_user
  password: ${DB_PASSWORD}
  database: iam
  max_open_conns: 100
  max_idle_conns: 10

redis:
  host: redis
  port: 6379
  password: ${REDIS_PASSWORD}
  db: 0
  pool_size: 50

jwt:
  access_secret: ${JWT_ACCESS_SECRET}
  refresh_secret: ${JWT_REFRESH_SECRET}
  access_ttl: 15m
  refresh_ttl: 168h  # 7 days

observability:
  metrics_enabled: true
  tracing_enabled: true
  otlp_endpoint: otel-collector:4317
  environment: production
```

---

Этот план даст вам полностью функциональный IAM микросервис с production-ready качеством. Начните с этапа 1 и последовательно двигайтесь к этапу 7, тестируя каждый компонент. Удачи в разработке! 🚀