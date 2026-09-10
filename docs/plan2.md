# IAM Микросервис на Go (Минимальный стек)

## 📋 Обновленная архитектура с минимальными зависимостями

### Сторонние пакеты (только критически необходимые)
| Пакет | Назначение | Почему нельзя заменить stdlib |
|-------|------------|-------------------------------|
| `github.com/jackc/pgx/v5` | PostgreSQL driver | Нет нативного драйвера с Connection Pooling |
| `github.com/pressly/goose/v3` | Миграции | Нет встроенного инструмента миграций |
| `github.com/golang-jwt/jwt/v5` | JWT | Сложность реализации RS256/HS256 с нуля |
| `github.com/redis/go-redis/v9` | Redis client | Нет нативного клиента |
| `go.uber.org/zap` | Логирование (опционально) | Можно заменить на `log/slog` (Go 1.21+) |

**Все остальное - стандартная библиотека!**
- HTTP сервер: `net/http` (без Gin/Echo)
- Роутинг: `net/http` + собственный паттерн матчинг
- Конфигурация: `os.Getenv` + `flag`
- Валидация: ручная

---

## 🏗️ Структура проекта (минималистичная)

```
iam-service/
├── cmd/
│   └── iam-service/
│       └── main.go
├── internal/
│   ├── server/
│   │   ├── server.go           # HTTP сервер на net/http
│   │   └── handlers.go         # Хендлеры
│   ├── auth/
│   │   ├── jwt.go              # JWT операции
│   │   ├── password.go         # Хеширование паролей (bcrypt из crypto)
│   │   └── session.go          # Управление сессиями
│   ├── storage/
│   │   ├── postgres.go         # PGX подключение и репозитории
│   │   ├── redis.go            # Redis клиент
│   │   └── migrations/         # Goose миграции
│   ├── middleware/
│   │   ├── auth.go
│   │   ├── logging.go          # Логирование через log/slog
│   │   └── metrics.go
│   └── models/
│       └── models.go
├── pkg/
│   └── httputil/
│       ├── response.go
│       └── errors.go
├── migrations/                  # SQL миграции
│   ├── 001_create_users.sql
│   └── 002_create_sessions.sql
├── scripts/
│   └── migrate.sh
├── go.mod
├── go.sum
├── Dockerfile
└── docker-compose.yml
```

---

## 📦 Установка зависимостей

```bash
go mod init iam-service

# Критические зависимости
go get github.com/jackc/pgx/v5
go get github.com/pressly/goose/v3
go get github.com/golang-jwt/jwt/v5
go get github.com/redis/go-redis/v9

# Только если нужно структурированное логгирование
# go get go.uber.org/zap (но можно использовать log/slog)

# Инструменты для миграций
go install github.com/pressly/goose/v3/cmd/goose@latest
```

---

## 🔧 Основной код с использованием stdlib

### 1. Конфигурация (только env + флаги)

```go
// internal/server/config.go
package server

import (
    "flag"
    "os"
    "strconv"
    "time"
)

type Config struct {
    Port            string
    PostgresURL     string
    RedisAddr       string
    RedisPassword   string
    JWTSecret       string
    JWTRefreshSecret string
    AccessTTL       time.Duration
    RefreshTTL      time.Duration
}

func LoadConfig() *Config {
    var cfg Config
    
    // Флаги командной строки
    flag.StringVar(&cfg.Port, "port", getEnv("PORT", "8080"), "HTTP port")
    flag.StringVar(&cfg.PostgresURL, "db-url", getEnv("DATABASE_URL", "postgres://user:pass@localhost:5432/iam"), "PostgreSQL URL")
    flag.StringVar(&cfg.RedisAddr, "redis-addr", getEnv("REDIS_ADDR", "localhost:6379"), "Redis address")
    flag.StringVar(&cfg.RedisPassword, "redis-password", getEnv("REDIS_PASSWORD", ""), "Redis password")
    flag.StringVar(&cfg.JWTSecret, "jwt-secret", getEnv("JWT_SECRET", ""), "JWT secret for access tokens")
    flag.StringVar(&cfg.JWTRefreshSecret, "jwt-refresh-secret", getEnv("JWT_REFRESH_SECRET", ""), "JWT secret for refresh tokens")
    
    flag.DurationVar(&cfg.AccessTTL, "access-ttl", getEnvDuration("ACCESS_TTL", 15*time.Minute), "Access token TTL")
    flag.DurationVar(&cfg.RefreshTTL, "refresh-ttl", getEnvDuration("REFRESH_TTL", 168*time.Hour), "Refresh token TTL")
    
    flag.Parse()
    
    return &cfg
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
    if value := os.Getenv(key); value != "" {
        if d, err := time.ParseDuration(value); err == nil {
            return d
        }
    }
    return defaultValue
}
```

### 2. Модели данных

```go
// internal/models/models.go
package models

import (
    "time"
)

type User struct {
    ID           string    `json:"id"`
    Email        string    `json:"email"`
    PasswordHash string    `json:"-"`
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
}

type Session struct {
    ID           string    `json:"id"`
    UserID       string    `json:"user_id"`
    RefreshToken string    `json:"refresh_token_hash"`
    DeviceID     string    `json:"device_id"`
    IPAddress    string    `json:"ip_address"`
    UserAgent    string    `json:"user_agent"`
    CreatedAt    time.Time `json:"created_at"`
    ExpiresAt    time.Time `json:"expires_at"`
}

type TokenPair struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    ExpiresIn    int64  `json:"expires_in"`
}

type LoginRequest struct {
    Email    string `json:"email"`
    Password string `json:"password"`
    DeviceID string `json:"device_id,omitempty"`
}

type RefreshRequest struct {
    RefreshToken string `json:"refresh_token"`
}
```

### 3. PostgreSQL с PGX

```go
// internal/storage/postgres.go
package storage

import (
    "context"
    "fmt"
    
    "github.com/jackc/pgx/v5"
    "github.com/jackc/pgx/v5/pgxpool"
)

type PostgresStorage struct {
    pool *pgxpool.Pool
}

func NewPostgresStorage(ctx context.Context, connString string) (*PostgresStorage, error) {
    config, err := pgxpool.ParseConfig(connString)
    if err != nil {
        return nil, fmt.Errorf("parse config: %w", err)
    }
    
    // Настройка пула соединений
    config.MaxConns = 100
    config.MinConns = 10
    
    pool, err := pgxpool.NewWithConfig(ctx, config)
    if err != nil {
        return nil, fmt.Errorf("create pool: %w", err)
    }
    
    if err := pool.Ping(ctx); err != nil {
        return nil, fmt.Errorf("ping: %w", err)
    }
    
    return &PostgresStorage{pool: pool}, nil
}

func (s *PostgresStorage) Close() {
    s.pool.Close()
}

// User Repository
func (s *PostgresStorage) CreateUser(ctx context.Context, email, passwordHash string) (*models.User, error) {
    var user models.User
    query := `
        INSERT INTO users (email, password_hash, created_at, updated_at)
        VALUES ($1, $2, NOW(), NOW())
        RETURNING id, email, created_at, updated_at
    `
    
    err := s.pool.QueryRow(ctx, query, email, passwordHash).Scan(
        &user.ID, &user.Email, &user.CreatedAt, &user.UpdatedAt,
    )
    if err != nil {
        return nil, fmt.Errorf("create user: %w", err)
    }
    
    return &user, nil
}

func (s *PostgresStorage) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
    var user models.User
    query := `SELECT id, email, password_hash, created_at, updated_at FROM users WHERE email = $1`
    
    err := s.pool.QueryRow(ctx, query, email).Scan(
        &user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt,
    )
    if err == pgx.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, fmt.Errorf("get user: %w", err)
    }
    
    return &user, nil
}

func (s *PostgresStorage) GetUserByID(ctx context.Context, id string) (*models.User, error) {
    var user models.User
    query := `SELECT id, email, password_hash, created_at, updated_at FROM users WHERE id = $1`
    
    err := s.pool.QueryRow(ctx, query, id).Scan(
        &user.ID, &user.Email, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt,
    )
    if err == pgx.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, fmt.Errorf("get user: %w", err)
    }
    
    return &user, nil
}
```

### 4. Redis клиент

```go
// internal/storage/redis.go
package storage

import (
    "context"
    "encoding/json"
    "fmt"
    "time"
    
    "github.com/redis/go-redis/v9"
    "iam-service/internal/models"
)

type RedisStorage struct {
    client *redis.Client
}

func NewRedisStorage(addr, password string, db int) (*RedisStorage, error) {
    client := redis.NewClient(&redis.Options{
        Addr:     addr,
        Password: password,
        DB:       db,
    })
    
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    if err := client.Ping(ctx).Err(); err != nil {
        return nil, fmt.Errorf("redis ping: %w", err)
    }
    
    return &RedisStorage{client: client}, nil
}

func (s *RedisStorage) Close() error {
    return s.client.Close()
}

// Session operations
func (s *RedisStorage) SaveSession(ctx context.Context, session *models.Session, ttl time.Duration) error {
    key := fmt.Sprintf("session:%s", session.ID)
    data, err := json.Marshal(session)
    if err != nil {
        return err
    }
    
    pipe := s.client.Pipeline()
    pipe.SetEx(ctx, key, data, ttl)
    pipe.SAdd(ctx, fmt.Sprintf("user_sessions:%s", session.UserID), session.ID)
    pipe.Expire(ctx, fmt.Sprintf("user_sessions:%s", session.UserID), ttl)
    
    _, err = pipe.Exec(ctx)
    return err
}

func (s *RedisStorage) GetSession(ctx context.Context, sessionID string) (*models.Session, error) {
    key := fmt.Sprintf("session:%s", sessionID)
    data, err := s.client.Get(ctx, key).Bytes()
    if err == redis.Nil {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    
    var session models.Session
    if err := json.Unmarshal(data, &session); err != nil {
        return nil, err
    }
    
    return &session, nil
}

func (s *RedisStorage) DeleteSession(ctx context.Context, sessionID string) error {
    // Получаем session для user_id
    key := fmt.Sprintf("session:%s", sessionID)
    data, err := s.client.Get(ctx, key).Bytes()
    if err == redis.Nil {
        return nil
    }
    if err != nil {
        return err
    }
    
    var session models.Session
    if err := json.Unmarshal(data, &session); err != nil {
        return err
    }
    
    pipe := s.client.Pipeline()
    pipe.Del(ctx, key)
    pipe.SRem(ctx, fmt.Sprintf("user_sessions:%s", session.UserID), sessionID)
    _, err = pipe.Exec(ctx)
    
    return err
}

// Refresh token storage (hashed)
func (s *RedisStorage) SaveRefreshToken(ctx context.Context, userID, tokenHash string, ttl time.Duration) error {
    key := fmt.Sprintf("refresh:%s", userID)
    return s.client.SetEx(ctx, key, tokenHash, ttl).Err()
}

func (s *RedisStorage) GetRefreshTokenHash(ctx context.Context, userID string) (string, error) {
    key := fmt.Sprintf("refresh:%s", userID)
    val, err := s.client.Get(ctx, key).Result()
    if err == redis.Nil {
        return "", nil
    }
    return val, err
}

func (s *RedisStorage) DeleteRefreshToken(ctx context.Context, userID string) error {
    key := fmt.Sprintf("refresh:%s", userID)
    return s.client.Del(ctx, key).Err()
}

// Atomic lock for refresh operations
func (s *RedisStorage) AcquireLock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
    return s.client.SetNX(ctx, key, "1", ttl).Result()
}

func (s *RedisStorage) ReleaseLock(ctx context.Context, key string) error {
    return s.client.Del(ctx, key).Err()
}
```

### 5. JWT (с использованием golang-jwt, но без лишних оберток)

```go
// internal/auth/jwt.go
package auth

import (
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "time"
    
    "github.com/golang-jwt/jwt/v5"
)

type JWTService struct {
    accessSecret  []byte
    refreshSecret []byte
    accessTTL     time.Duration
    refreshTTL    time.Duration
}

func NewJWTService(accessSecret, refreshSecret string, accessTTL, refreshTTL time.Duration) *JWTService {
    return &JWTService{
        accessSecret:  []byte(accessSecret),
        refreshSecret: []byte(refreshSecret),
        accessTTL:     accessTTL,
        refreshTTL:    refreshTTL,
    }
}

func (s *JWTService) GenerateAccessToken(userID string) (string, error) {
    claims := jwt.RegisteredClaims{
        Subject:   userID,
        ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.accessTTL)),
        IssuedAt:  jwt.NewNumericDate(time.Now()),
        Issuer:    "iam-service",
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString(s.accessSecret)
}

func (s *JWTService) GenerateRefreshToken(userID string) (string, string, error) {
    tokenID := generateTokenID()
    claims := jwt.RegisteredClaims{
        Subject:   userID,
        ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.refreshTTL)),
        IssuedAt:  jwt.NewNumericDate(time.Now()),
        ID:        tokenID,
        Issuer:    "iam-service",
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString(s.refreshSecret)
    if err != nil {
        return "", "", err
    }
    
    return tokenString, tokenID, nil
}

func (s *JWTService) VerifyAccessToken(tokenString string) (string, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        // Проверка алгоритма
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return s.accessSecret, nil
    })
    
    if err != nil || !token.Valid {
        return "", fmt.Errorf("invalid token: %w", err)
    }
    
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return "", fmt.Errorf("invalid claims")
    }
    
    userID, ok := claims["sub"].(string)
    if !ok {
        return "", fmt.Errorf("missing user id")
    }
    
    return userID, nil
}

func (s *JWTService) VerifyRefreshToken(tokenString string) (string, string, error) {
    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method")
        }
        return s.refreshSecret, nil
    })
    
    if err != nil || !token.Valid {
        return "", "", fmt.Errorf("invalid token: %w", err)
    }
    
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return "", "", fmt.Errorf("invalid claims")
    }
    
    userID, ok := claims["sub"].(string)
    if !ok {
        return "", "", fmt.Errorf("missing user id")
    }
    
    tokenID, ok := claims["jti"].(string)
    if !ok {
        return "", "", fmt.Errorf("missing token id")
    }
    
    return userID, tokenID, nil
}

func (s *JWTService) HashToken(token string) string {
    hash := sha256.Sum256([]byte(token))
    return hex.EncodeToString(hash[:])
}

func generateTokenID() string {
    b := make([]byte, 16)
    // crypto/rand для production
    for i := range b {
        b[i] = byte(time.Now().UnixNano() >> (i * 8))
    }
    return hex.EncodeToString(b)
}
```

### 6. Хеширование паролей (bcrypt из crypto)

```go
// internal/auth/password.go
package auth

import "golang.org/x/crypto/bcrypt"

// Примечание: bcrypt требует внешний пакет, но это стандарт де-факто
// Альтернатива: pbkdf2 из crypto/pbkdf2

func HashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}
```

### 7. HTTP сервер (net/http)

```go
// internal/server/server.go
package server

import (
    "context"
    "encoding/json"
    "fmt"
    "log/slog"
    "net/http"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"
    
    "iam-service/internal/auth"
    "iam-service/internal/models"
    "iam-service/internal/storage"
)

type Server struct {
    httpServer    *http.Server
    config        *Config
    postgres      *storage.PostgresStorage
    redis         *storage.RedisStorage
    jwtService    *auth.JWTService
    logger        *slog.Logger
}

func NewServer(cfg *Config) (*Server, error) {
    ctx := context.Background()
    
    // Подключение к БД
    pg, err := storage.NewPostgresStorage(ctx, cfg.PostgresURL)
    if err != nil {
        return nil, fmt.Errorf("postgres: %w", err)
    }
    
    // Подключение к Redis
    redis, err := storage.NewRedisStorage(cfg.RedisAddr, cfg.RedisPassword, 0)
    if err != nil {
        pg.Close()
        return nil, fmt.Errorf("redis: %w", err)
    }
    
    // JWT сервис
    jwtService := auth.NewJWTService(
        cfg.JWTSecret,
        cfg.JWTRefreshSecret,
        cfg.AccessTTL,
        cfg.RefreshTTL,
    )
    
    // Логгер
    logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
    
    srv := &Server{
        config:     cfg,
        postgres:   pg,
        redis:      redis,
        jwtService: jwtService,
        logger:     logger,
    }
    
    // Настройка HTTP сервера
    mux := http.NewServeMux()
    srv.setupRoutes(mux)
    
    srv.httpServer = &http.Server{
        Addr:         ":" + cfg.Port,
        Handler:      srv.loggingMiddleware(srv.metricsMiddleware(mux)),
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 10 * time.Second,
        IdleTimeout:  120 * time.Second,
    }
    
    return srv, nil
}

func (s *Server) setupRoutes(mux *http.ServeMux) {
    mux.HandleFunc("POST /auth/login", s.handleLogin)
    mux.HandleFunc("POST /auth/refresh", s.handleRefresh)
    mux.HandleFunc("GET /auth/verify", s.handleVerify)
    mux.HandleFunc("POST /auth/logout", s.handleLogout)
    mux.HandleFunc("GET /health", s.handleHealth)
    mux.HandleFunc("GET /metrics", s.handleMetrics)
}

func (s *Server) Start() error {
    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()
    
    go func() {
        s.logger.Info("server starting", "port", s.config.Port)
        if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            s.logger.Error("server error", "error", err)
        }
    }()
    
    <-ctx.Done()
    
    s.logger.Info("shutting down gracefully")
    
    shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    return s.httpServer.Shutdown(shutdownCtx)
}

func (s *Server) Close() {
    s.postgres.Close()
    s.redis.Close()
}
```

### 8. HTTP Handlers

```go
// internal/server/handlers.go (частично)
package server

import (
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "net/http"
    "strings"
    "time"
    
    "iam-service/internal/models"
)

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
    var req models.LoginRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        s.writeError(w, http.StatusBadRequest, "invalid request body")
        return
    }
    
    // Валидация
    if req.Email == "" || req.Password == "" {
        s.writeError(w, http.StatusBadRequest, "email and password required")
        return
    }
    
    // Получение пользователя
    user, err := s.postgres.GetUserByEmail(r.Context(), req.Email)
    if err != nil {
        s.logger.Error("get user error", "error", err)
        s.writeError(w, http.StatusInternalServerError, "internal error")
        return
    }
    
    if user == nil || !auth.CheckPasswordHash(req.Password, user.PasswordHash) {
        s.writeError(w, http.StatusUnauthorized, "invalid credentials")
        return
    }
    
    // Генерация токенов
    accessToken, err := s.jwtService.GenerateAccessToken(user.ID)
    if err != nil {
        s.writeError(w, http.StatusInternalServerError, "token generation failed")
        return
    }
    
    refreshToken, tokenID, err := s.jwtService.GenerateRefreshToken(user.ID)
    if err != nil {
        s.writeError(w, http.StatusInternalServerError, "token generation failed")
        return
    }
    
    // Сохранение refresh token в Redis
    hashedRefresh := s.jwtService.HashToken(refreshToken)
    if err := s.redis.SaveRefreshToken(r.Context(), user.ID, hashedRefresh, s.config.RefreshTTL); err != nil {
        s.logger.Error("save refresh token error", "error", err)
        s.writeError(w, http.StatusInternalServerError, "internal error")
        return
    }
    
    // Создание сессии
    deviceID := req.DeviceID
    if deviceID == "" {
        deviceID = generateDeviceID()
    }
    
    session := &models.Session{
        ID:           tokenID,
        UserID:       user.ID,
        RefreshToken: hashedRefresh,
        DeviceID:     deviceID,
        IPAddress:    r.RemoteAddr,
        UserAgent:    r.UserAgent(),
        CreatedAt:    time.Now(),
        ExpiresAt:    time.Now().Add(s.config.RefreshTTL),
    }
    
    if err := s.redis.SaveSession(r.Context(), session, s.config.RefreshTTL); err != nil {
        s.logger.Error("save session error", "error", err)
    }
    
    s.writeJSON(w, http.StatusOK, models.TokenPair{
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
        ExpiresIn:    int64(s.config.AccessTTL.Seconds()),
    })
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
    // Извлечение токена из заголовка
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        s.writeError(w, http.StatusUnauthorized, "missing authorization header")
        return
    }
    
    tokenString := strings.TrimPrefix(authHeader, "Bearer ")
    if tokenString == authHeader {
        s.writeError(w, http.StatusUnauthorized, "invalid token format")
        return
    }
    
    // Проверка токена
    userID, err := s.jwtService.VerifyAccessToken(tokenString)
    if err != nil {
        s.writeError(w, http.StatusUnauthorized, "invalid token")
        return
    }
    
    // Передача user_id в заголовок для бэкенда
    w.Header().Set("X-User-ID", userID)
    w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
    var req models.RefreshRequest
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        s.writeError(w, http.StatusBadRequest, "invalid request body")
        return
    }
    
    if req.RefreshToken == "" {
        s.writeError(w, http.StatusBadRequest, "refresh token required")
        return
    }
    
    // Верификация refresh token
    userID, tokenID, err := s.jwtService.VerifyRefreshToken(req.RefreshToken)
    if err != nil {
        s.writeError(w, http.StatusUnauthorized, "invalid refresh token")
        return
    }
    
    // Блокировка для предотвращения race condition
    lockKey := "refresh:lock:" + userID
    locked, err := s.redis.AcquireLock(r.Context(), lockKey, 5*time.Second)
    if err != nil || !locked {
        s.writeError(w, http.StatusConflict, "refresh already in progress")
        return
    }
    defer s.redis.ReleaseLock(r.Context(), lockKey)
    
    // Проверка сохраненного refresh token
    storedHash, err := s.redis.GetRefreshTokenHash(r.Context(), userID)
    if err != nil {
        s.logger.Error("get refresh token error", "error", err)
        s.writeError(w, http.StatusInternalServerError, "internal error")
        return
    }
    
    if storedHash == "" || storedHash != s.jwtService.HashToken(req.RefreshToken) {
        s.writeError(w, http.StatusUnauthorized, "invalid refresh token")
        return
    }
    
    // Генерация новой пары токенов
    newAccessToken, err := s.jwtService.GenerateAccessToken(userID)
    if err != nil {
        s.writeError(w, http.StatusInternalServerError, "token generation failed")
        return
    }
    
    newRefreshToken, newTokenID, err := s.jwtService.GenerateRefreshToken(userID)
    if err != nil {
        s.writeError(w, http.StatusInternalServerError, "token generation failed")
        return
    }
    
    // Сохранение нового refresh token
    newHashedRefresh := s.jwtService.HashToken(newRefreshToken)
    if err := s.redis.SaveRefreshToken(r.Context(), userID, newHashedRefresh, s.config.RefreshTTL); err != nil {
        s.writeError(w, http.StatusInternalServerError, "internal error")
        return
    }
    
    // Обновление сессии
    if err := s.redis.DeleteSession(r.Context(), tokenID); err != nil {
        s.logger.Warn("failed to delete old session", "error", err)
    }
    
    s.writeJSON(w, http.StatusOK, models.TokenPair{
        AccessToken:  newAccessToken,
        RefreshToken: newRefreshToken,
        ExpiresIn:    int64(s.config.AccessTTL.Seconds()),
    })
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
    s.writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(data)
}

func (s *Server) writeError(w http.ResponseWriter, status int, message string) {
    s.writeJSON(w, status, map[string]string{"error": message})
}

func generateDeviceID() string {
    bytes := make([]byte, 16)
    rand.Read(bytes)
    return hex.EncodeToString(bytes)
}
```

### 9. Middleware (логирование и метрики)

```go
// internal/server/middleware.go
package server

import (
    "log/slog"
    "net/http"
    "time"
)

type responseWriter struct {
    http.ResponseWriter
    statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
    rw.statusCode = code
    rw.ResponseWriter.WriteHeader(code)
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
        
        next.ServeHTTP(rw, r)
        
        s.logger.Info("request",
            slog.String("method", r.Method),
            slog.String("path", r.URL.Path),
            slog.Int("status", rw.statusCode),
            slog.Duration("duration", time.Since(start)),
            slog.String("remote_addr", r.RemoteAddr),
        )
    })
}

func (s *Server) metricsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Простые метрики в памяти
        start := time.Now()
        next.ServeHTTP(w, r)
        duration := time.Since(start)
        
        // Можно отправлять в Prometheus через экспортер
        _ = duration
    })
}
```

### 10. Миграции с Goose

```sql
-- migrations/001_create_users.sql
-- +goose Up
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_deleted_at ON users(deleted_at);

-- +goose Down
DROP TABLE IF EXISTS users;
DROP EXTENSION IF EXISTS "uuid-ossp";
```

```sql
-- migrations/002_create_sessions_table.sql (опционально для аудита)
-- +goose Up
CREATE TABLE sessions_audit (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id VARCHAR(255) NOT NULL,
    device_id VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_sessions_audit_user_id ON sessions_audit(user_id);
CREATE INDEX idx_sessions_audit_created_at ON sessions_audit(created_at);

-- +goose Down
DROP TABLE IF EXISTS sessions_audit;
```

### 11. Основная точка входа

```go
// cmd/iam-service/main.go
package main

import (
    "log"
    "os"
    
    "iam-service/internal/server"
)

func main() {
    cfg := server.LoadConfig()
    
    srv, err := server.NewServer(cfg)
    if err != nil {
        log.Printf("failed to create server: %v", err)
        os.Exit(1)
    }
    defer srv.Close()
    
    if err := srv.Start(); err != nil {
        log.Printf("server error: %v", err)
        os.Exit(1)
    }
}
```

### 12. Docker Compose

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: iam_user
      POSTGRES_PASSWORD: iam_pass
      POSTGRES_DB: iam
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U iam_user"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  iam-service:
    build: .
    ports:
      - "8080:8080"
    environment:
      PORT: 8080
      DATABASE_URL: postgres://iam_user:iam_pass@postgres:5432/iam
      REDIS_ADDR: redis:6379
      REDIS_PASSWORD: ""
      JWT_SECRET: ${JWT_SECRET:-change-me-in-production}
      JWT_REFRESH_SECRET: ${JWT_REFRESH_SECRET:-change-me-in-production}
      ACCESS_TTL: 15m
      REFRESH_TTL: 168h
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy

volumes:
  postgres_data:
  redis_data:
```

### 13. Dockerfile

```dockerfile
FROM golang:1.22-alpine AS builder

WORKDIR /app