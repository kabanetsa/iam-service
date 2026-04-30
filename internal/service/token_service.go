package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

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
	err = s.redisClient.SetEx(
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

func (s *TokenService) RefreshAccessToken(ctx context.Context, userID, oldRefreshToken string) (*TokenPair, error) {
	// 1. Атомарная блокировка для предотвращения race condition
	lockKey := fmt.Sprintf("refresh:lock:%s", userID)
	result, err := s.redisClient.SetArgs(ctx, lockKey, "1", redis.SetArgs{
		TTL:  5 * time.Second,
		Mode: "NX",
	}).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return nil, err
	}
	if errors.Is(err, redis.Nil) || result != "OK" {
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

func (s *TokenService) GetAccessSecret() []byte {
	return s.accessSecret
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
