package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"iam-service/internal/model"
)

type SessionService struct {
	redisClient *redis.Client
	ttl         time.Duration
}

func NewSessionService(redisClient *redis.Client, ttl time.Duration) *SessionService {
	return &SessionService{
		redisClient: redisClient,
		ttl:         ttl,
	}
}

func (s *SessionService) CreateSession(ctx context.Context, userID, deviceID, ip, userAgent string) (*model.Session, error) {
	session := &model.Session{
		ID:        uuid.New().String(),
		UserID:    userID,
		DeviceID:  deviceID,
		IPAddress: ip,
		UserAgent: userAgent,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(s.ttl),
	}

	// Сохранение в Redis с TTL
	key := fmt.Sprintf("session:%s", session.ID)
	data, err := json.Marshal(session)
	if err != nil {
		return nil, err
	}

	if err = s.redisClient.Set(ctx, key, data, s.ttl).Err(); err != nil {
		return nil, err
	}

	// Индекс для поиска сессий пользователя
	userSessionsKey := fmt.Sprintf("user_sessions:%s", userID)
	if err = s.redisClient.SAdd(ctx, userSessionsKey, session.ID).Err(); err != nil {
		return nil, err
	}

	if err = s.redisClient.Expire(ctx, userSessionsKey, s.ttl).Err(); err != nil {
		return nil, err
	}

	return session, nil
}

func (s *SessionService) DeleteSession(ctx context.Context, sessionID string) error {
	// Получение session для user_id
	key := fmt.Sprintf("session:%s", sessionID)
	data, err := s.redisClient.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil
	}
	if err != nil {
		return err
	}

	var session model.Session
	if err = json.Unmarshal(data, &session); err != nil {
		return err
	}

	// Удаление сессии и индекса
	pipe := s.redisClient.Pipeline()
	pipe.Del(ctx, key)
	pipe.SRem(ctx, fmt.Sprintf("user_sessions:%s", session.UserID), sessionID)
	_, err = pipe.Exec(ctx)

	return err
}

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
