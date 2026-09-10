package repository

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// LimitResult describes the outcome of a rate limit check.
type LimitResult struct {
	Allowed    bool
	Count      int64
	Limit      int
	RetryAfter time.Duration
}

// RateLimitRepo implements fixed-window counters and distributed locks in Redis.
type RateLimitRepo struct {
	r *Redis
}

// NewRateLimitRepo builds the limiter on the shared Redis client.
func NewRateLimitRepo(r *Redis) *RateLimitRepo { return &RateLimitRepo{r: r} }

// Allow consumes one unit of the quota for the given bucket. The counter and its
// expiry are set atomically by a Lua script, so a burst of parallel logins
// cannot all pass.
func (l *RateLimitRepo) Allow(ctx context.Context, bucket string, limit int, window time.Duration) (LimitResult, error) {
	result := LimitResult{Limit: limit, Allowed: true}
	if limit <= 0 {
		return result, nil
	}

	raw, err := rateLimitScript.Run(ctx, l.r.client, []string{key("rl", bucket)}, window.Milliseconds()).Result()
	if err != nil {
		return LimitResult{}, fmt.Errorf("repository: rate limit: %w", err)
	}
	values, ok := raw.([]any)
	if !ok || len(values) != 2 {
		return LimitResult{}, fmt.Errorf("repository: rate limit: unexpected script result %T", raw)
	}

	count, _ := values[0].(int64)
	ttlMillis, _ := values[1].(int64)
	result.Count = count
	if ttlMillis > 0 {
		result.RetryAfter = time.Duration(ttlMillis) * time.Millisecond
	} else {
		result.RetryAfter = window
	}
	result.Allowed = count <= int64(limit)
	return result, nil
}

// Reset clears counters, used after a successful login so that a legitimate user
// is not punished for earlier typos.
func (l *RateLimitRepo) Reset(ctx context.Context, buckets ...string) error {
	if len(buckets) == 0 {
		return nil
	}
	keys := make([]string, 0, len(buckets))
	for _, bucket := range buckets {
		keys = append(keys, key("rl", bucket))
	}
	if err := l.r.client.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("repository: reset rate limit: %w", err)
	}
	return nil
}

// AcquireLock takes a named lock, returning a random owner token. The token must
// be passed back to ReleaseLock, so a caller whose lock expired cannot release
// somebody else's lock.
func (l *RateLimitRepo) AcquireLock(ctx context.Context, name string, ttl time.Duration) (string, bool, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", false, fmt.Errorf("repository: lock token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(buf)

	ok, err := l.r.client.SetNX(ctx, key("lock", name), token, ttl).Result()
	if err != nil {
		return "", false, fmt.Errorf("repository: acquire lock: %w", err)
	}
	return token, ok, nil
}

// ReleaseLock releases a lock only if the token still matches.
func (l *RateLimitRepo) ReleaseLock(ctx context.Context, name, token string) error {
	if token == "" {
		return nil
	}
	if _, err := lockReleaseScript.Run(ctx, l.r.client, []string{key("lock", name)}, token).Result(); err != nil {
		if errors.Is(err, redis.Nil) {
			return nil
		}
		return fmt.Errorf("repository: release lock: %w", err)
	}
	return nil
}

// WaitForLock polls until the lock is free or the timeout elapses, then tries to
// take it once. It is used by refresh rotation: a client that fires two refresh
// requests at the same time should not be treated as an attacker.
func (l *RateLimitRepo) WaitForLock(ctx context.Context, name string, ttl, timeout time.Duration) (string, bool, error) {
	deadline := time.Now().Add(timeout)
	for {
		token, ok, err := l.AcquireLock(ctx, name, ttl)
		if err != nil {
			return "", false, err
		}
		if ok {
			return token, true, nil
		}
		if time.Now().After(deadline) {
			return "", false, nil
		}
		select {
		case <-ctx.Done():
			return "", false, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}
