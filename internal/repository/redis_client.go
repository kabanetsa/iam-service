package repository

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"

	"iam-service/internal/config"
)

// keyPrefix namespaces every key this service owns, so the Redis instance can be
// shared with other applications.
const keyPrefix = "iam:"

// Lua scripts. They keep read-modify-write sequences atomic without a
// transaction round trip.
var (
	// rateLimitScript increments a fixed-window counter, setting the TTL on the
	// first hit, and returns {count, ttlMillis}.
	rateLimitScript = redis.NewScript(`
		local current = redis.call('INCR', KEYS[1])
		if current == 1 then
			redis.call('PEXPIRE', KEYS[1], ARGV[1])
		end
		local ttl = redis.call('PTTL', KEYS[1])
		if ttl < 0 then
			redis.call('PEXPIRE', KEYS[1], ARGV[1])
			ttl = tonumber(ARGV[1])
		end
		return {current, ttl}
	`)

	// lockReleaseScript deletes a lock only if the caller still owns it, so a
	// holder whose TTL expired cannot release somebody else's lock.
	lockReleaseScript = redis.NewScript(`
		if redis.call('GET', KEYS[1]) == ARGV[1] then
			return redis.call('DEL', KEYS[1])
		end
		return 0
	`)

	// sessionDeleteScript removes a session and its user index entry atomically,
	// returning the session payload so the caller learns the owner.
	sessionDeleteScript = redis.NewScript(`
		local value = redis.call('GET', KEYS[1])
		if not value then
			return nil
		end
		redis.call('DEL', KEYS[1])
		redis.call('ZREM', KEYS[2], ARGV[1])
		return value
	`)
)

// Redis wraps the client and owns the Lua scripts.
type Redis struct {
	client *redis.Client
}

// NewRedis connects to Redis and verifies the connection.
func NewRedis(ctx context.Context, cfg config.RedisConfig) (*Redis, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Addr,
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	})

	pingCtx, cancel := context.WithTimeout(ctx, cfg.DialTimeout)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("repository: ping redis at %s: %w", cfg.Addr, err)
	}
	return &Redis{client: client}, nil
}

// Client exposes the raw client for repositories in this package.
func (r *Redis) Client() *redis.Client { return r.client }

// Ping verifies that Redis is reachable.
func (r *Redis) Ping(ctx context.Context) error { return r.client.Ping(ctx).Err() }

// Close releases the connection pool.
func (r *Redis) Close() error { return r.client.Close() }

// CountSessions counts live session keys by scanning, used by the metrics
// sampler. SCAN is non-blocking, unlike KEYS.
func (r *Redis) CountSessions(ctx context.Context) (int64, error) {
	var (
		cursor uint64
		total  int64
	)
	for {
		keys, next, err := r.client.Scan(ctx, cursor, keyPrefix+"session:*", 500).Result()
		if err != nil {
			return 0, fmt.Errorf("repository: scan sessions: %w", err)
		}
		total += int64(len(keys))
		cursor = next
		if cursor == 0 {
			return total, nil
		}
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
	}
}

// key builds a namespaced key from its parts.
func key(parts ...string) string {
	out := keyPrefix
	for i, part := range parts {
		if i > 0 {
			out += ":"
		}
		out += part
	}
	return out
}
