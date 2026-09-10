// Package repository contains the data access layer: Postgres repositories and
// the Redis-backed state store.
package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"iam-service/internal/config"
)

// Sentinel errors returned by repositories.
var (
	// ErrNotFound means the requested record does not exist.
	ErrNotFound = errors.New("repository: not found")
	// ErrConflict means a uniqueness constraint was violated.
	ErrConflict = errors.New("repository: conflict")
)

// Postgres owns the connection pool. All repositories share one pool.
type Postgres struct {
	pool *pgxpool.Pool
}

// NewPostgres parses the DSN, configures the pool and verifies connectivity.
func NewPostgres(ctx context.Context, cfg config.DatabaseConfig) (*Postgres, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("repository: parse database dsn: %w", err)
	}
	poolCfg.MaxConns = cfg.MaxConns
	poolCfg.MinConns = cfg.MinConns
	poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.MaxConnIdleTime
	poolCfg.ConnConfig.ConnectTimeout = cfg.ConnectTimeout

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("repository: create pool: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("repository: ping database: %w", err)
	}
	return &Postgres{pool: pool}, nil
}

// Pool exposes the underlying pool for repositories.
func (p *Postgres) Pool() *pgxpool.Pool { return p.pool }

// Ping verifies that the database is reachable.
func (p *Postgres) Ping(ctx context.Context) error { return p.pool.Ping(ctx) }

// Close releases all pooled connections.
func (p *Postgres) Close() {
	if p.pool != nil {
		p.pool.Close()
	}
}

// Stats reports pool utilisation for metrics.
func (p *Postgres) Stats() *pgxpool.Stat { return p.pool.Stat() }

// WaitForSchema blocks until the expected tables exist or the timeout elapses.
// It keeps the service from starting before migrations have been applied.
func (p *Postgres) WaitForSchema(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var count int
		err := p.pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables
			WHERE table_schema = current_schema() AND table_name IN ('users', 'oauth_clients', 'auth_events')`).Scan(&count)
		if err == nil && count == 3 {
			return nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return fmt.Errorf("repository: schema check failed: %w", err)
			}
			return fmt.Errorf("repository: schema is incomplete, run `iam-service migrate up` (found %d/3 tables)", count)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
