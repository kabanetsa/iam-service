package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"iam-service/internal/config"
	"iam-service/internal/model"
	"iam-service/internal/repository"
)

// SessionService owns the lifecycle policy of login sessions: creation with a
// per-user limit, revocation, listing and the cached account status used by
// /verify.
type SessionService struct {
	state  *repository.SessionRepo
	users  *repository.UserRepo
	cfg    config.OAuthConfig
	logger *zap.Logger
	now    func() time.Time
}

// NewSessionService builds the session service.
func NewSessionService(state *repository.SessionRepo, users *repository.UserRepo, cfg config.OAuthConfig, logger *zap.Logger) *SessionService {
	return &SessionService{state: state, users: users, cfg: cfg, logger: logger, now: time.Now}
}

// Create stores a new session and enforces the per-user session cap by evicting
// the oldest sessions. The evicted count is returned for audit and metrics.
func (s *SessionService) Create(ctx context.Context, session *model.Session, ttl time.Duration) (int, error) {
	if session.ID == "" || session.UserID == "" {
		return 0, fmt.Errorf("service: session id and user id are required")
	}
	if session.ExpiresAt.IsZero() {
		session.ExpiresAt = s.now().Add(ttl)
	}

	evicted := 0
	if s.cfg.MaxSessionsPerUser > 0 {
		sessions, err := s.state.ListSessions(ctx, session.UserID)
		if err != nil {
			return 0, err
		}
		if len(sessions) >= s.cfg.MaxSessionsPerUser {
			// Oldest first: ListSessions returns newest expiry first.
			excess := len(sessions) - s.cfg.MaxSessionsPerUser + 1
			ids := make([]string, 0, excess)
			for i := len(sessions) - 1; i >= 0 && len(ids) < excess; i-- {
				ids = append(ids, sessions[i].ID)
			}
			if _, err := s.state.DeleteSessions(ctx, session.UserID, ids...); err != nil {
				return 0, err
			}
			evicted = len(ids)
		}
	}

	if err := s.state.SaveSession(ctx, session, ttl); err != nil {
		return evicted, err
	}
	return evicted, nil
}

// Get returns a session or repository.ErrNotFound.
func (s *SessionService) Get(ctx context.Context, sid string) (*model.Session, error) {
	return s.state.GetSession(ctx, sid)
}

// Extend slides the session expiry on a refresh, never past the absolute cap
// measured from the original authentication time.
func (s *SessionService) Extend(ctx context.Context, session *model.Session) error {
	now := s.now()
	absoluteDeadline := session.AuthTime.Add(s.cfg.RefreshAbsoluteTTL)
	next := now.Add(s.cfg.RefreshTTL)
	if next.After(absoluteDeadline) {
		next = absoluteDeadline
	}
	if !next.After(now) {
		return fmt.Errorf("service: refresh token family reached its absolute lifetime")
	}
	session.ExpiresAt = next
	return s.state.SaveSession(ctx, session, next.Sub(now))
}

// Revoke removes a single session. It is idempotent.
func (s *SessionService) Revoke(ctx context.Context, sid string) error {
	return s.state.DeleteSession(ctx, sid)
}

// RevokeAll removes every session of a user and returns how many were removed.
func (s *SessionService) RevokeAll(ctx context.Context, userID string) (int, error) {
	return s.state.DeleteAllSessions(ctx, userID)
}

// List returns the live sessions of a user.
func (s *SessionService) List(ctx context.Context, userID string) ([]*model.Session, error) {
	return s.state.ListSessions(ctx, userID)
}

// IsUserActive answers whether the account behind a token may still be used. The
// answer is cached in Redis for a short TTL so that a disabled user stops working
// within that window without a Postgres round trip per proxied request.
func (s *SessionService) IsUserActive(ctx context.Context, userID string) (bool, error) {
	if status, ok, err := s.state.CachedUserStatus(ctx, userID); err != nil {
		return false, err
	} else if ok {
		return status == model.UserStatusActive, nil
	}

	status, err := s.users.Status(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	if cacheErr := s.state.CacheUserStatus(ctx, userID, status, s.cfg.UserStatusCacheTTL); cacheErr != nil && s.logger != nil {
		s.logger.Warn("failed to cache user status", zap.String("error", cacheErr.Error()))
	}
	return status == model.UserStatusActive, nil
}

// InvalidateUserStatus drops the cached status (used after a status change).
func (s *SessionService) InvalidateUserStatus(ctx context.Context, userID string) error {
	return s.state.DeleteUserStatus(ctx, userID)
}

// State exposes the underlying state store for code and refresh bookkeeping.
func (s *SessionService) State() *repository.SessionRepo { return s.state }
