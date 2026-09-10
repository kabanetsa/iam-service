package service

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"go.uber.org/zap"

	"iam-service/internal/config"
	"iam-service/internal/model"
	apierr "iam-service/internal/pkg/errors"
	"iam-service/internal/pkg/password"
	"iam-service/internal/repository"
)

// LoginInput carries everything the login form collected about the attempt.
type LoginInput struct {
	Email     string
	Password  string
	IP        netip.Addr
	UserAgent string
	RequestID string
}

// LoginResult is a successful authentication.
type LoginResult struct {
	User  *model.User
	Roles []string
}

// AuthService authenticates end users with a password. Every failure mode that
// reveals whether an account exists is answered with the same generic error, and
// verification always costs the same amount of work.
type AuthService struct {
	users   *repository.UserRepo
	limiter *repository.RateLimitRepo
	audit   *repository.AuditRepo
	cfg     config.RateLimitConfig
	logger  *zap.Logger
	now     func() time.Time
}

// NewAuthService builds the authentication service.
func NewAuthService(users *repository.UserRepo, limiter *repository.RateLimitRepo, audit *repository.AuditRepo, cfg config.RateLimitConfig, logger *zap.Logger) *AuthService {
	return &AuthService{users: users, limiter: limiter, audit: audit, cfg: cfg, logger: logger, now: time.Now}
}

// invalidCredentials is deliberately identical for unknown accounts, wrong
// passwords and disabled accounts.
const invalidCredentials = "invalid email or password"

// Authenticate verifies the credentials and applies brute-force protection:
// a per-account window that counts attempts since the last success, a per-IP
// window that counts only failures, and a lockout counter in Postgres.
//
// Counting only failures per IP keeps a shared office or CI runner from being
// throttled by its own successful logins, while credential stuffing — which is
// made of failures — is still cut off.
func (s *AuthService) Authenticate(ctx context.Context, in LoginInput) (*LoginResult, error) {
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if email == "" || in.Password == "" {
		return nil, apierr.InvalidRequest("email and password are required")
	}

	accountBucket := "login:account:" + repository.HashToken(email)
	ipBucket := "login:ip:" + in.IP.String()

	if err := s.checkWindow(ctx, in, accountBucket, s.cfg.LoginPerAccount); err != nil {
		return nil, err
	}

	user, err := s.users.ByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			password.VerifyDummy(in.Password)
			return nil, s.penalise(ctx, in, ipBucket, "", invalidCredentials)
		}
		return nil, apierr.ServerError("could not verify credentials").WithCause(err)
	}

	now := s.now()
	if user.IsLocked(now) {
		remaining := user.LockedFor(now)
		s.record(ctx, model.EventAccountLocked, in, user.ID, "account_locked")
		return nil, apierr.RateLimited("account temporarily locked, try again later", remaining)
	}

	if !user.IsActive() {
		// Burn the same work as a real verification to keep timing uniform.
		password.VerifyDummy(in.Password)
		if err := s.consumeIPQuota(ctx, in, ipBucket); err != nil {
			return nil, err
		}
		s.record(ctx, model.EventLoginFailure, in, user.ID, "account_not_active")
		return nil, apierr.AccessDenied("account is not active")
	}

	if !password.Verify(user.PasswordHash, in.Password) {
		locked, lockedUntil, err := s.users.RecordFailedLogin(ctx, user.ID, s.cfg.FailedLoginsToLock, s.cfg.AccountLockDuration)
		if err != nil && s.logger != nil {
			s.logger.Error("failed to record failed login", zap.String("error", err.Error()))
		}
		if quotaErr := s.consumeIPQuota(ctx, in, ipBucket); quotaErr != nil {
			return nil, quotaErr
		}
		s.record(ctx, model.EventLoginFailure, in, user.ID, "invalid_password")
		if locked {
			s.record(ctx, model.EventAccountLocked, in, user.ID, "account_locked")
			return nil, apierr.RateLimited("account temporarily locked, try again later", time.Until(lockedUntil))
		}
		return nil, apierr.InvalidGrant(invalidCredentials)
	}

	roles, err := s.users.Roles(ctx, user.ID)
	if err != nil && s.logger != nil {
		s.logger.Warn("failed to load roles", zap.String("error", err.Error()))
	}

	if err := s.users.ResetFailedLogins(ctx, user.ID); err != nil && s.logger != nil {
		s.logger.Warn("failed to reset failed logins", zap.String("error", err.Error()))
	}
	// A successful login clears the failure counters, so a legitimate user is not
	// punished for earlier typos.
	if err := s.limiter.Reset(ctx, accountBucket, ipBucket); err != nil && s.logger != nil {
		s.logger.Warn("failed to reset rate limit", zap.String("error", err.Error()))
	}

	if password.NeedsRehash(user.PasswordHash) {
		if hash, hashErr := password.Hash(in.Password); hashErr == nil {
			if updateErr := s.users.UpdatePasswordHash(ctx, user.ID, hash); updateErr != nil && s.logger != nil {
				s.logger.Warn("failed to rehash password", zap.String("error", updateErr.Error()))
			}
		}
	}

	s.record(ctx, model.EventLoginSuccess, in, user.ID, "")
	return &LoginResult{User: user, Roles: roles}, nil
}

// consumeIPQuota counts one failed attempt for the client address and reports a
// rate limit error once the window is exhausted.
func (s *AuthService) consumeIPQuota(ctx context.Context, in LoginInput, ipBucket string) error {
	result, err := s.limiter.Allow(ctx, ipBucket, s.cfg.LoginPerIP, s.cfg.Window)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("rate limiter unavailable", zap.String("bucket", "login:ip"), zap.String("error", err.Error()))
		}
		return nil
	}
	if result.Allowed {
		return nil
	}
	s.record(ctx, model.EventRateLimited, in, "", "rate_limited")
	return apierr.RateLimited("too many login attempts, try again later", result.RetryAfter)
}

// penalise consumes the failure quota and answers with the generic credentials
// error, or with a rate limit error once the address is out of budget.
func (s *AuthService) penalise(ctx context.Context, in LoginInput, ipBucket, userID, description string) error {
	if err := s.consumeIPQuota(ctx, in, ipBucket); err != nil {
		return err
	}
	s.record(ctx, model.EventLoginFailure, in, userID, "invalid_credentials")
	return apierr.InvalidGrant(description)
}

func (s *AuthService) checkWindow(ctx context.Context, in LoginInput, bucket string, limit int) error {
	result, err := s.limiter.Allow(ctx, bucket, limit, s.cfg.Window)
	if err != nil {
		// A limiter outage must not lock everybody out of the product, but it is
		// logged loudly because brute-force protection is degraded.
		if s.logger != nil {
			s.logger.Error("rate limiter unavailable", zap.String("bucket", bucket), zap.String("error", err.Error()))
		}
		return nil
	}
	if result.Allowed {
		return nil
	}
	s.record(ctx, model.EventRateLimited, in, "", "rate_limited")
	return apierr.RateLimited("too many login attempts, try again later", result.RetryAfter)
}

func (s *AuthService) record(ctx context.Context, eventType string, in LoginInput, userID, errorCode string) {
	event := model.NewAuthEvent(eventType, errorCode == "").
		WithUser(userID).
		WithIP(in.IP).
		WithAgent(in.UserAgent).
		WithRequest(in.RequestID).
		WithError(errorCode)
	if err := s.audit.Insert(ctx, event); err != nil && s.logger != nil {
		s.logger.Warn("audit write failed", zap.String("event", eventType), zap.String("error", err.Error()))
	}
}

// LoginAllowed reports whether the login buckets still have room, without
// consuming a unit. It lets the login page fail before asking for a password.
func (s *AuthService) LoginAllowed(ctx context.Context, email string, ip netip.Addr) (bool, time.Duration) {
	accountBucket := "login:account:" + repository.HashToken(strings.ToLower(strings.TrimSpace(email)))
	if result, err := s.limiter.Allow(ctx, accountBucket, s.cfg.LoginPerAccount, s.cfg.Window); err == nil && !result.Allowed {
		return false, result.RetryAfter
	}
	return true, 0
}
