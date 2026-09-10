package model

import (
	"net/netip"
	"time"
)

// Audited authentication event types.
const (
	EventLoginSuccess       = "login_success"
	EventLoginFailure       = "login_failure"
	EventAccountLocked      = "account_locked"
	EventRateLimited        = "rate_limited"
	EventCodeIssued         = "code_issued"
	EventCodeReused         = "code_reused"
	EventTokenIssued        = "token_issued"
	EventTokenRefreshed     = "token_refreshed"
	EventRefreshReuse       = "refresh_reuse_detected"
	EventClientAuthFailure  = "client_auth_failure"
	EventConsentDenied      = "consent_denied"
	EventLogout             = "logout"
	EventVerifyFailure      = "verify_failure"
	EventInvalidAuthorize   = "authorize_rejected"
	EventClientCredentials  = "client_credentials_issued"
	EventSessionsRevokedAll = "sessions_revoked_all"
)

// AuthEvent is a single row of the audit trail. Secrets are never recorded here:
// only identifiers, outcomes and coarse request metadata.
type AuthEvent struct {
	EventType string
	UserID    string
	ClientID  string
	SessionID string
	IP        netip.Addr
	UserAgent string
	Success   bool
	ErrorCode string
	RequestID string
}

// NewAuthEvent builds an event stamping the current time (the database default
// is used only when this field is not set by the caller).
func NewAuthEvent(eventType string, success bool) *AuthEvent {
	return &AuthEvent{EventType: eventType, Success: success}
}

func (e *AuthEvent) WithUser(userID string) *AuthEvent { e.UserID = userID; return e }
func (e *AuthEvent) WithClient(id string) *AuthEvent   { e.ClientID = id; return e }
func (e *AuthEvent) WithSession(id string) *AuthEvent  { e.SessionID = id; return e }
func (e *AuthEvent) WithRequest(id string) *AuthEvent  { e.RequestID = id; return e }
func (e *AuthEvent) WithIP(ip netip.Addr) *AuthEvent   { e.IP = ip; return e }
func (e *AuthEvent) WithAgent(ua string) *AuthEvent    { e.UserAgent = ua; return e }
func (e *AuthEvent) WithError(code string) *AuthEvent  { e.ErrorCode = code; return e }
func (e *AuthEvent) WithFailure(code string) *AuthEvent {
	e.Success = false
	e.ErrorCode = code
	return e
}

// AuditRecord is a read model for logs and future admin endpoints.
type AuditRecord struct {
	ID        int64     `db:"id"`
	EventType string    `db:"event_type"`
	UserID    *string   `db:"user_id"`
	ClientID  *string   `db:"client_id"`
	SessionID *string   `db:"session_id"`
	IP        *string   `db:"ip"`
	UserAgent *string   `db:"user_agent"`
	Success   bool      `db:"success"`
	ErrorCode *string   `db:"error_code"`
	RequestID *string   `db:"request_id"`
	CreatedAt time.Time `db:"created_at"`
}
