package model

import (
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Token types carried in the `token_use` claim.
const (
	TokenUseAccess = "access"
	TokenUseID     = "id"
)

// OIDC scopes understood by the service.
const (
	ScopeOpenID        = "openid"
	ScopeProfile       = "profile"
	ScopeEmail         = "email"
	ScopeOfflineAccess = "offline_access"
)

// TokenPair is the successful response of the token endpoint.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// AccessClaims is the claim set of access tokens and id_tokens. It embeds the
// standard claims, so `iss`, `sub`, `aud`, `exp`, `iat`, `jti` are produced and
// validated by golang-jwt itself.
type AccessClaims struct {
	Scope         string   `json:"scope,omitempty"`
	ClientID      string   `json:"client_id,omitempty"`
	SessionID     string   `json:"sid,omitempty"`
	TokenUse      string   `json:"token_use"`
	AuthTime      int64    `json:"auth_time,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
	Email         string   `json:"email,omitempty"`
	EmailVerified *bool    `json:"email_verified,omitempty"`
	Name          string   `json:"name,omitempty"`
	Roles         []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

// HasScope reports whether the claim set contains the requested scope.
func (c *AccessClaims) HasScope(scope string) bool {
	for _, s := range SplitScope(c.Scope) {
		if s == scope {
			return true
		}
	}
	return false
}

// IsUserToken reports whether the token was issued on behalf of a user
// (as opposed to a client_credentials token).
func (c *AccessClaims) IsUserToken() bool { return c.SessionID != "" }

// Expiry returns the expiry instant, or the zero time when absent.
func (c *AccessClaims) Expiry() time.Time {
	if c.ExpiresAt == nil {
		return time.Time{}
	}
	return c.ExpiresAt.Time
}

// SplitScope splits a space-delimited scope string, dropping empty entries.
func SplitScope(scope string) []string {
	if scope == "" {
		return nil
	}
	return strings.Fields(scope)
}

// JoinScope normalises a scope string: no duplicates, single spaces.
func JoinScope(scopes []string) string {
	seen := make(map[string]struct{}, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}
