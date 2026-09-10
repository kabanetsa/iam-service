package model

import (
	"strings"
	"time"
)

// Client types and token endpoint authentication methods (RFC 7591 / OAuth 2.1).
const (
	AuthMethodClientSecretBasic = "client_secret_basic"
	AuthMethodClientSecretPost  = "client_secret_post"
	AuthMethodNone              = "none"
)

// Grant types supported by the token endpoint.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
)

// Response types supported by the authorization endpoint.
const (
	ResponseTypeCode = "code"
)

// PKCE challenge methods (S256 only — `plain` is rejected by OAuth 2.1).
const (
	PKCEMethodS256 = "S256"
)

// OAuthClient is a registered client application. Field tags are understood by
// pgx.RowToStructByName; the *_hash field never leaves the service.
type OAuthClient struct {
	ClientID                string    `db:"client_id"`
	ClientSecretHash        *string   `db:"client_secret_hash"`
	Name                    string    `db:"name"`
	IsPublic                bool      `db:"is_public"`
	TokenEndpointAuthMethod string    `db:"token_endpoint_auth_method"`
	RedirectURIs            []string  `db:"redirect_uris"`
	AllowedScopes           []string  `db:"allowed_scopes"`
	GrantTypes              []string  `db:"grant_types"`
	RequireConsent          bool      `db:"require_consent"`
	AccessTokenTTLSeconds   *int      `db:"access_token_ttl_seconds"`
	RefreshTokenTTLSeconds  *int      `db:"refresh_token_ttl_seconds"`
	Disabled                bool      `db:"disabled"`
	CreatedAt               time.Time `db:"created_at"`
	UpdatedAt               time.Time `db:"updated_at"`
}

// SupportsGrant reports whether the client is allowed to use the grant type.
func (c *OAuthClient) SupportsGrant(grant string) bool {
	for _, g := range c.GrantTypes {
		if g == grant {
			return true
		}
	}
	return false
}

// AllowsScope reports whether the scope is registered for the client.
func (c *OAuthClient) AllowsScope(scope string) bool {
	for _, s := range c.AllowedScopes {
		if s == scope {
			return true
		}
	}
	return false
}

// IsRegisteredRedirectURI reports whether the URI matches one of the registered
// redirect URIs exactly (no wildcards, no fragments — OAuth 2.1 §3.1.2.2).
func (c *OAuthClient) IsRegisteredRedirectURI(uri string) bool {
	if uri == "" || strings.Contains(uri, "#") {
		return false
	}
	for _, registered := range c.RedirectURIs {
		if registered == uri {
			return true
		}
	}
	return false
}

// AccessTokenTTL returns the client-specific access token lifetime override.
func (c *OAuthClient) AccessTokenTTL() (time.Duration, bool) {
	if c.AccessTokenTTLSeconds == nil || *c.AccessTokenTTLSeconds <= 0 {
		return 0, false
	}
	return time.Duration(*c.AccessTokenTTLSeconds) * time.Second, true
}

// RefreshTokenTTL returns the client-specific refresh token lifetime override.
func (c *OAuthClient) RefreshTokenTTL() (time.Duration, bool) {
	if c.RefreshTokenTTLSeconds == nil || *c.RefreshTokenTTLSeconds <= 0 {
		return 0, false
	}
	return time.Duration(*c.RefreshTokenTTLSeconds) * time.Second, true
}
