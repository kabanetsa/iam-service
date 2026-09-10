package service

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"iam-service/internal/config"
	"iam-service/internal/model"
	"iam-service/internal/pkg/jwt"
)

// refreshTokenBytes is the entropy of an opaque refresh token.
const refreshTokenBytes = 32

// TokenService signs and verifies tokens and decides their lifetimes. It holds
// no storage: session and refresh bookkeeping lives in the session store.
type TokenService struct {
	signer *jwt.Signer
	cfg    config.OAuthConfig
	now    func() time.Time
}

// NewTokenService builds the token service on a configured signer.
func NewTokenService(signer *jwt.Signer, cfg config.OAuthConfig) *TokenService {
	return &TokenService{signer: signer, cfg: cfg, now: time.Now}
}

// Signer exposes the signer (JWKS rendering needs the keyring).
func (s *TokenService) Signer() *jwt.Signer { return s.signer }

// AccessTTL returns the access token lifetime, honouring a per-client override.
func (s *TokenService) AccessTTL(client *model.OAuthClient) time.Duration {
	if ttl, ok := client.AccessTokenTTL(); ok {
		return ttl
	}
	return s.cfg.AccessTTL
}

// RefreshTTL returns the refresh token lifetime, honouring a per-client
// override.
func (s *TokenService) RefreshTTL(client *model.OAuthClient) time.Duration {
	if ttl, ok := client.RefreshTokenTTL(); ok {
		return ttl
	}
	return s.cfg.RefreshTTL
}

// AccessTokenInput describes a user-bound access token.
type AccessTokenInput struct {
	User    *model.User
	Roles   []string
	Client  *model.OAuthClient
	Session *model.Session
	Scope   string
}

// NewUserAccessToken issues an access token bound to a session. Revoking the
// session revokes the token at /verify, regardless of its remaining lifetime.
func (s *TokenService) NewUserAccessToken(in AccessTokenInput) (string, int64, error) {
	ttl := s.AccessTTL(in.Client)
	now := s.now()

	claims := &model.AccessClaims{
		Scope:     in.Scope,
		ClientID:  in.Client.ClientID,
		SessionID: in.Session.ID,
		TokenUse:  model.TokenUseAccess,
		AuthTime:  in.Session.AuthTime.Unix(),
		Roles:     in.Roles,
		RegisteredClaims: jwtlib.RegisteredClaims{
			Issuer:    s.signer.Issuer(),
			Subject:   in.User.ID,
			Audience:  jwtlib.ClaimStrings{s.signerAudience()},
			ExpiresAt: jwtlib.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwtlib.NewNumericDate(now),
			NotBefore: jwtlib.NewNumericDate(now),
		},
	}
	token, err := s.signer.Sign(claims)
	if err != nil {
		return "", 0, err
	}
	return token, int64(ttl.Seconds()), nil
}

// NewClientAccessToken issues a machine-to-machine access token. It carries no
// session: it stays valid until it expires, or until the client is disabled.
func (s *TokenService) NewClientAccessToken(client *model.OAuthClient, scope string) (string, int64, error) {
	ttl := s.cfg.ServiceAccessTTL
	now := s.now()

	claims := &model.AccessClaims{
		Scope:    scope,
		ClientID: client.ClientID,
		TokenUse: model.TokenUseAccess,
		RegisteredClaims: jwtlib.RegisteredClaims{
			Issuer:    s.signer.Issuer(),
			Subject:   client.ClientID,
			Audience:  jwtlib.ClaimStrings{s.signerAudience()},
			ExpiresAt: jwtlib.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwtlib.NewNumericDate(now),
			NotBefore: jwtlib.NewNumericDate(now),
		},
	}
	token, err := s.signer.Sign(claims)
	if err != nil {
		return "", 0, err
	}
	return token, int64(ttl.Seconds()), nil
}

// IDTokenInput describes the OIDC identity token of an authentication event.
type IDTokenInput struct {
	User    *model.User
	Roles   []string
	Client  *model.OAuthClient
	Session *model.Session
	Scope   string
	Nonce   string
}

// NewIDToken issues an OIDC id_token. Its audience is the client, per OpenID
// Connect Core §2.
func (s *TokenService) NewIDToken(in IDTokenInput) (string, error) {
	ttl := s.AccessTTL(in.Client)
	now := s.now()

	claims := &model.AccessClaims{
		Scope:     in.Scope,
		ClientID:  in.Client.ClientID,
		SessionID: in.Session.ID,
		TokenUse:  model.TokenUseID,
		AuthTime:  in.Session.AuthTime.Unix(),
		Nonce:     in.Nonce,
		Roles:     in.Roles,
		RegisteredClaims: jwtlib.RegisteredClaims{
			Issuer:    s.signer.Issuer(),
			Subject:   in.User.ID,
			Audience:  jwtlib.ClaimStrings{in.Client.ClientID},
			ExpiresAt: jwtlib.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwtlib.NewNumericDate(now),
		},
	}
	if containsScope(in.Scope, model.ScopeEmail) {
		verified := in.User.EmailVerified
		claims.Email = in.User.Email
		claims.EmailVerified = &verified
	}
	if containsScope(in.Scope, model.ScopeProfile) {
		claims.Name = in.User.DisplayName
	}
	return s.signer.Sign(claims)
}

// VerifyAccess validates a presented access token.
func (s *TokenService) VerifyAccess(token string) (*model.AccessClaims, error) {
	return s.signer.VerifyAccess(token)
}

// NewRefreshToken returns an opaque, high-entropy refresh token. Refresh tokens
// are not JWTs: they are always resolved server-side, which keeps revocation and
// reuse detection authoritative.
func NewRefreshToken() (string, error) {
	buf := make([]byte, refreshTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("service: generate refresh token: %w", err)
	}
	return "rt_" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// NewOpaqueToken returns a random URL-safe identifier (session, interaction or
// state values).
func NewOpaqueToken(numBytes int) (string, error) {
	if numBytes < 16 {
		numBytes = 16
	}
	buf := make([]byte, numBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("service: generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (s *TokenService) signerAudience() string { return s.cfg.Audience }

// containsScope reports whether the space-delimited scope string has a value.
func containsScope(scope, want string) bool {
	for _, s := range model.SplitScope(scope) {
		if s == want {
			return true
		}
	}
	return false
}
