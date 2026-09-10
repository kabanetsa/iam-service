package service

import (
	"context"
	"errors"

	"iam-service/internal/config"
	"iam-service/internal/model"
	apierr "iam-service/internal/pkg/errors"
	"iam-service/internal/repository"
)

// OIDCService implements the OpenID Connect documents and endpoints: discovery,
// JWKS, userinfo.
type OIDCService struct {
	tokens *TokenService
	users  *repository.UserRepo
	cfg    config.OAuthConfig
}

// NewOIDCService builds the OIDC service.
func NewOIDCService(tokens *TokenService, users *repository.UserRepo, cfg config.OAuthConfig) *OIDCService {
	return &OIDCService{tokens: tokens, users: users, cfg: cfg}
}

// Issuer returns the issuer identifier.
func (s *OIDCService) Issuer() string { return s.cfg.IssuerURL }

// Discovery renders the OpenID Provider configuration document.
func (s *OIDCService) Discovery() map[string]any {
	issuer := s.cfg.IssuerURL
	return map[string]any{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/oauth/authorize",
		"token_endpoint":         issuer + "/oauth/token",
		"userinfo_endpoint":      issuer + "/oauth/userinfo",
		"jwks_uri":               issuer + "/.well-known/jwks.json",
		"revocation_endpoint":    issuer + "/oauth/revoke",
		"end_session_endpoint":   issuer + "/oauth/end_session",

		"response_types_supported":              []string{model.ResponseTypeCode},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{model.GrantAuthorizationCode, model.GrantRefreshToken, model.GrantClientCredentials},
		"code_challenge_methods_supported":      []string{model.PKCEMethodS256},
		"token_endpoint_auth_methods_supported": []string{model.AuthMethodClientSecretBasic, model.AuthMethodClientSecretPost, model.AuthMethodNone},
		"scopes_supported":                      []string{model.ScopeOpenID, model.ScopeProfile, model.ScopeEmail, model.ScopeOfflineAccess},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid",
			"email", "email_verified", "name", "roles",
		},
		"subject_types_supported":                          []string{"public"},
		"id_token_signing_alg_values_supported":            []string{"RS256"},
		"token_endpoint_auth_signing_alg_values_supported": []string{"RS256"},
		"request_parameter_supported":                      false,
		"require_pkce":                                     true,
	}
}

// JWKS renders the key set published for token verification.
func (s *OIDCService) JWKS() ([]byte, error) {
	return s.tokens.Signer().Keyring().JWKS()
}

// UserInfo returns the claims of the authenticated subject. The `openid` scope is
// required, and `email`/`profile` decide which claims are added.
func (s *OIDCService) UserInfo(ctx context.Context, claims *model.AccessClaims) (map[string]any, error) {
	if !claims.HasScope(model.ScopeOpenID) {
		return nil, apierr.New(apierr.CodeInsufficientScope, "the openid scope is required for userinfo")
	}
	if claims.SessionID == "" {
		return nil, apierr.InvalidToken("access token is not bound to a user")
	}

	user, err := s.users.ByID(ctx, claims.Subject)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return nil, apierr.InvalidToken("subject no longer exists")
		}
		return nil, apierr.ServerError("could not load user").WithCause(err)
	}

	out := map[string]any{"sub": user.ID}
	if claims.HasScope(model.ScopeEmail) {
		out["email"] = user.Email
		out["email_verified"] = user.EmailVerified
	}
	if claims.HasScope(model.ScopeProfile) {
		out["name"] = user.DisplayName
		out["preferred_username"] = user.Email
	}
	if len(claims.Roles) > 0 {
		out["roles"] = claims.Roles
	}
	return out, nil
}
