package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"iam-service/internal/model"
	apierr "iam-service/internal/pkg/errors"
	"iam-service/internal/repository"
)

// ClientService authenticates OAuth clients and validates requested scopes.
type ClientService struct {
	clients *repository.ClientRepo
	audit   *repository.AuditRepo
	logger  *zap.Logger
}

// NewClientService builds the client service.
func NewClientService(clients *repository.ClientRepo, audit *repository.AuditRepo, logger *zap.Logger) *ClientService {
	return &ClientService{clients: clients, audit: audit, logger: logger}
}

// Lookup returns an enabled client by id. Unknown and disabled clients are not
// distinguished for callers of the token endpoint: both yield invalid_client.
func (s *ClientService) Lookup(ctx context.Context, clientID string) (*model.OAuthClient, error) {
	if strings.TrimSpace(clientID) == "" {
		return nil, apierr.InvalidClient("client authentication required")
	}
	client, err := s.clients.ByID(ctx, clientID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			s.fail(ctx, clientID, "unknown_client")
			return nil, apierr.InvalidClient("unknown client")
		}
		return nil, apierr.ServerError("could not load client").WithCause(err)
	}
	if client.Disabled {
		s.fail(ctx, clientID, "client_disabled")
		return nil, apierr.InvalidClient("client is disabled")
	}
	return client, nil
}

// Authenticate validates the client credentials presented at the token or
// revocation endpoint. Public clients must present no secret at all: they rely
// on PKCE (OAuth 2.1 §2.3).
func (s *ClientService) Authenticate(ctx context.Context, clientID, clientSecret string) (*model.OAuthClient, error) {
	client, err := s.Lookup(ctx, clientID)
	if err != nil {
		return nil, err
	}

	if client.IsPublic || client.TokenEndpointAuthMethod == model.AuthMethodNone {
		if clientSecret != "" {
			s.fail(ctx, clientID, "public_client_sent_secret")
			return nil, apierr.InvalidClient("public clients must not present a client secret")
		}
		return client, nil
	}

	if clientSecret == "" || client.ClientSecretHash == nil {
		s.fail(ctx, clientID, "missing_client_secret")
		return nil, apierr.InvalidClient("client authentication required")
	}
	expected := *client.ClientSecretHash
	presented := HashClientSecret(clientSecret)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) != 1 {
		s.fail(ctx, clientID, "invalid_client_secret")
		return nil, apierr.InvalidClient("invalid client credentials")
	}
	return client, nil
}

// ValidateScope checks the requested scope against the client registration and
// returns the normalised, granted scope string. An empty request grants the
// client's default scopes, which never include offline_access.
func (s *ClientService) ValidateScope(client *model.OAuthClient, requested string) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		defaults := make([]string, 0, len(client.AllowedScopes))
		for _, scope := range client.AllowedScopes {
			if scope == model.ScopeOfflineAccess {
				continue
			}
			defaults = append(defaults, scope)
		}
		if len(defaults) == 0 {
			return "", apierr.InvalidScope("client has no default scope registered")
		}
		return model.JoinScope(defaults), nil
	}

	scopes := model.SplitScope(requested)
	for _, scope := range scopes {
		if !client.AllowsScope(scope) {
			return "", apierr.InvalidScope(fmt.Sprintf("scope %q is not allowed for this client", scope))
		}
	}
	return model.JoinScope(scopes), nil
}

// RequiresConsent reports whether the consent screen must be shown.
func (s *ClientService) RequiresConsent(client *model.OAuthClient, defaultConsent bool) bool {
	return client.RequireConsent || defaultConsent
}

func (s *ClientService) fail(ctx context.Context, clientID, reason string) {
	if s.audit == nil {
		return
	}
	event := model.NewAuthEvent(model.EventClientAuthFailure, false).WithClient(clientID).WithError(reason)
	if err := s.audit.Insert(ctx, event); err != nil && s.logger != nil {
		s.logger.Warn("audit write failed", zap.String("event", model.EventClientAuthFailure), zap.String("error", err.Error()))
	}
}

// HashClientSecret hashes a client secret for storage. Client secrets are
// high-entropy random values, so a single SHA-256 is sufficient (unlike
// passwords, which need a slow KDF).
func HashClientSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// GenerateClientSecret returns a new 32-byte URL-safe client secret.
func GenerateClientSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("service: generate client secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
