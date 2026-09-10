package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"iam-service/internal/model"
)

const clientColumns = `client_id, client_secret_hash, name, is_public, token_endpoint_auth_method,
	redirect_uris, allowed_scopes, grant_types, require_consent,
	access_token_ttl_seconds, refresh_token_ttl_seconds, disabled, created_at, updated_at`

// ClientRepo stores registered OAuth clients.
type ClientRepo struct {
	pg *Postgres
}

// NewClientRepo builds a client repository on the shared pool.
func NewClientRepo(pg *Postgres) *ClientRepo { return &ClientRepo{pg: pg} }

// ByID returns the client or ErrNotFound. Disabled clients are returned as well:
// the caller decides how to react.
func (r *ClientRepo) ByID(ctx context.Context, clientID string) (*model.OAuthClient, error) {
	rows, err := r.pg.pool.Query(ctx,
		`SELECT `+clientColumns+` FROM oauth_clients WHERE client_id = $1`, clientID)
	if err != nil {
		return nil, fmt.Errorf("repository: query client: %w", err)
	}
	client, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[model.OAuthClient])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("repository: scan client: %w", err)
	}
	return &client, nil
}

// Upsert inserts or updates a client registration. It is used by the seed
// command; self-service registration is out of scope for v1.
func (r *ClientRepo) Upsert(ctx context.Context, c *model.OAuthClient) error {
	_, err := r.pg.pool.Exec(ctx, `
		INSERT INTO oauth_clients (
			client_id, client_secret_hash, name, is_public, token_endpoint_auth_method,
			redirect_uris, allowed_scopes, grant_types, require_consent,
			access_token_ttl_seconds, refresh_token_ttl_seconds, disabled
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		ON CONFLICT (client_id) DO UPDATE SET
			client_secret_hash = EXCLUDED.client_secret_hash,
			name = EXCLUDED.name,
			is_public = EXCLUDED.is_public,
			token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
			redirect_uris = EXCLUDED.redirect_uris,
			allowed_scopes = EXCLUDED.allowed_scopes,
			grant_types = EXCLUDED.grant_types,
			require_consent = EXCLUDED.require_consent,
			access_token_ttl_seconds = EXCLUDED.access_token_ttl_seconds,
			refresh_token_ttl_seconds = EXCLUDED.refresh_token_ttl_seconds,
			disabled = EXCLUDED.disabled,
			updated_at = now()`,
		c.ClientID, c.ClientSecretHash, c.Name, c.IsPublic, c.TokenEndpointAuthMethod,
		c.RedirectURIs, c.AllowedScopes, c.GrantTypes, c.RequireConsent,
		c.AccessTokenTTLSeconds, c.RefreshTokenTTLSeconds, c.Disabled,
	)
	if err != nil {
		return fmt.Errorf("repository: upsert client: %w", err)
	}
	return nil
}
