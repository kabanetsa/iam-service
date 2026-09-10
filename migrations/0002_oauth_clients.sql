-- +goose Up
CREATE TABLE oauth_clients (
    client_id                  text PRIMARY KEY,
    client_secret_hash         text,
    name                       text NOT NULL,
    is_public                  boolean NOT NULL DEFAULT false,
    token_endpoint_auth_method text NOT NULL DEFAULT 'client_secret_basic',
    redirect_uris              text[] NOT NULL DEFAULT '{}',
    allowed_scopes             text[] NOT NULL DEFAULT '{openid}',
    grant_types                text[] NOT NULL DEFAULT '{authorization_code,refresh_token}',
    require_consent            boolean NOT NULL DEFAULT false,
    access_token_ttl_seconds   int,
    refresh_token_ttl_seconds  int,
    disabled                   boolean NOT NULL DEFAULT false,
    created_at                 timestamptz NOT NULL DEFAULT now(),
    updated_at                 timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT oauth_clients_auth_method_check
        CHECK (token_endpoint_auth_method IN ('client_secret_basic', 'client_secret_post', 'none')),
    CONSTRAINT oauth_clients_public_consistency
        CHECK (NOT is_public OR token_endpoint_auth_method = 'none' OR client_secret_hash IS NULL),
    CONSTRAINT oauth_clients_public_needs_pkce
        CHECK (NOT is_public OR NOT ('authorization_code' = ANY (grant_types)) OR array_length(redirect_uris, 1) >= 1),
    CONSTRAINT oauth_clients_ttl_positive
        CHECK ((access_token_ttl_seconds IS NULL OR access_token_ttl_seconds > 0)
           AND (refresh_token_ttl_seconds IS NULL OR refresh_token_ttl_seconds > 0))
);

CREATE INDEX oauth_clients_active_idx ON oauth_clients (client_id) WHERE NOT disabled;

-- +goose Down
DROP TABLE IF EXISTS oauth_clients;
