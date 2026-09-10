-- +goose Up
-- Append-only audit trail of authentication and authorization events. No secrets
-- and no token values are ever stored here.
CREATE TABLE auth_events (
    id         bigserial PRIMARY KEY,
    event_type text NOT NULL,
    user_id    uuid REFERENCES users (id) ON DELETE SET NULL,
    client_id  text,
    session_id text,
    ip         inet,
    user_agent text,
    success    boolean NOT NULL,
    error_code text,
    request_id text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX auth_events_user_idx ON auth_events (user_id, created_at DESC);
CREATE INDEX auth_events_type_idx ON auth_events (event_type, created_at DESC);
CREATE INDEX auth_events_created_idx ON auth_events (created_at DESC);

-- +goose Down
DROP TABLE IF EXISTS auth_events;
