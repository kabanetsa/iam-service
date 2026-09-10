-- +goose Up
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email          citext NOT NULL UNIQUE,
    display_name   text NOT NULL DEFAULT '',
    email_verified boolean NOT NULL DEFAULT false,
    password_hash  text NOT NULL,
    status         text NOT NULL DEFAULT 'active',
    failed_logins  int NOT NULL DEFAULT 0,
    locked_until   timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    deleted_at     timestamptz,
    CONSTRAINT users_status_check CHECK (status IN ('active', 'disabled', 'locked'))
);

CREATE INDEX users_status_idx ON users (status) WHERE deleted_at IS NULL;

-- Reference data for authorisation. Roles are carried into tokens as a claim.
CREATE TABLE roles (
    name        text PRIMARY KEY,
    description text NOT NULL DEFAULT ''
);

CREATE TABLE user_roles (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role    text NOT NULL REFERENCES roles (name) ON DELETE CASCADE,
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role)
);

INSERT INTO roles (name, description) VALUES
    ('user',  'Обычный пользователь приложения'),
    ('admin', 'Администратор, доступ к управляющим операциям')
ON CONFLICT (name) DO NOTHING;

-- +goose Down
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;
