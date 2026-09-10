package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"iam-service/internal/model"
)

const userColumns = `id, email, display_name, email_verified, password_hash, status,
	failed_logins, locked_until, created_at, updated_at, deleted_at`

// UserRepo stores identities in Postgres.
type UserRepo struct {
	pg *Postgres
}

// NewUserRepo builds a user repository on the shared pool.
func NewUserRepo(pg *Postgres) *UserRepo { return &UserRepo{pg: pg} }

// ByEmail looks a user up by exact, case-insensitive email address.
func (r *UserRepo) ByEmail(ctx context.Context, email string) (*model.User, error) {
	return r.one(ctx, `SELECT `+userColumns+` FROM users WHERE email = $1 AND deleted_at IS NULL`, email)
}

// ByID looks a user up by identifier.
func (r *UserRepo) ByID(ctx context.Context, id string) (*model.User, error) {
	return r.one(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1 AND deleted_at IS NULL`, id)
}

func (r *UserRepo) one(ctx context.Context, query string, args ...any) (*model.User, error) {
	rows, err := r.pg.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("repository: query user: %w", err)
	}
	user, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[model.User])
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("repository: scan user: %w", err)
	}
	return &user, nil
}

// Create inserts a new user. A duplicate email yields ErrConflict.
func (r *UserRepo) Create(ctx context.Context, email, displayName, passwordHash string) (*model.User, error) {
	rows, err := r.pg.pool.Query(ctx, `
		INSERT INTO users (email, display_name, password_hash, status)
		VALUES ($1, $2, $3, $4)
		RETURNING `+userColumns, email, displayName, passwordHash, model.UserStatusActive)
	if err != nil {
		return nil, fmt.Errorf("repository: insert user: %w", err)
	}
	user, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[model.User])
	if err != nil {
		if isUniqueViolation(err) {
			return nil, fmt.Errorf("%w: email already registered", ErrConflict)
		}
		return nil, fmt.Errorf("repository: scan created user: %w", err)
	}
	return &user, nil
}

// UpdatePasswordHash replaces the stored password hash (also used for rehashing
// at login when the bcrypt cost changed).
func (r *UserRepo) UpdatePasswordHash(ctx context.Context, id, passwordHash string) error {
	return r.exec(ctx, `UPDATE users SET password_hash = $2, updated_at = now() WHERE id = $1`, id, passwordHash)
}

// SetStatus changes the account status (active, disabled, locked).
func (r *UserRepo) SetStatus(ctx context.Context, id, status string) error {
	return r.exec(ctx, `UPDATE users SET status = $2, updated_at = now() WHERE id = $1`, id, status)
}

// Status reads just the account status, used to refresh the Redis status cache.
func (r *UserRepo) Status(ctx context.Context, id string) (string, error) {
	var status string
	err := r.pg.pool.QueryRow(ctx, `SELECT status FROM users WHERE id = $1 AND deleted_at IS NULL`, id).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("repository: read user status: %w", err)
	}
	return status, nil
}

// RecordFailedLogin increments the failure counter and, once lockAfter attempts
// are reached, locks the account for lockFor. It reports whether the account is
// now locked and until when.
func (r *UserRepo) RecordFailedLogin(ctx context.Context, id string, lockAfter int, lockFor time.Duration) (bool, time.Time, error) {
	var (
		failedLogins int
		lockedUntil  *time.Time
	)
	err := r.pg.pool.QueryRow(ctx, `
		UPDATE users
		SET failed_logins = failed_logins + 1,
		    locked_until = CASE WHEN failed_logins + 1 >= $2 THEN now() + $3::interval ELSE locked_until END,
		    status = CASE WHEN failed_logins + 1 >= $2 THEN $4 ELSE status END,
		    updated_at = now()
		WHERE id = $1
		RETURNING failed_logins, locked_until`,
		id, lockAfter, lockFor.String(), model.UserStatusLocked,
	).Scan(&failedLogins, &lockedUntil)
	if err != nil {
		return false, time.Time{}, fmt.Errorf("repository: record failed login: %w", err)
	}

	locked := lockedUntil != nil && lockedUntil.After(time.Now())
	return locked, derefTime(lockedUntil), nil
}

// ResetFailedLogins clears the failure counter and any lock after a successful
// login.
func (r *UserRepo) ResetFailedLogins(ctx context.Context, id string) error {
	return r.exec(ctx, `
		UPDATE users
		SET failed_logins = 0, locked_until = NULL,
		    status = CASE WHEN status = $2 THEN $3 ELSE status END,
		    updated_at = now()
		WHERE id = $1`, id, model.UserStatusLocked, model.UserStatusActive)
}

// Roles returns the roles granted to the user.
func (r *UserRepo) Roles(ctx context.Context, userID string) ([]string, error) {
	rows, err := r.pg.pool.Query(ctx, `SELECT role FROM user_roles WHERE user_id = $1 ORDER BY role`, userID)
	if err != nil {
		return nil, fmt.Errorf("repository: query roles: %w", err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, fmt.Errorf("repository: scan role: %w", err)
		}
		roles = append(roles, role)
	}
	return roles, rows.Err()
}

// AssignRole grants a role to the user. Granting an existing role is a no-op,
// not an error: the statement affects no rows, so it must not go through the
// generic "must touch a row" helper.
func (r *UserRepo) AssignRole(ctx context.Context, userID, role string) error {
	if _, err := r.pg.pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role) VALUES ($1, $2) ON CONFLICT DO NOTHING`, userID, role); err != nil {
		return fmt.Errorf("repository: assign role: %w", err)
	}
	return nil
}

func (r *UserRepo) exec(ctx context.Context, query string, args ...any) error {
	tag, err := r.pg.pool.Exec(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("repository: exec: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}
