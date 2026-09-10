package model

import "time"

// User statuses.
const (
	UserStatusActive   = "active"
	UserStatusDisabled = "disabled"
	UserStatusLocked   = "locked"
)

// Roles seeded by migrations. Real authorisation is expected to grow from here.
const (
	RoleUser  = "user"
	RoleAdmin = "admin"
)

// User is the local identity record. Field tags are understood by
// pgx.RowToStructByName.
type User struct {
	ID            string     `db:"id"`
	Email         string     `db:"email"`
	DisplayName   string     `db:"display_name"`
	EmailVerified bool       `db:"email_verified"`
	PasswordHash  string     `db:"password_hash"`
	Status        string     `db:"status"`
	FailedLogins  int        `db:"failed_logins"`
	LockedUntil   *time.Time `db:"locked_until"`
	CreatedAt     time.Time  `db:"created_at"`
	UpdatedAt     time.Time  `db:"updated_at"`
	DeletedAt     *time.Time `db:"deleted_at"`
}

// IsActive reports whether the account may authenticate right now.
func (u *User) IsActive() bool { return u.Status == UserStatusActive && u.DeletedAt == nil }

// IsLocked reports whether the account is temporarily locked out.
func (u *User) IsLocked(now time.Time) bool { return u.LockedFor(now) > 0 }

// LockedFor returns the remaining lockout duration, or zero when not locked.
func (u *User) LockedFor(now time.Time) time.Duration {
	if u.LockedUntil == nil {
		return 0
	}
	if d := u.LockedUntil.Sub(now); d > 0 {
		return d
	}
	return 0
}
