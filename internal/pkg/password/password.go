// Package password hashes and verifies user passwords with bcrypt.
//
// Verification always performs the same amount of work, whether or not the user
// exists, so that response timing does not leak account existence.
package password

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

const (
	// Cost is the bcrypt work factor used for new hashes.
	Cost = 12
	// MinLength is the minimum accepted password length.
	MinLength = 12
	// MaxLength is bcrypt's input limit in bytes: longer inputs are silently
	// truncated by bcrypt, which is a security hazard, so they are rejected.
	MaxLength = 72
	// HashPrefix marks hashes produced by this service.
	HashPrefix = "$2"
)

// dummyHash is a valid bcrypt hash of a random throwaway string. It exists only
// so that verifying a password for an unknown account costs the same as
// verifying one for a known account.
const dummyHash = "$2a$12$axgi2SZw4GuFntfhNo4KwOm5hPlkUPeF0VOvBXDtHtltMqfOkG6Wu"

// ErrTooLong is returned when a password exceeds bcrypt's input limit.
var ErrTooLong = fmt.Errorf("password: length must not exceed %d bytes", MaxLength)

// Validate applies the password policy. Callers should also reject passwords
// equal to the account's own identifiers.
func Validate(password string) error {
	if len(password) < MinLength {
		return fmt.Errorf("password: length must be at least %d characters", MinLength)
	}
	if len(password) > MaxLength {
		return ErrTooLong
	}
	return nil
}

// Hash returns a bcrypt hash of the password at the current cost.
func Hash(password string) (string, error) {
	if len(password) > MaxLength {
		return "", ErrTooLong
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), Cost)
	if err != nil {
		return "", fmt.Errorf("password: hash: %w", err)
	}
	return string(hash), nil
}

// Verify reports whether the password matches the stored hash. Any bcrypt error
// (malformed hash, mismatch) is reported as a plain false.
func Verify(hash, password string) bool {
	if hash == "" || len(password) > MaxLength {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// VerifyDummy burns the same work as Verify for an absent or unusable account.
func VerifyDummy(password string) {
	if len(password) > MaxLength {
		password = password[:MaxLength]
	}
	_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
}

// NeedsRehash reports whether the stored hash was produced with a weaker cost or
// a different algorithm and should be replaced after a successful login.
func NeedsRehash(hash string) bool {
	if hash == "" {
		return true
	}
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return true
	}
	return cost < Cost
}

// IsBcryptHash reports whether the value is a parsable bcrypt hash.
func IsBcryptHash(hash string) bool {
	_, err := bcrypt.Cost([]byte(hash))
	return err == nil
}
