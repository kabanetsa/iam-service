// Package errors models OAuth 2.0 protocol errors (RFC 6749 §5.2, RFC 6750,
// RFC 7009) and maps them onto HTTP status codes.
//
// The public shape of an error is deliberately narrow: an internal cause can be
// attached for logging but is never rendered into a response.
package errors

import (
	stderrors "errors"
	"fmt"
	"net/http"
	"time"
)

// Error codes.
const (
	CodeInvalidRequest          = "invalid_request"
	CodeInvalidClient           = "invalid_client"
	CodeInvalidGrant            = "invalid_grant"
	CodeUnauthorizedClient      = "unauthorized_client"
	CodeUnsupportedGrantType    = "unsupported_grant_type"
	CodeUnsupportedResponseType = "unsupported_response_type"
	CodeInvalidScope            = "invalid_scope"
	CodeAccessDenied            = "access_denied"
	CodeServerError             = "server_error"
	CodeTemporarilyUnavailable  = "temporarily_unavailable"
	CodeInvalidToken            = "invalid_token"
	CodeInsufficientScope       = "insufficient_scope"
	// CodeRateLimited is not an OAuth code: it maps to HTTP 429 responses of the
	// service's own endpoints.
	CodeRateLimited = "rate_limited"
)

// Error is a protocol error with a safe public description.
type Error struct {
	Code        string
	Description string
	RetryAfter  time.Duration
	cause       error
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Description, e.cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

// Unwrap exposes the internal cause to errors.Is/As for logging and tests.
func (e *Error) Unwrap() error { return e.cause }

// Status returns the HTTP status code for the error code.
func (e *Error) Status() int {
	switch e.Code {
	case CodeInvalidClient, CodeInvalidToken:
		return http.StatusUnauthorized
	case CodeInsufficientScope, CodeAccessDenied:
		return http.StatusForbidden
	case CodeRateLimited:
		return http.StatusTooManyRequests
	case CodeTemporarilyUnavailable:
		return http.StatusServiceUnavailable
	case CodeServerError:
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

// WithCause attaches an internal cause. The cause is never sent to clients.
func (e *Error) WithCause(err error) *Error {
	clone := *e
	clone.cause = err
	return &clone
}

// WithDescription replaces the public description.
func (e *Error) WithDescription(description string) *Error {
	clone := *e
	clone.Description = description
	return &clone
}

// New creates an error with the given code and public description.
func New(code, description string) *Error {
	return &Error{Code: code, Description: description}
}

// Constructors for the common cases.
func InvalidRequest(description string) *Error { return New(CodeInvalidRequest, description) }
func InvalidClient(description string) *Error  { return New(CodeInvalidClient, description) }
func InvalidGrant(description string) *Error   { return New(CodeInvalidGrant, description) }
func InvalidScope(description string) *Error   { return New(CodeInvalidScope, description) }
func InvalidToken(description string) *Error   { return New(CodeInvalidToken, description) }
func AccessDenied(description string) *Error   { return New(CodeAccessDenied, description) }
func ServerError(description string) *Error    { return New(CodeServerError, description) }
func Unavailable(description string) *Error    { return New(CodeTemporarilyUnavailable, description) }
func UnauthorizedClient(description string) *Error {
	return New(CodeUnauthorizedClient, description)
}
func UnsupportedGrantType(description string) *Error {
	return New(CodeUnsupportedGrantType, description)
}
func UnsupportedResponseType(description string) *Error {
	return New(CodeUnsupportedResponseType, description)
}

// RateLimited reports a rate limit or lockout with the time until retry.
func RateLimited(description string, retryAfter time.Duration) *Error {
	return &Error{Code: CodeRateLimited, Description: description, RetryAfter: retryAfter}
}

// From converts any error into a protocol error. Unknown errors become
// server_error with a generic description, keeping the cause for logging.
func From(err error) *Error {
	if err == nil {
		return nil
	}
	var protoErr *Error
	if stderrors.As(err, &protoErr) {
		return protoErr
	}
	return New(CodeServerError, "an internal error occurred").WithCause(err)
}

// IsCode reports whether err carries the given protocol error code.
func IsCode(err error, code string) bool {
	var protoErr *Error
	if !stderrors.As(err, &protoErr) {
		return false
	}
	return protoErr.Code == code
}

// WWWAuthenticate renders the WWW-Authenticate challenge value for err, as used
// by /verify and /oauth/userinfo (RFC 6750 §3).
func WWWAuthenticate(err error) string {
	protoErr := From(err)
	if protoErr == nil {
		return ""
	}
	if protoErr.Code == CodeInvalidClient {
		return `Basic realm="iam"`
	}
	challenge := fmt.Sprintf(`Bearer error=%q`, protoErr.Code)
	if protoErr.Description != "" {
		challenge += fmt.Sprintf(`, error_description=%q`, protoErr.Description)
	}
	return challenge
}
