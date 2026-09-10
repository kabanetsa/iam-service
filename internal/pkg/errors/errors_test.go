package errors

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestStatusMapping(t *testing.T) {
	cases := []struct {
		err    *Error
		status int
	}{
		{InvalidRequest("bad"), http.StatusBadRequest},
		{InvalidGrant("bad"), http.StatusBadRequest},
		{InvalidScope("bad"), http.StatusBadRequest},
		{UnsupportedGrantType("bad"), http.StatusBadRequest},
		{InvalidClient("bad"), http.StatusUnauthorized},
		{InvalidToken("bad"), http.StatusUnauthorized},
		{AccessDenied("bad"), http.StatusForbidden},
		{New(CodeInsufficientScope, "bad"), http.StatusForbidden},
		{RateLimited("slow down", time.Second), http.StatusTooManyRequests},
		{Unavailable("down"), http.StatusServiceUnavailable},
		{ServerError("boom"), http.StatusInternalServerError},
	}
	for _, tc := range cases {
		if got := tc.err.Status(); got != tc.status {
			t.Errorf("%s: status = %d, want %d", tc.err.Code, got, tc.status)
		}
	}
}

func TestFromHidesInternalErrors(t *testing.T) {
	cause := errors.New("connection refused to postgres://user:secret@host")
	protoErr := From(fmt.Errorf("wrapped: %w", cause))

	if protoErr.Code != CodeServerError {
		t.Fatalf("code = %q, want server_error", protoErr.Code)
	}
	if strings.Contains(protoErr.Description, "secret") {
		t.Fatalf("the public description leaks internals: %q", protoErr.Description)
	}
	if !errors.Is(protoErr, cause) {
		t.Error("the cause must stay reachable for logging")
	}
}

func TestFromKeepsProtocolError(t *testing.T) {
	original := InvalidGrant("code already used")
	if got := From(original); got != original {
		t.Errorf("From() returned a different error: %v", got)
	}
	if From(nil) != nil {
		t.Error("From(nil) must be nil")
	}
}

func TestWithCauseDoesNotMutateOriginal(t *testing.T) {
	original := InvalidRequest("bad request")
	withCause := original.WithCause(errors.New("boom"))

	if original.Unwrap() != nil {
		t.Error("the original error was mutated")
	}
	if withCause.Unwrap() == nil {
		t.Error("the clone lost its cause")
	}
	if withCause.Code != original.Code || withCause.Description != original.Description {
		t.Error("the clone changed the public fields")
	}
}

func TestIsCode(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", InvalidClient("nope"))
	if !IsCode(err, CodeInvalidClient) {
		t.Error("IsCode did not unwrap the error")
	}
	if IsCode(err, CodeInvalidGrant) {
		t.Error("IsCode matched the wrong code")
	}
	if IsCode(errors.New("plain"), CodeInvalidClient) {
		t.Error("IsCode matched a plain error")
	}
}

func TestWWWAuthenticate(t *testing.T) {
	bearer := WWWAuthenticate(InvalidToken("expired"))
	if !strings.HasPrefix(bearer, "Bearer ") || !strings.Contains(bearer, `error="invalid_token"`) {
		t.Errorf("unexpected challenge: %q", bearer)
	}
	basic := WWWAuthenticate(InvalidClient("unknown client"))
	if !strings.HasPrefix(basic, "Basic ") {
		t.Errorf("client errors must use a Basic challenge, got %q", basic)
	}
	if WWWAuthenticate(nil) != "" {
		t.Error("nil error must produce an empty challenge")
	}
}

func TestRetryAfterIsKeptForRateLimits(t *testing.T) {
	err := RateLimited("too many attempts", 90*time.Second)
	if err.RetryAfter != 90*time.Second {
		t.Fatalf("RetryAfter = %s", err.RetryAfter)
	}
}
