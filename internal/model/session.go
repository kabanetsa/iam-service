package model

import "time"

// Session is the server-side login state, stored in Redis and addressed by the
// `sid` claim of every access token issued from it. A session owns exactly one
// refresh-token family (FamilyID).
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	FamilyID  string    `json:"family_id"`
	Scope     string    `json:"scope"`
	AuthTime  time.Time `json:"auth_time"`
	IPAddress string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Expired reports whether the session has outlived its refresh lifetime.
func (s *Session) Expired(now time.Time) bool { return !s.ExpiresAt.After(now) }

// AuthorizationCode is an issued, not yet redeemed authorization code. It is
// stored under the hash of the code value and consumed exactly once. Sessions
// and refresh-token families are created when the code is redeemed, so an
// abandoned login leaves no state behind.
type AuthorizationCode struct {
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	Nonce               string    `json:"nonce,omitempty"`
	AuthTime            time.Time `json:"auth_time"`
	IssuedAt            time.Time `json:"issued_at"`
}

// Interaction is the pending /authorize request carried through the login and
// consent pages. It also carries the CSRF token of those forms, and the id of
// the user who authenticated in the meantime.
type Interaction struct {
	ID                  string    `json:"id"`
	ClientID            string    `json:"client_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	State               string    `json:"state,omitempty"`
	Nonce               string    `json:"nonce,omitempty"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	CSRFToken           string    `json:"csrf_token"`
	AuthenticatedUserID string    `json:"authenticated_user_id,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
}
