package service

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"iam-service/internal/model"
	apierr "iam-service/internal/pkg/errors"
)

func challengeFor(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestVerifyPKCES256(t *testing.T) {
	verifier := strings.Repeat("a", 43)
	if err := verifyPKCE(challengeFor(verifier), verifier); err != nil {
		t.Fatalf("a valid verifier was rejected: %v", err)
	}
}

func TestVerifyPKCERejects(t *testing.T) {
	verifier := strings.Repeat("b", 64)

	cases := []struct {
		name      string
		challenge string
		verifier  string
		wantCode  string
	}{
		{"missing challenge", "", verifier, apierr.CodeInvalidRequest},
		{"wrong verifier", challengeFor(verifier), strings.Repeat("c", 64), apierr.CodeInvalidGrant},
		{"too short verifier", challengeFor(verifier), "short", apierr.CodeInvalidGrant},
		{"too long verifier", challengeFor(verifier), strings.Repeat("d", 129), apierr.CodeInvalidGrant},
		{"plain challenge", verifier, verifier, apierr.CodeInvalidGrant},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyPKCE(tc.challenge, tc.verifier)
			if err == nil {
				t.Fatal("expected a rejection")
			}
			if !apierr.IsCode(err, tc.wantCode) {
				t.Fatalf("error code = %v, want %s", err, tc.wantCode)
			}
		})
	}
}

func TestValidateScope(t *testing.T) {
	clients := &ClientService{}
	client := &model.OAuthClient{
		ClientID:      "erplite-spa",
		AllowedScopes: []string{model.ScopeOpenID, model.ScopeEmail, model.ScopeOfflineAccess, "api.read"},
	}

	scope, err := clients.ValidateScope(client, "openid email api.read")
	if err != nil {
		t.Fatalf("valid scope rejected: %v", err)
	}
	if scope != "openid email api.read" {
		t.Errorf("scope = %q", scope)
	}

	// Duplicates collapse, order is preserved.
	scope, err = clients.ValidateScope(client, "openid openid api.read")
	if err != nil {
		t.Fatalf("valid scope rejected: %v", err)
	}
	if scope != "openid api.read" {
		t.Errorf("scope = %q, want duplicates removed", scope)
	}

	// An empty request grants the defaults, which never include offline_access.
	scope, err = clients.ValidateScope(client, "")
	if err != nil {
		t.Fatalf("default scope rejected: %v", err)
	}
	if strings.Contains(scope, model.ScopeOfflineAccess) {
		t.Errorf("default scope %q must not include offline_access", scope)
	}
	if !strings.Contains(scope, model.ScopeOpenID) {
		t.Errorf("default scope %q should include openid", scope)
	}

	if _, err := clients.ValidateScope(client, "openid api.admin"); !apierr.IsCode(err, apierr.CodeInvalidScope) {
		t.Fatalf("an unregistered scope was accepted: %v", err)
	}

	empty := &model.OAuthClient{ClientID: "x", AllowedScopes: nil}
	if _, err := clients.ValidateScope(empty, ""); !apierr.IsCode(err, apierr.CodeInvalidScope) {
		t.Fatalf("a client without defaults must not receive a scope: %v", err)
	}
}

func TestScopeHelpers(t *testing.T) {
	if got := model.JoinScope([]string{"a", "a", " b ", ""}); got != "a b" {
		t.Errorf("JoinScope = %q", got)
	}
	if got := model.SplitScope("  a   b "); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("SplitScope = %v", got)
	}
	if containsScope("openid email", model.ScopeEmail) != true {
		t.Error("containsScope missed an existing scope")
	}
	if containsScope("openid", "emails") {
		t.Error("containsScope matched a prefix")
	}
}

func TestClientRedirectURIMatching(t *testing.T) {
	client := &model.OAuthClient{
		RedirectURIs: []string{"http://localhost:3000/callback", "erplite://callback"},
	}
	cases := map[string]bool{
		"http://localhost:3000/callback":   true,
		"erplite://callback":               true,
		"http://localhost:3000/callback/":  false,
		"http://localhost:3001/callback":   false,
		"http://localhost:3000/callback#f": false,
		"":                                 false,
	}
	for uri, want := range cases {
		if got := client.IsRegisteredRedirectURI(uri); got != want {
			t.Errorf("IsRegisteredRedirectURI(%q) = %v, want %v", uri, got, want)
		}
	}
}

func TestHashClientSecretIsStableAndConstantLength(t *testing.T) {
	first := HashClientSecret("secret-value")
	second := HashClientSecret("secret-value")
	if first != second {
		t.Error("hashing is not deterministic")
	}
	if len(first) != 64 {
		t.Errorf("hash length = %d, want 64 hex characters", len(first))
	}
	if HashClientSecret("other") == first {
		t.Error("different secrets collide")
	}
}

func TestGenerateClientSecretHasEnoughEntropy(t *testing.T) {
	seen := make(map[string]struct{}, 32)
	for i := 0; i < 32; i++ {
		secret, err := GenerateClientSecret()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if len(secret) < 40 {
			t.Fatalf("secret %q is too short", secret)
		}
		if _, exists := seen[secret]; exists {
			t.Fatal("duplicate client secret generated")
		}
		seen[secret] = struct{}{}
	}
}

func TestNewOpaqueTokenIsRandomAndBounded(t *testing.T) {
	token, err := NewOpaqueToken(24)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(token) < 32 {
		t.Errorf("token %q is unexpectedly short", token)
	}
	other, err := NewOpaqueToken(24)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if token == other {
		t.Error("two tokens are identical")
	}

	tiny, err := NewOpaqueToken(4) // clamped to the 16-byte minimum
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(tiny) < 22 {
		t.Errorf("minimum entropy was not enforced: %q", tiny)
	}
}

func TestNewRefreshTokenShape(t *testing.T) {
	token, err := NewRefreshToken()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.HasPrefix(token, "rt_") {
		t.Errorf("refresh token %q lacks its prefix", token)
	}
	if len(token) < 45 {
		t.Errorf("refresh token %q is too short for 32 bytes of entropy", token)
	}
}
