package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"iam-service/internal/model"
)

const (
	testIssuer   = "https://iam.test"
	testAudience = "test-api"
)

func newTestKeyring(t *testing.T) *Keyring {
	t.Helper()
	key, err := GenerateRSA(2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyring := NewKeyring()
	if err := keyring.Add(key); err != nil {
		t.Fatalf("add key: %v", err)
	}
	return keyring
}

func newClaims(audience, subject string, ttl time.Duration) *model.AccessClaims {
	now := time.Now()
	return &model.AccessClaims{
		TokenUse:  model.TokenUseAccess,
		SessionID: "sid-1",
		RegisteredClaims: jwtlib.RegisteredClaims{
			Subject:   subject,
			Audience:  jwtlib.ClaimStrings{audience},
			ExpiresAt: jwtlib.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwtlib.NewNumericDate(now),
		},
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	keyring := newTestKeyring(t)
	signer := NewSigner(keyring, testIssuer, testAudience, time.Second)

	token, err := signer.Sign(newClaims(testAudience, "user-1", time.Minute))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	claims, err := signer.VerifyAccess(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("subject = %q, want user-1", claims.Subject)
	}
	if claims.TokenUse != model.TokenUseAccess {
		t.Errorf("token_use = %q", claims.TokenUse)
	}
	if claims.ID == "" {
		t.Error("jti was not set")
	}
	if claims.Issuer != testIssuer {
		t.Errorf("iss = %q", claims.Issuer)
	}
}

func TestSignSetsIssueAndID(t *testing.T) {
	keyring := newTestKeyring(t)
	signer := NewSigner(keyring, testIssuer, testAudience, 0)

	first, err := signer.Sign(newClaims(testAudience, "user-1", time.Minute))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	second, err := signer.Sign(newClaims(testAudience, "user-1", time.Minute))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if first == second {
		t.Error("two tokens with different jti must not be identical")
	}
}

func TestVerifyRejectsAlgNone(t *testing.T) {
	keyring := newTestKeyring(t)
	signer := NewSigner(keyring, testIssuer, testAudience, 0)

	header := b64.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"` + keyring.ActiveKID() + `"}`))
	payloadBytes, err := json.Marshal(newClaims(testAudience, "attacker", time.Minute))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	payload := b64.EncodeToString(payloadBytes)

	if _, err := signer.VerifyAccess(header + "." + payload + "."); err == nil {
		t.Fatal("a token with alg=none was accepted")
	}
}

func TestVerifyRejectsSymmetricSignature(t *testing.T) {
	keyring := newTestKeyring(t)
	signer := NewSigner(keyring, testIssuer, testAudience, 0)

	// The classic confusion attack: sign with HMAC using the public key material.
	pub := keyring.Keys()[0].Public
	mac := hmac.New(sha256.New, []byte(pub.N.String()))
	header := b64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"` + keyring.ActiveKID() + `"}`))
	payloadBytes, _ := json.Marshal(newClaims(testAudience, "attacker", time.Minute))
	payload := b64.EncodeToString(payloadBytes)
	mac.Write([]byte(header + "." + payload))
	signature := b64.EncodeToString(mac.Sum(nil))

	if _, err := signer.VerifyAccess(header + "." + payload + "." + signature); err == nil {
		t.Fatal("an HS256 token was accepted by an RS256 verifier")
	}
}

func TestVerifyRejectsWrongAudienceAndIssuer(t *testing.T) {
	keyring := newTestKeyring(t)
	signer := NewSigner(keyring, testIssuer, testAudience, 0)
	other := NewSigner(keyring, "https://evil.test", "other-api", 0)

	token, err := other.Sign(newClaims("other-api", "user-1", time.Minute))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := signer.VerifyAccess(token); err == nil {
		t.Fatal("a token with the wrong issuer/audience was accepted")
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	keyring := newTestKeyring(t)
	signer := NewSigner(keyring, testIssuer, testAudience, 0)

	token, err := signer.Sign(newClaims(testAudience, "user-1", -time.Minute))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := signer.VerifyAccess(token); err == nil {
		t.Fatal("an expired token was accepted")
	}
}

func TestVerifyAccessRejectsIDToken(t *testing.T) {
	keyring := newTestKeyring(t)
	signer := NewSigner(keyring, testIssuer, testAudience, 0)

	claims := newClaims(testAudience, "user-1", time.Minute)
	claims.TokenUse = model.TokenUseID
	token, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := signer.VerifyAccess(token); err == nil {
		t.Fatal("an id_token was accepted as an access token")
	}
}

func TestJWKSPublishesActiveKeyFirst(t *testing.T) {
	keyring := newTestKeyring(t)
	older, err := GenerateRSA(2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	older.CreatedAt = time.Now().Add(-time.Hour)
	if err := keyring.Add(older); err != nil {
		t.Fatalf("add: %v", err)
	}

	payload, err := keyring.JWKS()
	if err != nil {
		t.Fatalf("jwks: %v", err)
	}
	var set struct {
		Keys []struct {
			KID string `json:"kid"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(payload, &set); err != nil {
		t.Fatalf("unmarshal jwks: %v", err)
	}
	if len(set.Keys) != 2 {
		t.Fatalf("jwks has %d keys, want 2", len(set.Keys))
	}
	if set.Keys[0].KID != keyring.ActiveKID() {
		t.Errorf("first published key = %q, want the active key %q", set.Keys[0].KID, keyring.ActiveKID())
	}
	for _, key := range set.Keys {
		if key.Use != "sig" || key.Alg != SigningAlgorithm {
			t.Errorf("key %s has use=%q alg=%q", key.KID, key.Use, key.Alg)
		}
		if key.N == "" || key.E == "" {
			t.Errorf("key %s is missing RSA parameters", key.KID)
		}
	}
}

func TestThumbprintIsStableAndUnique(t *testing.T) {
	first, err := GenerateRSA(2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	second, err := GenerateRSA(2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	a1, err := Thumbprint(first.Public)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	a2, err := Thumbprint(first.Public)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	b, err := Thumbprint(second.Public)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if a1 != a2 {
		t.Error("thumbprint is not deterministic")
	}
	if a1 == b {
		t.Error("different keys share a thumbprint")
	}
	if strings.ContainsAny(a1, "+/=") {
		t.Errorf("thumbprint %q is not base64url", a1)
	}
}

func TestLoadKeyringWritesAndReloadsKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "signing.pem")

	generated, wasGenerated, err := LoadKeyring(path, "", true)
	if err != nil {
		t.Fatalf("generate keyring: %v", err)
	}
	if !wasGenerated {
		t.Fatal("expected the key to be generated")
	}

	reloaded, wasGenerated, err := LoadKeyring(path, "", false)
	if err != nil {
		t.Fatalf("reload keyring: %v", err)
	}
	if wasGenerated {
		t.Fatal("a key file exists, nothing should be generated")
	}
	if reloaded.ActiveKID() != generated.ActiveKID() {
		t.Errorf("kid changed after reload: %q != %q", reloaded.ActiveKID(), generated.ActiveKID())
	}
}

func TestLoadKeyringRefusesToGenerateInProduction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.pem")
	if _, _, err := LoadKeyring(path, "", false); err == nil {
		t.Fatal("expected an error when no key exists and generation is disabled")
	}
}

func TestLookupRejectsExpiredKey(t *testing.T) {
	keyring := newTestKeyring(t)
	key := keyring.Keys()[0]
	key.ExpiresAt = time.Now().Add(-time.Minute)

	if _, err := keyring.Lookup(key.KID); err == nil {
		t.Fatal("an expired key was accepted for verification")
	}
}

func TestDecodeBase64URLHeader(t *testing.T) {
	// Guards the test helper: the encoder used in the tampering tests must match
	// the JWT wire format.
	if got := b64.EncodeToString([]byte("hi")); got != base64.RawURLEncoding.EncodeToString([]byte("hi")) {
		t.Fatalf("unexpected base64url encoding %q", got)
	}
}
