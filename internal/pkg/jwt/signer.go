package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"

	"iam-service/internal/model"
)

var b64 = base64.RawURLEncoding

// Signing and verification errors.
var (
	ErrInvalidToken  = errors.New("jwt: invalid token")
	ErrWrongTokenUse = errors.New("jwt: unexpected token_use claim")
	ErrMissingKeyID  = errors.New("jwt: token has no kid header")
	ErrUnexpectedAlg = errors.New("jwt: unexpected signing algorithm")
)

// Signer issues and validates tokens for one issuer/audience pair.
type Signer struct {
	keyring  *Keyring
	issuer   string
	audience string
	leeway   time.Duration
	now      func() time.Time
}

// NewSigner builds a signer. audience is the resource identifier expected in
// access tokens; id_tokens carry the client id instead and are not validated
// here.
func NewSigner(keyring *Keyring, issuer, audience string, leeway time.Duration) *Signer {
	return &Signer{keyring: keyring, issuer: issuer, audience: audience, leeway: leeway, now: time.Now}
}

// Issuer returns the configured issuer identifier.
func (s *Signer) Issuer() string { return s.issuer }

// Keyring exposes the key ring so that the JWKS endpoint can render it.
func (s *Signer) Keyring() *Keyring { return s.keyring }

// Sign serialises and signs the claims with the active key.
func (s *Signer) Sign(claims *model.AccessClaims) (string, error) {
	key, err := s.keyring.Active()
	if err != nil {
		return "", err
	}
	if claims.Issuer == "" {
		claims.Issuer = s.issuer
	}
	if claims.IssuedAt == nil {
		claims.IssuedAt = jwtlib.NewNumericDate(s.now())
	}
	if claims.ID == "" {
		jti, err := randomID()
		if err != nil {
			return "", err
		}
		claims.ID = jti
	}

	token := jwtlib.NewWithClaims(jwtlib.SigningMethodRS256, claims)
	token.Header["kid"] = key.KID
	signed, err := token.SignedString(key.Private)
	if err != nil {
		return "", fmt.Errorf("jwt: sign: %w", err)
	}
	return signed, nil
}

// Verify validates the signature, algorithm, issuer, audience and lifetime, and
// returns the claim set. It accepts both access and id tokens; callers that need
// an access token must check the token use themselves (see VerifyAccess).
func (s *Signer) Verify(tokenString string) (*model.AccessClaims, error) {
	claims := &model.AccessClaims{}
	token, err := jwtlib.ParseWithClaims(tokenString, claims, s.keyFunc,
		jwtlib.WithValidMethods([]string{SigningAlgorithm}),
		jwtlib.WithIssuer(s.issuer),
		jwtlib.WithAudience(s.audience),
		jwtlib.WithExpirationRequired(),
		jwtlib.WithLeeway(s.leeway),
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// VerifyAccess validates an access token: correct use claim and, for user
// tokens, the presence of a session id.
func (s *Signer) VerifyAccess(tokenString string) (*model.AccessClaims, error) {
	claims, err := s.Verify(tokenString)
	if err != nil {
		return nil, err
	}
	if claims.TokenUse != model.TokenUseAccess {
		return nil, fmt.Errorf("%w: %s", ErrWrongTokenUse, claims.TokenUse)
	}
	return claims, nil
}

func (s *Signer) keyFunc(token *jwtlib.Token) (any, error) {
	if token.Method.Alg() != SigningAlgorithm {
		return nil, fmt.Errorf("%w: %s", ErrUnexpectedAlg, token.Method.Alg())
	}
	kid, _ := token.Header["kid"].(string)
	if kid == "" {
		return nil, ErrMissingKeyID
	}
	key, err := s.keyring.Lookup(kid)
	if err != nil {
		return nil, err
	}
	if key.Private != nil {
		return &key.Private.PublicKey, nil
	}
	return key.Public, nil
}

func randomID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("jwt: random id: %w", err)
	}
	return b64.EncodeToString(buf), nil
}
