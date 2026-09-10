// Package jwt implements RS256 signing, verification and the JWKS document of
// the authorization server.
//
// Tokens are signed with an RSA private key held by a Keyring, which supports
// key rotation: exactly one key signs, while previously published keys keep
// verifying tokens until they expire.
package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	// SigningAlgorithm is the only JWS algorithm this service issues.
	SigningAlgorithm = "RS256"
	// DefaultKeyBits is the size of generated RSA keys.
	DefaultKeyBits = 2048
	// MinKeyBits refuses weak keys at load time.
	MinKeyBits = 2048
)

// Keyring errors.
var (
	ErrNoActiveKey   = errors.New("jwt: keyring has no active signing key")
	ErrUnknownKeyID  = errors.New("jwt: unknown key id")
	ErrKeyExpired    = errors.New("jwt: signing key expired")
	ErrWeakKey       = errors.New("jwt: rsa key is too small")
	ErrNoKeyMaterial = errors.New("jwt: no key material found")
)

// Key is a signing or verification key with its public metadata.
type Key struct {
	KID       string
	Private   *rsa.PrivateKey
	Public    *rsa.PublicKey
	CreatedAt time.Time
	ExpiresAt time.Time // zero means "does not expire"
}

// Expired reports whether the key must no longer be used for verification.
func (k *Key) Expired(now time.Time) bool {
	return !k.ExpiresAt.IsZero() && !k.ExpiresAt.After(now)
}

// Keyring holds the signing keys of the service.
type Keyring struct {
	mu     sync.RWMutex
	active string
	keys   map[string]*Key
	order  []string
	now    func() time.Time
}

// NewKeyring returns an empty keyring.
func NewKeyring() *Keyring {
	return &Keyring{keys: make(map[string]*Key), now: time.Now}
}

// Add registers a key. The first key added becomes active.
func (k *Keyring) Add(key *Key) error {
	if key == nil || key.Public == nil {
		return fmt.Errorf("jwt: key must have a public key")
	}
	if key.Public.N.BitLen() < MinKeyBits {
		return fmt.Errorf("%w: %d bits", ErrWeakKey, key.Public.N.BitLen())
	}
	if key.KID == "" {
		kid, err := Thumbprint(key.Public)
		if err != nil {
			return err
		}
		key.KID = kid
	}
	if key.CreatedAt.IsZero() {
		key.CreatedAt = k.now()
	}

	k.mu.Lock()
	defer k.mu.Unlock()
	if _, exists := k.keys[key.KID]; !exists {
		k.order = append(k.order, key.KID)
	}
	k.keys[key.KID] = key
	if k.active == "" && key.Private != nil {
		k.active = key.KID
	}
	return nil
}

// SetActive selects the key used for signing.
func (k *Keyring) SetActive(kid string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	key, ok := k.keys[kid]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownKeyID, kid)
	}
	if key.Private == nil {
		return fmt.Errorf("jwt: key %s has no private part and cannot sign", kid)
	}
	k.active = kid
	return nil
}

// Active returns the signing key.
func (k *Keyring) Active() (*Key, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.active == "" {
		return nil, ErrNoActiveKey
	}
	key, ok := k.keys[k.active]
	if !ok {
		return nil, ErrNoActiveKey
	}
	return key, nil
}

// ActiveKID returns the id of the signing key, or an empty string.
func (k *Keyring) ActiveKID() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.active
}

// Lookup finds a verification key by key id, skipping expired keys.
func (k *Keyring) Lookup(kid string) (*Key, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	key, ok := k.keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKeyID, kid)
	}
	if key.Expired(k.now()) {
		return nil, fmt.Errorf("%w: %s", ErrKeyExpired, kid)
	}
	return key, nil
}

// Keys returns the keys known to the ring, active first, then newest first.
func (k *Keyring) Keys() []*Key {
	k.mu.RLock()
	order := make([]string, len(k.order))
	copy(order, k.order)
	keys := k.keys
	active := k.active
	k.mu.RUnlock()

	out := make([]*Key, 0, len(order))
	if key, ok := keys[active]; ok {
		out = append(out, key)
	}
	rest := make([]*Key, 0, len(order))
	for _, kid := range order {
		if kid == active {
			continue
		}
		if key, ok := keys[kid]; ok {
			rest = append(rest, key)
		}
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i].CreatedAt.After(rest[j].CreatedAt) })
	return append(out, rest...)
}

// JWKS renders the public JSON Web Key Set (RFC 7517). Only signing-capable
// public keys are published, active key first.
func (k *Keyring) JWKS() ([]byte, error) {
	now := time.Now()
	set := jose.JSONWebKeySet{}
	for _, key := range k.Keys() {
		if key.Expired(now) {
			continue
		}
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key:       key.Public,
			KeyID:     key.KID,
			Algorithm: SigningAlgorithm,
			Use:       "sig",
		})
	}
	return json.Marshal(set)
}

// Thumbprint computes the RFC 7638 JWK thumbprint used as the key id.
func Thumbprint(pub *rsa.PublicKey) (string, error) {
	if pub == nil {
		return "", fmt.Errorf("jwt: nil public key")
	}
	jwk := jose.JSONWebKey{Key: pub}
	thumb, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("jwt: thumbprint: %w", err)
	}
	return b64.EncodeToString(thumb), nil
}

// GenerateRSA creates a fresh RSA key pair with the given size.
func GenerateRSA(bits int) (*Key, error) {
	if bits < MinKeyBits {
		bits = DefaultKeyBits
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("jwt: generate rsa key: %w", err)
	}
	key := &Key{Private: priv, Public: &priv.PublicKey, CreatedAt: time.Now()}
	kid, err := Thumbprint(key.Public)
	if err != nil {
		return nil, err
	}
	key.KID = kid
	return key, nil
}

// MarshalPrivateKeyPEM encodes the key as PKCS#8 PEM.
func MarshalPrivateKeyPEM(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("jwt: marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// WritePrivateKeyPEM writes the private key to path with 0600 permissions.
func WritePrivateKeyPEM(path string, key *rsa.PrivateKey) error {
	data, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("jwt: create key directory: %w", err)
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("jwt: write key: %w", err)
	}
	return nil
}

// LoadKeyring loads keys from a PEM file (possibly containing several blocks) or
// from every *.pem file in a directory. The first private key found is the
// active signing key unless explicitKID selects another one.
//
// When path is empty and allowGenerate is true (development only) an ephemeral
// key is generated in memory: tokens then stop verifying after a restart.
func LoadKeyring(path, explicitKID string, allowGenerate bool) (*Keyring, bool, error) {
	keyring := NewKeyring()
	if path == "" {
		if !allowGenerate {
			return nil, false, fmt.Errorf("jwt: signing key path is not configured and generation is disabled")
		}
		key, err := GenerateRSA(DefaultKeyBits)
		if err != nil {
			return nil, false, err
		}
		if err := keyring.Add(key); err != nil {
			return nil, false, err
		}
		return keyring, true, nil
	}

	files, err := keyFiles(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && allowGenerate {
			key, genErr := GenerateRSA(DefaultKeyBits)
			if genErr != nil {
				return nil, false, genErr
			}
			if writeErr := WritePrivateKeyPEM(path, key.Private); writeErr != nil {
				return nil, false, writeErr
			}
			if addErr := keyring.Add(key); addErr != nil {
				return nil, false, addErr
			}
			return keyring, true, nil
		}
		return nil, false, err
	}

	found := false
	for _, file := range files {
		keys, err := parseKeyFile(file)
		if err != nil {
			return nil, false, err
		}
		for _, key := range keys {
			if err := keyring.Add(key); err != nil {
				return nil, false, err
			}
			found = true
		}
	}
	if !found {
		return nil, false, fmt.Errorf("%w in %s", ErrNoKeyMaterial, path)
	}
	if explicitKID != "" {
		if err := keyring.SetActive(explicitKID); err != nil {
			return nil, false, err
		}
	}
	return keyring, false, nil
}

func keyFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("jwt: read key directory: %w", err)
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".pem" {
			continue
		}
		files = append(files, filepath.Join(path, entry.Name()))
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%w in %s", ErrNoKeyMaterial, path)
	}
	sort.Strings(files)
	return files, nil
}

func parseKeyFile(path string) ([]*Key, error) {
	//nolint:gosec // the key file path comes from the service configuration.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("jwt: read key file: %w", err)
	}

	var keys []*Key
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		switch block.Type {
		case "PRIVATE KEY":
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("jwt: parse pkcs8 key %s: %w", path, err)
			}
			priv, ok := parsed.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("jwt: key %s is not an RSA key", path)
			}
			keys = append(keys, &Key{Private: priv, Public: &priv.PublicKey, CreatedAt: modTime(path)})
		case "RSA PRIVATE KEY":
			priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("jwt: parse pkcs1 key %s: %w", path, err)
			}
			keys = append(keys, &Key{Private: priv, Public: &priv.PublicKey, CreatedAt: modTime(path)})
		case "PUBLIC KEY":
			parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("jwt: parse public key %s: %w", path, err)
			}
			pub, ok := parsed.(*rsa.PublicKey)
			if !ok {
				return nil, fmt.Errorf("jwt: public key %s is not an RSA key", path)
			}
			keys = append(keys, &Key{Public: pub, CreatedAt: modTime(path)})
		default:
			return nil, fmt.Errorf("jwt: unsupported PEM block %q in %s", block.Type, path)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w in %s", ErrNoKeyMaterial, path)
	}

	// A key loaded before its replacement is meant for verification only: keep
	// the newest private key as the sole signing candidate.
	var newest *Key
	for _, key := range keys {
		if key.Private == nil {
			continue
		}
		if newest == nil || key.CreatedAt.After(newest.CreatedAt) {
			newest = key
		}
	}
	for _, key := range keys {
		if key.Private != nil && key != newest {
			key.Private = nil
		}
	}
	return keys, nil
}

func modTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Now()
	}
	return info.ModTime()
}
