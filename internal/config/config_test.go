package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// loadWithEnv builds a configuration from environment variables only, so the
// tests do not depend on the checked-in development file.
func loadWithEnv(t *testing.T, env map[string]string) (*Config, error) {
	t.Helper()
	t.Setenv("CONFIG_PATH", filepath.Join(t.TempDir(), "absent.yaml"))
	for key, value := range env {
		t.Setenv(key, value)
	}
	return Load()
}

func validEnv() map[string]string {
	return map[string]string{
		"DATABASE_URL":      "postgres://user:pass@localhost:5432/iam",
		"REDIS_ADDR":        "localhost:6379",
		"OAUTH_ISSUER_URL":  "http://localhost:8088",
		"OAUTH_AUDIENCE":    "erplite-api",
		"ENVIRONMENT":       EnvDevelopment,
		"TRUSTED_PROXIES":   "127.0.0.1/32,10.0.0.0/8",
		"SERVER_ADMIN_PORT": "9090",
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := loadWithEnv(t, validEnv())
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if cfg.OAuth.AccessTTL != 10*time.Minute {
		t.Errorf("access_ttl = %s, want 10m", cfg.OAuth.AccessTTL)
	}
	if cfg.OAuth.RefreshReplayGrace != 10*time.Second {
		t.Errorf("refresh_replay_grace = %s, want 10s", cfg.OAuth.RefreshReplayGrace)
	}
	if !cfg.Redis.FailClosed {
		t.Error("fail_closed must default to true: revocation has to stay authoritative")
	}
	if len(cfg.Server.TrustedProxies) != 2 {
		t.Errorf("trusted_proxies = %v, want the two configured CIDRs", cfg.Server.TrustedProxies)
	}
	if cfg.IsProduction() {
		t.Error("the default environment must not be production")
	}
}

func TestLoadRejectsMissingDependencies(t *testing.T) {
	// An environment variable set to whitespace is not "unset": it must be
	// rejected rather than silently falling back to a default.
	cases := map[string]map[string]string{
		"no database":    {"DATABASE_URL": ""},
		"no redis":       {"REDIS_ADDR": ""},
		"blank issuer":   {"OAUTH_ISSUER_URL": " "},
		"blank audience": {"OAUTH_AUDIENCE": " "},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			env := validEnv()
			for key, value := range overrides {
				env[key] = value
			}
			if _, err := loadWithEnv(t, env); err == nil {
				t.Fatal("expected a validation error")
			}
		})
	}
}

func TestProductionRequiresHTTPSAndKeyFile(t *testing.T) {
	env := validEnv()
	env["ENVIRONMENT"] = EnvProduction
	env["OAUTH_ISSUER_URL"] = "http://iam.erplite.local"
	env["OAUTH_SIGNING_KEY_PATH"] = "/etc/iam/keys/signing.pem"

	_, err := loadWithEnv(t, env)
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected an https requirement, got %v", err)
	}

	env["OAUTH_ISSUER_URL"] = "https://iam.erplite.local"
	env["OAUTH_SIGNING_KEY_PATH"] = ""
	if _, err := loadWithEnv(t, env); err == nil {
		t.Fatal("production must refuse to start without a signing key")
	}

	env["OAUTH_SIGNING_KEY_PATH"] = "/etc/iam/keys/signing.pem"
	cfg, err := loadWithEnv(t, env)
	if err != nil {
		t.Fatalf("a valid production configuration was rejected: %v", err)
	}
	if !cfg.IsProduction() {
		t.Error("environment was not applied")
	}
	if cfg.OAuth.AllowDevKeyGeneration && cfg.IsProduction() {
		t.Log("dev key generation stays enabled in the file but is ignored in production by serve")
	}
}

func TestIssuerTrailingSlashIsNormalised(t *testing.T) {
	env := validEnv()
	env["OAUTH_ISSUER_URL"] = "https://iam.erplite.local/"
	cfg, err := loadWithEnv(t, env)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.OAuth.IssuerURL != "https://iam.erplite.local" {
		t.Errorf("issuer = %q, want it without a trailing slash", cfg.OAuth.IssuerURL)
	}
}

func TestValidateLifetimeOrdering(t *testing.T) {
	base := func() *Config {
		cfg, err := loadWithEnv(t, validEnv())
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		return cfg
	}

	cfg := base()
	cfg.OAuth.RefreshTTL = time.Minute
	cfg.OAuth.AccessTTL = time.Hour
	if err := cfg.Validate(); err == nil {
		t.Error("refresh_ttl shorter than access_ttl must be rejected")
	}

	cfg = base()
	cfg.OAuth.RefreshTTL = 30 * 24 * time.Hour
	cfg.OAuth.RefreshAbsoluteTTL = time.Hour
	if err := cfg.Validate(); err == nil {
		t.Error("refresh_absolute_ttl shorter than refresh_ttl must be rejected")
	}

	cfg = base()
	cfg.Server.AdminPort = cfg.Server.Port
	if err := cfg.Validate(); err == nil {
		t.Error("an admin port equal to the public port must be rejected")
	}

	cfg = base()
	cfg.OAuth.IssuerURL = "not-a-url"
	if err := cfg.Validate(); err == nil {
		t.Error("a relative issuer must be rejected")
	}
}

func TestUnknownEnvironmentIsRejected(t *testing.T) {
	env := validEnv()
	env["ENVIRONMENT"] = "staging-ish"
	if _, err := loadWithEnv(t, env); err == nil {
		t.Fatal("expected an unknown environment to be rejected")
	}
}

// Viper ignores environment variables that are set to an empty string, so an
// empty override falls back to the value from the file or the default. The
// behaviour is pinned here because it decides when validation can catch a
// missing setting: only a non-empty value (e.g. whitespace) will replace one.
func TestEmptyEnvironmentValueFallsBackToDefault(t *testing.T) {
	env := validEnv()
	env["OAUTH_ISSUER_URL"] = ""

	cfg, err := loadWithEnv(t, env)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.OAuth.IssuerURL == "" {
		t.Fatal("an empty environment value must not blank out a default")
	}
}
