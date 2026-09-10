package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

// Environment names understood by the service.
const (
	EnvDevelopment = "development"
	EnvTest        = "test"
	EnvProduction  = "production"
)

// Config is the full service configuration, loaded from YAML with environment
// variable overrides (key "redis.addr" is overridable as REDIS_ADDR).
type Config struct {
	Environment string          `mapstructure:"environment"`
	Server      ServerConfig    `mapstructure:"server"`
	OAuth       OAuthConfig     `mapstructure:"oauth"`
	Database    DatabaseConfig  `mapstructure:"database"`
	Redis       RedisConfig     `mapstructure:"redis"`
	RateLimit   RateLimitConfig `mapstructure:"ratelimit"`
	Log         LogConfig       `mapstructure:"log"`
}

type ServerConfig struct {
	Host            string        `mapstructure:"host"`
	Port            int           `mapstructure:"port"`
	AdminHost       string        `mapstructure:"admin_host"`
	AdminPort       int           `mapstructure:"admin_port"`
	ReadTimeout     time.Duration `mapstructure:"read_timeout"`
	WriteTimeout    time.Duration `mapstructure:"write_timeout"`
	IdleTimeout     time.Duration `mapstructure:"idle_timeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdown_timeout"`
	MaxBodyBytes    int64         `mapstructure:"max_body_bytes"`
	TrustedProxies  []string      `mapstructure:"trusted_proxies"`
}

// OAuthConfig carries the authorization server identity and token lifetimes.
type OAuthConfig struct {
	IssuerURL             string        `mapstructure:"issuer_url"`
	Audience              string        `mapstructure:"audience"`
	SigningKeyPath        string        `mapstructure:"signing_key_path"`
	SigningKeyID          string        `mapstructure:"signing_key_id"`
	AllowDevKeyGeneration bool          `mapstructure:"allow_dev_key_generation"`
	AccessTTL             time.Duration `mapstructure:"access_ttl"`
	ServiceAccessTTL      time.Duration `mapstructure:"service_access_ttl"`
	RefreshTTL            time.Duration `mapstructure:"refresh_ttl"`
	RefreshAbsoluteTTL    time.Duration `mapstructure:"refresh_absolute_ttl"`
	CodeTTL               time.Duration `mapstructure:"code_ttl"`
	InteractionTTL        time.Duration `mapstructure:"interaction_ttl"`
	RefreshReplayGrace    time.Duration `mapstructure:"refresh_replay_grace"`
	RefreshLockTTL        time.Duration `mapstructure:"refresh_lock_ttl"`
	RefreshLockWait       time.Duration `mapstructure:"refresh_lock_wait"`
	ClockSkew             time.Duration `mapstructure:"clock_skew"`
	UserStatusCacheTTL    time.Duration `mapstructure:"user_status_cache_ttl"`
	RequireConsentDefault bool          `mapstructure:"require_consent_default"`
	MaxSessionsPerUser    int           `mapstructure:"max_sessions_per_user"`
	ClientCredentials     bool          `mapstructure:"client_credentials_enabled"`
	ActiveSessionSampler  time.Duration `mapstructure:"active_session_sampler"`
}

type DatabaseConfig struct {
	DSN             string        `mapstructure:"dsn"`
	MaxConns        int32         `mapstructure:"max_conns"`
	MinConns        int32         `mapstructure:"min_conns"`
	MaxConnLifetime time.Duration `mapstructure:"max_conn_lifetime"`
	MaxConnIdleTime time.Duration `mapstructure:"max_conn_idle_time"`
	ConnectTimeout  time.Duration `mapstructure:"connect_timeout"`
	HealthTimeout   time.Duration `mapstructure:"health_timeout"`
}

type RedisConfig struct {
	Addr         string        `mapstructure:"addr"`
	Password     string        `mapstructure:"password"`
	DB           int           `mapstructure:"db"`
	PoolSize     int           `mapstructure:"pool_size"`
	MinIdleConns int           `mapstructure:"min_idle_conns"`
	DialTimeout  time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	// FailClosed makes /verify reject requests (503) when Redis is unreachable
	// instead of trusting the token signature alone.
	FailClosed bool `mapstructure:"fail_closed"`
}

type RateLimitConfig struct {
	LoginPerAccount     int           `mapstructure:"login_per_account"`
	LoginPerIP          int           `mapstructure:"login_per_ip"`
	AuthorizePerIP      int           `mapstructure:"authorize_per_ip"`
	TokenPerClient      int           `mapstructure:"token_per_client"`
	Window              time.Duration `mapstructure:"window"`
	FailedLoginsToLock  int           `mapstructure:"failed_logins_to_lock"`
	AccountLockDuration time.Duration `mapstructure:"account_lock_duration"`
}

type LogConfig struct {
	Level string `mapstructure:"level"`
}

// Load reads the configuration from CONFIG_PATH (default configs/config.yaml),
// applies environment overrides and validates the result. A missing file is not
// an error: defaults plus environment variables are enough to start.
func Load() (*Config, error) {
	path := os.Getenv("CONFIG_PATH")
	if path == "" {
		path = "configs/config.yaml"
	}

	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")
	setDefaults(v)

	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	// Aliases for conventional environment variable names.
	for _, alias := range [][2]string{
		{"database.dsn", "DATABASE_URL"},
		{"redis.addr", "REDIS_ADDR"},
		{"redis.password", "REDIS_PASSWORD"},
		{"oauth.issuer_url", "OAUTH_ISSUER_URL"},
		{"oauth.audience", "OAUTH_AUDIENCE"},
		{"oauth.signing_key_path", "OAUTH_SIGNING_KEY_PATH"},
		{"log.level", "LOG_LEVEL"},
		{"server.trusted_proxies", "TRUSTED_PROXIES"},
	} {
		_ = v.BindEnv(alias[0], alias[1])
	}

	if err := v.ReadInConfig(); err != nil {
		if !os.IsNotExist(err) {
			var notFound viper.ConfigFileNotFoundError
			if !asConfigNotFound(err, &notFound) {
				return nil, fmt.Errorf("read config %s: %w", path, err)
			}
		}
	}

	var cfg Config
	err := v.Unmarshal(&cfg, viper.DecodeHook(mapstructure.ComposeDecodeHookFunc(
		mapstructure.StringToTimeDurationHookFunc(),
		mapstructure.StringToSliceHookFunc(","),
	)))
	if err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}

	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func asConfigNotFound(err error, target *viper.ConfigFileNotFoundError) bool {
	if e, ok := err.(viper.ConfigFileNotFoundError); ok {
		*target = e
		return true
	}
	return false
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("environment", EnvDevelopment)
	v.SetDefault("log.level", "info")

	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.admin_host", "127.0.0.1")
	v.SetDefault("server.admin_port", 9090)
	v.SetDefault("server.read_timeout", 10*time.Second)
	v.SetDefault("server.write_timeout", 20*time.Second)
	v.SetDefault("server.idle_timeout", 120*time.Second)
	v.SetDefault("server.shutdown_timeout", 30*time.Second)
	v.SetDefault("server.max_body_bytes", int64(1<<20))

	v.SetDefault("oauth.issuer_url", "http://localhost:8088")
	v.SetDefault("oauth.audience", "erplite-api")
	v.SetDefault("oauth.allow_dev_key_generation", true)
	v.SetDefault("oauth.access_ttl", 10*time.Minute)
	v.SetDefault("oauth.service_access_ttl", 5*time.Minute)
	v.SetDefault("oauth.refresh_ttl", 720*time.Hour)
	v.SetDefault("oauth.refresh_absolute_ttl", 2160*time.Hour)
	v.SetDefault("oauth.code_ttl", 60*time.Second)
	v.SetDefault("oauth.interaction_ttl", 15*time.Minute)
	v.SetDefault("oauth.refresh_replay_grace", 10*time.Second)
	v.SetDefault("oauth.refresh_lock_ttl", 5*time.Second)
	v.SetDefault("oauth.refresh_lock_wait", time.Second)
	v.SetDefault("oauth.clock_skew", 60*time.Second)
	v.SetDefault("oauth.user_status_cache_ttl", 60*time.Second)
	v.SetDefault("oauth.require_consent_default", false)
	v.SetDefault("oauth.max_sessions_per_user", 50)
	v.SetDefault("oauth.client_credentials_enabled", true)
	v.SetDefault("oauth.active_session_sampler", time.Minute)

	v.SetDefault("database.max_conns", 25)
	v.SetDefault("database.min_conns", 2)
	v.SetDefault("database.max_conn_lifetime", 30*time.Minute)
	v.SetDefault("database.max_conn_idle_time", 5*time.Minute)
	v.SetDefault("database.connect_timeout", 10*time.Second)
	v.SetDefault("database.health_timeout", 2*time.Second)

	v.SetDefault("redis.pool_size", 50)
	v.SetDefault("redis.min_idle_conns", 5)
	v.SetDefault("redis.dial_timeout", 5*time.Second)
	v.SetDefault("redis.read_timeout", 3*time.Second)
	v.SetDefault("redis.write_timeout", 3*time.Second)
	v.SetDefault("redis.fail_closed", true)

	v.SetDefault("ratelimit.login_per_account", 5)
	v.SetDefault("ratelimit.login_per_ip", 20)
	v.SetDefault("ratelimit.authorize_per_ip", 120)
	v.SetDefault("ratelimit.token_per_client", 60)
	v.SetDefault("ratelimit.window", 15*time.Minute)
	v.SetDefault("ratelimit.failed_logins_to_lock", 5)
	v.SetDefault("ratelimit.account_lock_duration", 15*time.Minute)
}

func (c *Config) normalize() {
	c.OAuth.IssuerURL = strings.TrimRight(strings.TrimSpace(c.OAuth.IssuerURL), "/")
	c.OAuth.Audience = strings.TrimSpace(c.OAuth.Audience)
	c.OAuth.SigningKeyPath = strings.TrimSpace(c.OAuth.SigningKeyPath)
	c.OAuth.SigningKeyID = strings.TrimSpace(c.OAuth.SigningKeyID)
	c.Database.DSN = strings.TrimSpace(c.Database.DSN)
	c.Redis.Addr = strings.TrimSpace(c.Redis.Addr)
	c.Log.Level = strings.TrimSpace(c.Log.Level)
	if c.Environment == "" {
		c.Environment = EnvDevelopment
	}

	proxies := make([]string, 0, len(c.Server.TrustedProxies))
	for _, proxy := range c.Server.TrustedProxies {
		if trimmed := strings.TrimSpace(proxy); trimmed != "" {
			proxies = append(proxies, trimmed)
		}
	}
	c.Server.TrustedProxies = proxies
}

// Validate fails fast so that a misconfigured instance never starts silently.
func (c *Config) Validate() error {
	switch c.Environment {
	case EnvDevelopment, EnvTest, EnvProduction:
	default:
		return fmt.Errorf("config: unknown environment %q", c.Environment)
	}

	if c.OAuth.IssuerURL == "" {
		return fmt.Errorf("config: oauth.issuer_url is required")
	}
	issuer, err := url.Parse(c.OAuth.IssuerURL)
	if err != nil || issuer.Host == "" {
		return fmt.Errorf("config: oauth.issuer_url %q is not an absolute URL", c.OAuth.IssuerURL)
	}
	if issuer.Scheme != "https" && c.IsProduction() {
		return fmt.Errorf("config: oauth.issuer_url must use https in production")
	}
	if c.OAuth.Audience == "" {
		return fmt.Errorf("config: oauth.audience is required")
	}
	if c.IsProduction() && c.OAuth.SigningKeyPath == "" {
		return fmt.Errorf("config: oauth.signing_key_path is required in production")
	}
	if c.OAuth.AccessTTL <= 0 || c.OAuth.CodeTTL <= 0 || c.OAuth.InteractionTTL <= 0 || c.OAuth.ServiceAccessTTL <= 0 {
		return fmt.Errorf("config: token lifetimes must be positive")
	}
	if c.OAuth.RefreshTTL < c.OAuth.AccessTTL {
		return fmt.Errorf("config: oauth.refresh_ttl (%s) must be >= oauth.access_ttl (%s)", c.OAuth.RefreshTTL, c.OAuth.AccessTTL)
	}
	if c.OAuth.RefreshAbsoluteTTL < c.OAuth.RefreshTTL {
		return fmt.Errorf("config: oauth.refresh_absolute_ttl (%s) must be >= oauth.refresh_ttl (%s)", c.OAuth.RefreshAbsoluteTTL, c.OAuth.RefreshTTL)
	}
	if c.OAuth.RefreshReplayGrace <= 0 {
		return fmt.Errorf("config: oauth.refresh_replay_grace must be positive")
	}
	if c.OAuth.MaxSessionsPerUser < 1 {
		return fmt.Errorf("config: oauth.max_sessions_per_user must be >= 1")
	}
	if c.Database.DSN == "" {
		return fmt.Errorf("config: database.dsn is required (env DATABASE_URL)")
	}
	if c.Redis.Addr == "" {
		return fmt.Errorf("config: redis.addr is required (env REDIS_ADDR)")
	}
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("config: server.port %d is out of range", c.Server.Port)
	}
	if c.Server.AdminPort <= 0 || c.Server.AdminPort > 65535 {
		return fmt.Errorf("config: server.admin_port %d is out of range", c.Server.AdminPort)
	}
	if c.Server.AdminPort == c.Server.Port {
		return fmt.Errorf("config: server.admin_port must differ from server.port")
	}
	if c.Server.MaxBodyBytes <= 0 {
		return fmt.Errorf("config: server.max_body_bytes must be positive")
	}
	if c.RateLimit.Window <= 0 || c.RateLimit.FailedLoginsToLock < 1 {
		return fmt.Errorf("config: ratelimit.window and ratelimit.failed_logins_to_lock must be positive")
	}
	return nil
}

func (c *Config) IsProduction() bool { return c.Environment == EnvProduction }

func (c *Config) IsDevelopment() bool { return c.Environment == EnvDevelopment }
