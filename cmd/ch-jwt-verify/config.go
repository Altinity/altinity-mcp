package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the YAML configuration consumed by the ch-jwt-verify sidecar.
// Fields can also be overridden via environment variables, which is how the
// Helm chart injects deployment-time values without re-templating a config
// file. Env-var names follow `CH_JWT_VERIFY_<UPPER_SNAKE>` to avoid clashes
// with the colocated ClickHouse process.
type Config struct {
	Listen   ListenConfig   `yaml:"listen"`
	OAuth    OAuthConfig    `yaml:"oauth"`
	Identity IdentityConfig `yaml:"identity"`
	// SettingsFromScope maps an OAuth scope name to a set of ClickHouse
	// session settings the sidecar returns in its /verify response. The CH
	// http_authentication handler applies these settings for the duration
	// of the request only — they cannot escape the per-query scope.
	SettingsFromScope map[string]map[string]string `yaml:"settings_from_scope"`
	Cache             CacheConfig                  `yaml:"cache"`
}

// ListenConfig selects the transport. Exactly one of Unix or TCP must be set;
// validateConfig enforces that and rejects mixed configs. Unix sockets are
// preferred for trust isolation (no port surface, fs permissions gate access);
// TCP is for environments where bind-mounted sockets aren't practical.
type ListenConfig struct {
	Unix string `yaml:"unix"`
	TCP  string `yaml:"tcp"`
}

// OAuthConfig is the subset of pkg/oauth knobs the sidecar needs. We don't
// reuse pkg/oauth.OAuthConfig verbatim because that struct carries broker-mode
// fields (client_id/client_secret/refresh-token TTL) which are meaningless on
// the sidecar — keeping a narrow type rejects misconfiguration at parse time.
type OAuthConfig struct {
	Issuer           string        `yaml:"issuer"`
	JWKSURL          string        `yaml:"jwks_url"`
	Audience         string        `yaml:"audience"`
	RequiredScopes   []string      `yaml:"required_scopes"`
	JWKSCacheTTL     time.Duration `yaml:"jwks_cache_ttl"`
	JWKSRefreshAhead time.Duration `yaml:"jwks_refresh_ahead"`
}

// IdentityConfig encapsulates the user-vs-claim matching rule and the domain
// allow-lists. UsernameClaim picks which JWT claim to match against the Basic
// header's user half (`email` for OIDC-style deployments, `sub` for opaque
// principals). MatchMode selects the comparison: `exact` requires byte-equal,
// `lowercase_equal` (the default) tolerates case differences common when
// operators provision CH users in lowercase.
type IdentityConfig struct {
	UsernameClaim        string   `yaml:"username_claim"`
	MatchMode            string   `yaml:"match_mode"`
	RequireEmailVerified bool     `yaml:"require_email_verified"`
	AllowedEmailDomains  []string `yaml:"allowed_email_domains"`
	AllowedHostedDomains []string `yaml:"allowed_hosted_domains"`
}

// CacheConfig governs the per-JWT verification cache. Positive entries are
// keyed by SHA256(JWT) and short-lived — refreshed often enough that clock
// skew between sidecar and IdP doesn't strand an expired token. Negative
// entries reuse the same key to suppress repeated cryptographic checks when
// an upstream replays a bad token.
type CacheConfig struct {
	PositiveTTL time.Duration `yaml:"positive_ttl"`
	NegativeTTL time.Duration `yaml:"negative_ttl"`
}

// LoadConfig reads cfgPath as YAML, then layers env-var overrides for the
// deployment-time fields the Helm chart sets. Returns the parsed config plus
// any validation error.
func LoadConfig(cfgPath string) (*Config, error) {
	cfg := defaultConfig()

	if cfgPath != "" {
		data, err := os.ReadFile(cfgPath)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}

	applyEnvOverrides(cfg)

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// defaultConfig sets values that the operator usually doesn't need to tune:
// JWKS cache TTL, identity-policy defaults, cache windows.
func defaultConfig() *Config {
	return &Config{
		OAuth: OAuthConfig{
			JWKSCacheTTL:     5 * time.Minute,
			JWKSRefreshAhead: 1 * time.Minute,
		},
		Identity: IdentityConfig{
			UsernameClaim:        "email",
			MatchMode:            "lowercase_equal",
			RequireEmailVerified: true,
		},
		Cache: CacheConfig{
			PositiveTTL: 30 * time.Second,
			NegativeTTL: 5 * time.Minute,
		},
	}
}

func applyEnvOverrides(cfg *Config) {
	if v := strings.TrimSpace(os.Getenv("CH_JWT_VERIFY_LISTEN_UNIX")); v != "" {
		cfg.Listen.Unix = v
	}
	if v := strings.TrimSpace(os.Getenv("CH_JWT_VERIFY_LISTEN_TCP")); v != "" {
		cfg.Listen.TCP = v
	}
	if v := strings.TrimSpace(os.Getenv("CH_JWT_VERIFY_OAUTH_ISSUER")); v != "" {
		cfg.OAuth.Issuer = v
	}
	if v := strings.TrimSpace(os.Getenv("CH_JWT_VERIFY_OAUTH_JWKS_URL")); v != "" {
		cfg.OAuth.JWKSURL = v
	}
	if v := strings.TrimSpace(os.Getenv("CH_JWT_VERIFY_OAUTH_AUDIENCE")); v != "" {
		cfg.OAuth.Audience = v
	}
}

func validateConfig(cfg *Config) error {
	if cfg.Listen.Unix == "" && cfg.Listen.TCP == "" {
		return fmt.Errorf("listen: either unix or tcp must be set")
	}
	if cfg.Listen.Unix != "" && cfg.Listen.TCP != "" {
		return fmt.Errorf("listen: unix and tcp are mutually exclusive")
	}
	if strings.TrimSpace(cfg.OAuth.Issuer) == "" && strings.TrimSpace(cfg.OAuth.JWKSURL) == "" {
		return fmt.Errorf("oauth: either issuer or jwks_url must be set")
	}
	if strings.TrimSpace(cfg.OAuth.Audience) == "" {
		return fmt.Errorf("oauth: audience is required (RFC 8707 byte-equal match)")
	}
	switch cfg.Identity.MatchMode {
	case "", "exact", "lowercase_equal":
	default:
		return fmt.Errorf("identity.match_mode: must be exact or lowercase_equal, got %q", cfg.Identity.MatchMode)
	}
	if cfg.Identity.MatchMode == "" {
		cfg.Identity.MatchMode = "lowercase_equal"
	}
	if cfg.Identity.UsernameClaim == "" {
		cfg.Identity.UsernameClaim = "email"
	}
	return nil
}
