package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// ClickHouseProtocol defines the protocol used to connect to ClickHouse
type ClickHouseProtocol string

const (
	// HTTPProtocol uses HTTP protocol for ClickHouse connection
	HTTPProtocol ClickHouseProtocol = "http"
	// TCPProtocol uses native TCP protocol for ClickHouse connection
	TCPProtocol ClickHouseProtocol = "tcp"
)

// TLSConfig defines TLS configuration for ClickHouse connection
type TLSConfig struct {
	Enabled            bool   `json:"enabled" yaml:"enabled" flag:"clickhouse-tls" env:"CLICKHOUSE_TLS" desc:"Enable TLS for ClickHouse connection"`
	CaCert             string `json:"ca_cert" yaml:"ca_cert" flag:"clickhouse-tls-ca-cert" env:"CLICKHOUSE_TLS_CA_CERT" desc:"Path to CA certificate for ClickHouse connection"`
	ClientCert         string `json:"client_cert" yaml:"client_cert" flag:"clickhouse-tls-client-cert" env:"CLICKHOUSE_TLS_CLIENT_CERT" desc:"Path to client certificate for ClickHouse connection"`
	ClientKey          string `json:"client_key" yaml:"client_key" flag:"clickhouse-tls-client-key" env:"CLICKHOUSE_TLS_CLIENT_KEY" desc:"Path to client key for ClickHouse connection"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify" yaml:"insecure_skip_verify" flag:"clickhouse-tls-insecure-skip-verify" env:"CLICKHOUSE_TLS_INSECURE_SKIP_VERIFY" desc:"Skip server certificate verification"`
}

// ClickHouseConfig defines configuration for connecting to ClickHouse
type ClickHouseConfig struct {
	Host             string             `json:"host" yaml:"host" flag:"clickhouse-host" env:"CLICKHOUSE_HOST" default:"localhost" desc:"ClickHouse server host"`
	Port             int                `json:"port" yaml:"port" flag:"clickhouse-port" env:"CLICKHOUSE_PORT" default:"8123" desc:"ClickHouse server port"`
	Database         string             `json:"database" yaml:"database" flag:"clickhouse-database" env:"CLICKHOUSE_DATABASE" default:"default" desc:"ClickHouse database name"`
	Username         string             `json:"username" yaml:"username" flag:"clickhouse-username" env:"CLICKHOUSE_USERNAME" default:"default" desc:"ClickHouse username"`
	Password         string             `json:"password" yaml:"password" flag:"clickhouse-password" env:"CLICKHOUSE_PASSWORD" desc:"ClickHouse password"`
	Protocol         ClickHouseProtocol `json:"protocol" yaml:"protocol" flag:"clickhouse-protocol" env:"CLICKHOUSE_PROTOCOL" default:"http" desc:"ClickHouse connection protocol (http/tcp)"`
	TLS              TLSConfig          `json:"tls" yaml:"tls"`
	ReadOnly         bool               `json:"read_only" yaml:"read_only" flag:"read-only" env:"CLICKHOUSE_READ_ONLY" desc:"Connect to ClickHouse in read-only mode"`
	MaxExecutionTime int                `json:"max_execution_time" yaml:"max_execution_time" flag:"clickhouse-max-execution-time" env:"CLICKHOUSE_MAX_EXECUTION_TIME" default:"600" desc:"ClickHouse max execution time in seconds"`
	Limit            int                `json:"limit" yaml:"limit" flag:"clickhouse-limit" env:"CLICKHOUSE_LIMIT" desc:"Maximum limit for query results (0 means no limit)"`
	HttpHeaders      map[string]string  `json:"http_headers" yaml:"http_headers" flag:"clickhouse-http-headers" env:"CLICKHOUSE_HTTP_HEADERS" desc:"HTTP Headers for ClickHouse"`
	ExtraSettings    map[string]string  `json:"extra_settings,omitempty" yaml:"extra_settings,omitempty" desc:"Per-request ClickHouse settings injected by tool_input_settings"`
	// ClusterName + ClusterSecret enable interserver-secret authentication.
	// When ClusterSecret is set, altinity-mcp connects as a trusted cluster
	// peer (no username/password) and executes each query as the
	// MCP-authenticated user. The target ClickHouse must list altinity-mcp
	// under <remote_servers><cluster><secret>...</secret></cluster>. Only
	// the TCP protocol is supported.
	ClusterName   string `json:"cluster_name,omitempty" yaml:"cluster_name,omitempty" flag:"clickhouse-cluster-name" env:"CLICKHOUSE_CLUSTER_NAME" desc:"ClickHouse cluster name for interserver-secret auth"`
	ClusterSecret string `json:"cluster_secret,omitempty" yaml:"cluster_secret,omitempty" flag:"clickhouse-cluster-secret" env:"CLICKHOUSE_CLUSTER_SECRET" desc:"Shared interserver secret; when set altinity-mcp authenticates as a trusted cluster peer"`
	// MaxQueryLength caps the size in bytes of a single SQL query string sent by a client.
	// Default 10 MB when 0. Set to a negative number to disable the check.
	MaxQueryLength int `json:"max_query_length,omitempty" yaml:"max_query_length,omitempty" flag:"clickhouse-max-query-length" env:"CLICKHOUSE_MAX_QUERY_LENGTH" desc:"Max bytes of SQL query string accepted from clients (0=default 10MB, <0=disabled)"`
}

// defaultMaxQueryLength is the default cap applied when MaxQueryLength is 0.
const defaultMaxQueryLength = 10 * 1024 * 1024 // 10 MiB

// EffectiveMaxQueryLength returns the effective cap after applying defaults/disable semantics.
// Returns 0 if the check is disabled.
func (c ClickHouseConfig) EffectiveMaxQueryLength() int {
	if c.MaxQueryLength < 0 {
		return 0
	}
	if c.MaxQueryLength == 0 {
		return defaultMaxQueryLength
	}
	return c.MaxQueryLength
}

// MCPTransport defines the transport used for MCP communication
type MCPTransport string

const (
	// StdioTransport uses standard input/output for MCP communication
	StdioTransport MCPTransport = "stdio"
	// HTTPTransport uses HTTP for MCP communication
	HTTPTransport MCPTransport = "http"
	// SSETransport uses Server-Sent Events for MCP communication
	SSETransport MCPTransport = "sse"
)

// ServerTLSConfig defines TLS configuration for the MCP server
type ServerTLSConfig struct {
	Enabled  bool   `json:"enabled" yaml:"enabled" flag:"server-tls" env:"MCP_SERVER_TLS" desc:"Enable TLS for the MCP server"`
	CertFile string `json:"cert_file" yaml:"cert_file" flag:"server-tls-cert-file" env:"MCP_SERVER_TLS_CERT_FILE" desc:"Path to TLS certificate file"`
	KeyFile  string `json:"key_file" yaml:"key_file" flag:"server-tls-key-file" env:"MCP_SERVER_TLS_KEY_FILE" desc:"Path to TLS key file"`
	CaCert   string `json:"ca_cert" yaml:"ca_cert" flag:"server-tls-ca-cert" env:"MCP_SERVER_TLS_CA_CERT" desc:"Path to CA certificate for client certificate validation"`
}

// JWEConfig defines configuration for JWE authentication
type JWEConfig struct {
	Enabled      bool   `json:"enabled" yaml:"enabled" flag:"allow-jwe-auth" env:"MCP_ALLOW_JWE_AUTH" desc:"Enable JWE encryption for ClickHouse connection"`
	JWESecretKey string `json:"jwe_secret_key" yaml:"jwe_secret_key" flag:"jwe-secret-key" env:"MCP_JWE_SECRET_KEY" desc:"Secret key for JWE token encryption/decryption"`
	JWTSecretKey string `json:"jwt_secret_key" yaml:"jwt_secret_key" flag:"jwt-secret-key" env:"MCP_JWT_SECRET_KEY" desc:"Secret key for JWT signature verification"`
}

// OAuthConfig defines configuration for OAuth 2.0 authentication.
//
// Every flag-tagged field is settable via CLI flag (`flag:` tag) or env var
// (`env:` tag). The env-var convention here is `MCP_OAUTH_<UPPER_SNAKE>` so
// secrets like GatingSecretKey can be injected from a Kubernetes Secret via
// the Helm chart's env: array using valueFrom.secretKeyRef.
type OAuthConfig struct {
	// Mode controls whether altinity-mcp forwards external OAuth bearers or gates them into local MCP tokens.
	// "forward" is the production path: pass the end-user bearer through to ClickHouse.
	// "gating" keeps the built-in limited OAuth facade that issues its own tokens.
	Mode string `json:"mode" yaml:"mode" flag:"oauth-mode" env:"MCP_OAUTH_MODE" desc:"OAuth operating mode (forward/gating)"`

	// Enabled enables OAuth authentication
	Enabled bool `json:"enabled" yaml:"enabled" flag:"oauth-enabled" env:"MCP_OAUTH_ENABLED" desc:"Enable OAuth 2.0 authentication"`

	// Issuer is the OAuth token issuer URL for token validation (e.g., "https://accounts.google.com")
	Issuer string `json:"issuer" yaml:"issuer" flag:"oauth-issuer" env:"MCP_OAUTH_ISSUER" desc:"OAuth token issuer URL for validation"`

	// JWKSURL is the URL to fetch JSON Web Key Set for token validation
	// If empty, will be discovered from issuer's .well-known/openid-configuration
	JWKSURL string `json:"jwks_url" yaml:"jwks_url" flag:"oauth-jwks-url" env:"MCP_OAUTH_JWKS_URL" desc:"URL to fetch JWKS for token validation"`

	// Audience is the expected audience claim in the token
	Audience string `json:"audience" yaml:"audience" flag:"oauth-audience" env:"MCP_OAUTH_AUDIENCE" desc:"Expected audience claim in OAuth token"`

	// PublicResourceURL is the externally visible protected resource base URL.
	// When empty, it is inferred from the request host/prefix or Audience path.
	PublicResourceURL string `json:"public_resource_url" yaml:"public_resource_url" flag:"oauth-public-resource-url" env:"MCP_OAUTH_PUBLIC_RESOURCE_URL" desc:"Externally visible protected resource base URL"`

	// PublicAuthServerURL is the externally visible authorization server base URL.
	// When empty, it is inferred from the request host/prefix or Issuer path.
	PublicAuthServerURL string `json:"public_auth_server_url" yaml:"public_auth_server_url" flag:"oauth-public-auth-server-url" env:"MCP_OAUTH_PUBLIC_AUTH_SERVER_URL" desc:"Externally visible OAuth authorization server base URL"`

	// ClientID is the OAuth client ID (used for client credentials flow or validation)
	ClientID string `json:"client_id" yaml:"client_id" flag:"oauth-client-id" env:"MCP_OAUTH_CLIENT_ID" desc:"OAuth client ID"`

	// ClientSecret is the OAuth client secret (used for client credentials flow)
	ClientSecret string `json:"client_secret" yaml:"client_secret" flag:"oauth-client-secret" env:"MCP_OAUTH_CLIENT_SECRET" desc:"OAuth client secret"`

	// TokenURL is the OAuth token endpoint URL (used for client credentials flow)
	TokenURL string `json:"token_url" yaml:"token_url" flag:"oauth-token-url" env:"MCP_OAUTH_TOKEN_URL" desc:"OAuth token endpoint URL"`

	// AuthURL is the OAuth authorization endpoint URL (used for authorization code flow)
	AuthURL string `json:"auth_url" yaml:"auth_url" flag:"oauth-auth-url" env:"MCP_OAUTH_AUTH_URL" desc:"OAuth authorization endpoint URL"`

	// UserInfoURL is the upstream OpenID Connect userinfo endpoint URL.
	// If empty, it will be discovered from issuer metadata when needed.
	UserInfoURL string `json:"userinfo_url" yaml:"userinfo_url" flag:"oauth-userinfo-url" env:"MCP_OAUTH_USERINFO_URL" desc:"OAuth/OpenID Connect userinfo endpoint URL"`

	// Scopes is the list of OAuth scopes to request
	Scopes []string `json:"scopes" yaml:"scopes" flag:"oauth-scopes" env:"MCP_OAUTH_SCOPES" desc:"OAuth scopes to request"`

	// UpstreamOfflineAccess opts forward mode into requesting offline_access from the upstream IdP
	// and wrapping the returned refresh token in a stateless JWE handed back to the MCP client.
	// Default false: forward mode behaves exactly as before (no refresh token issued, refresh grant rejected).
	UpstreamOfflineAccess bool `json:"upstream_offline_access" yaml:"upstream_offline_access" flag:"oauth-upstream-offline-access" env:"MCP_OAUTH_UPSTREAM_OFFLINE_ACCESS" desc:"Forward mode: request offline_access upstream and issue JWE-wrapped refresh tokens"`

	// RequiredScopes is the list of scopes required for access (token must have all of these)
	RequiredScopes []string `json:"required_scopes" yaml:"required_scopes" flag:"oauth-required-scopes" env:"MCP_OAUTH_REQUIRED_SCOPES" desc:"Required OAuth scopes for access"`

	// ClickHouseHeaderName is the header name to use when forwarding OAuth token to ClickHouse
	// Default: "Authorization" (sends as "Bearer {token}")
	// When set to a custom header, the raw token is sent without "Bearer " prefix
	ClickHouseHeaderName string `json:"clickhouse_header_name" yaml:"clickhouse_header_name" flag:"oauth-clickhouse-header-name" env:"MCP_OAUTH_CLICKHOUSE_HEADER_NAME" desc:"Header name for forwarding OAuth token to ClickHouse"`

	// ClaimsToHeaders maps OAuth token claims to ClickHouse HTTP headers
	// Example: {"sub": "X-ClickHouse-User", "email": "X-ClickHouse-Email"}
	ClaimsToHeaders map[string]string `json:"claims_to_headers" yaml:"claims_to_headers" flag:"oauth-claims-to-headers" env:"MCP_OAUTH_CLAIMS_TO_HEADERS" desc:"Map OAuth claims to ClickHouse HTTP headers"`

	// AllowedEmailDomains constrains accepted principals by email domain.
	AllowedEmailDomains []string `json:"allowed_email_domains" yaml:"allowed_email_domains" flag:"oauth-allowed-email-domains" env:"MCP_OAUTH_ALLOWED_EMAIL_DOMAINS" desc:"Allowed email domains for verified OAuth identities"`

	// AllowedHostedDomains constrains accepted principals by hosted/workspace domain claim such as Google hd.
	AllowedHostedDomains []string `json:"allowed_hosted_domains" yaml:"allowed_hosted_domains" flag:"oauth-allowed-hosted-domains" env:"MCP_OAUTH_ALLOWED_HOSTED_DOMAINS" desc:"Allowed hosted/workspace domains for verified OAuth identities"`

	// RequireEmailVerified rejects identities where email_verified is false when an email claim is present.
	RequireEmailVerified bool `json:"require_email_verified" yaml:"require_email_verified" flag:"oauth-require-email-verified" env:"MCP_OAUTH_REQUIRE_EMAIL_VERIFIED" desc:"Require email_verified=true on OAuth identities"`

	// RegistrationPath configures the relative path for dynamic client registration.
	RegistrationPath string `json:"registration_path" yaml:"registration_path" flag:"oauth-registration-path" env:"MCP_OAUTH_REGISTRATION_PATH" desc:"Relative path for OAuth client registration endpoint"`

	// AuthorizationPath configures the relative path for the authorization endpoint.
	AuthorizationPath string `json:"authorization_path" yaml:"authorization_path" flag:"oauth-authorization-path" env:"MCP_OAUTH_AUTHORIZATION_PATH" desc:"Relative path for OAuth authorization endpoint"`

	// CallbackPath configures the relative path for the upstream IdP callback handler.
	CallbackPath string `json:"callback_path" yaml:"callback_path" flag:"oauth-callback-path" env:"MCP_OAUTH_CALLBACK_PATH" desc:"Relative path for OAuth upstream callback endpoint"`

	// TokenPath configures the relative path for the token endpoint.
	TokenPath string `json:"token_path" yaml:"token_path" flag:"oauth-token-path" env:"MCP_OAUTH_TOKEN_PATH" desc:"Relative path for OAuth token endpoint"`

	// ConsentPath configures the relative path for the per-DCR-client consent
	// form (confused-deputy mitigation, MCP §Confused Deputy Problem).
	ConsentPath string `json:"consent_path" yaml:"consent_path" flag:"oauth-consent-path" env:"MCP_OAUTH_CONSENT_PATH" desc:"Relative path for OAuth consent endpoint"`

	// DisableDCRConsent skips the per-DCR-client consent screen between the
	// upstream IdP callback and the gating-code redirect. The MCP spec marks
	// this consent as MUST when DCR is exposed (§Confused Deputy Problem) —
	// disabling it is a deliberate spec deviation, only safe when the
	// deployment has another trust gate (typically AllowedEmailDomains or
	// AllowedHostedDomains) that prevents an attacker-DCR'd client from
	// being usable against an arbitrary phished victim. See
	// docs/oauth_compatibility_hypotheses.md for the trade-off discussion.
	DisableDCRConsent bool `json:"disable_dcr_consent" yaml:"disable_dcr_consent" flag:"oauth-disable-dcr-consent" env:"MCP_OAUTH_DISABLE_DCR_CONSENT" desc:"Skip the per-DCR-client consent screen (spec-deviation, only safe when AllowedEmailDomains or AllowedHostedDomains is set)"`

	// UpstreamIssuerAllowlist constrains which upstream identity token issuers are accepted during callback exchange.
	UpstreamIssuerAllowlist []string `json:"upstream_issuer_allowlist" yaml:"upstream_issuer_allowlist" flag:"oauth-upstream-issuer-allowlist" env:"MCP_OAUTH_UPSTREAM_ISSUER_ALLOWLIST" desc:"Allowed upstream identity token issuers"`

	// AccessTokenTTLSeconds controls how long minted access tokens remain valid.
	AccessTokenTTLSeconds int `json:"access_token_ttl_seconds" yaml:"access_token_ttl_seconds" flag:"oauth-access-token-ttl-seconds" env:"MCP_OAUTH_ACCESS_TOKEN_TTL_SECONDS" desc:"Access token lifetime in seconds"`

	// RefreshTokenTTLSeconds controls how long minted refresh tokens remain valid.
	RefreshTokenTTLSeconds int `json:"refresh_token_ttl_seconds" yaml:"refresh_token_ttl_seconds" flag:"oauth-refresh-token-ttl-seconds" env:"MCP_OAUTH_REFRESH_TOKEN_TTL_SECONDS" desc:"Refresh token lifetime in seconds"`

	// SigningSecret is the server-side symmetric secret used to HMAC-sign every
	// stateless OAuth artifact this server mints: self-issued JWT access tokens
	// (HS256), authorization codes, refresh tokens, and RFC 7591 dynamic-client-
	// registration `client_secret`s. Required whenever OAuth is enabled, in both
	// forward and gating modes.
	SigningSecret string `json:"signing_secret" yaml:"signing_secret" flag:"oauth-signing-secret" env:"MCP_OAUTH_SIGNING_SECRET" desc:"Server-side HMAC secret for all stateless OAuth artifacts (JWTs, auth codes, refresh tokens, DCR client_secrets)"`
}

func (cfg OAuthConfig) NormalizedMode() string {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	switch mode {
	case "forward":
		return "forward"
	case "gating":
		return "gating"
	case "":
		return "gating"
	default:
		return mode
	}
}

func (cfg OAuthConfig) IsForwardMode() bool {
	return cfg.NormalizedMode() == "forward"
}

func (cfg OAuthConfig) IsGatingMode() bool {
	return cfg.NormalizedMode() == "gating"
}

// ServerConfig defines configuration for the MCP server
type ServerConfig struct {
	Transport           MCPTransport    `json:"transport" yaml:"transport" flag:"transport" env:"MCP_TRANSPORT" default:"stdio" desc:"MCP transport type (stdio/http/sse)"`
	Address             string          `json:"address" yaml:"address" flag:"address" env:"MCP_ADDRESS" default:"0.0.0.0" desc:"Server address for HTTP/SSE transport"`
	Port                int             `json:"port" yaml:"port" flag:"port" env:"MCP_PORT" default:"8080" desc:"Server port for HTTP/SSE transport"`
	TLS                 ServerTLSConfig `json:"tls" yaml:"tls"`
	JWE                 JWEConfig       `json:"jwe" yaml:"jwe"`
	OAuth               OAuthConfig     `json:"oauth" yaml:"oauth"`
	OpenAPI             OpenAPIConfig   `json:"openapi" yaml:"openapi" desc:"OpenAPI endpoints configuration"`
	CORSOrigin          string          `json:"cors_origin" yaml:"cors_origin" flag:"cors-origin" env:"MCP_CORS_ORIGIN" default:"*" desc:"CORS origin for HTTP/SSE transports"`
	ToolInputSettings   []string        `json:"tool_input_settings" yaml:"tool_input_settings" flag:"tool-input-settings" env:"TOOL_INPUT_SETTINGS" desc:"ClickHouse setting names allowed in tool arguments (e.g. custom_tenant_id)"`
	BlockedQueryClauses []string        `json:"blocked_query_clauses" yaml:"blocked_query_clauses" flag:"blocked-query-clauses" env:"BLOCKED_QUERY_CLAUSES" desc:"AST clause kinds to block: SQL-style names derived from clickhouse-sql-parser types (e.g. WHERE, SETTINGS, FORMAT, SET, EXPLAIN) or full type stems (WHERECLAUSE); INTO OUTFILE is a special form"`
	// Tools is the unified tool configuration (static + dynamic in one array).
	// Static tools: type + name. Dynamic tools: type + regexp + prefix + mode.
	Tools []ToolDefinition `json:"tools" yaml:"tools" desc:"Tool definitions (static and dynamic)"`
	// DynamicTools is the legacy rule list for generating tools from ClickHouse views.
	// DEPRECATED: use Tools instead. Retained for backwards compatibility.
	DynamicTools []DynamicToolRule `json:"dynamic_tools" yaml:"dynamic_tools" desc:"(Deprecated: use tools instead) Rules for generating tools from ClickHouse views"`
}

// OpenAPIConfig defines OpenAPI endpoints configuration
type OpenAPIConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled" desc:"Enable OpenAPI endpoints"`
	TLS     bool `json:"tls" yaml:"tls" desc:"Use TLS (https) for OpenAPI endpoints"`
}

// ToolDefinition describes a tool in the unified tools configuration.
//
//   - Static tool: Type + Name (no ViewRegexp/TableRegexp). Currently supported names:
//     "execute_query" (read), "write_query" (write).
//   - Dynamic read tool: Type "read" + ViewRegexp (+ optional Name/Prefix). Discovers views.
//   - Dynamic write tool: Type "write" + TableRegexp (+ optional Name/Prefix). Discovers tables.
//     Dynamic write tools require Mode (currently only "insert" is implemented).
type ToolDefinition struct {
	Type        string `json:"type"         yaml:"type"`         // "read" or "write"
	Name        string `json:"name"         yaml:"name"`         // static tool name, or label for dynamic rule
	ViewRegexp  string `json:"view_regexp"  yaml:"view_regexp"`  // dynamic read discovery pattern (matched against db.view_name)
	TableRegexp string `json:"table_regexp" yaml:"table_regexp"` // dynamic write discovery pattern (matched against db.table_name)
	Prefix      string `json:"prefix"       yaml:"prefix"`       // tool-name prefix for discovered tools
	Mode        string `json:"mode"         yaml:"mode"`         // "insert" (required for dynamic write tools)
}

// DynamicToolRule describes a rule to create dynamic tools from views.
// DEPRECATED: use ToolDefinition instead. Retained for backwards compatibility.
type DynamicToolRule struct {
	Name   string `json:"name" yaml:"name"`
	Regexp string `json:"regexp" yaml:"regexp"`
	Prefix string `json:"prefix" yaml:"prefix"`
	// Type and Mode are accepted so DynamicToolRule can round-trip through
	// the new unified Tools path without losing information.
	Type string `json:"type" yaml:"type"` // "read" or "write"
	Mode string `json:"mode" yaml:"mode"` // "insert" for write tools
}

// LogLevel defines the logging level
type LogLevel string

const (
	// DebugLevel enables debug logging
	DebugLevel LogLevel = "debug"
	// InfoLevel enables info logging
	InfoLevel LogLevel = "info"
	// WarnLevel enables warn logging
	WarnLevel LogLevel = "warn"
	// ErrorLevel enables error logging
	ErrorLevel LogLevel = "error"
)

// LoggingConfig defines configuration for logging
type LoggingConfig struct {
	Level LogLevel `json:"level" yaml:"level" flag:"log-level" env:"LOG_LEVEL" default:"info" desc:"Logging level (debug/info/warn/error)"`
}

// Config is the main application configuration
type Config struct {
	ClickHouse ClickHouseConfig `json:"clickhouse" yaml:"clickhouse"`
	Server     ServerConfig     `json:"server" yaml:"server"`
	Logging    LoggingConfig    `json:"logging" yaml:"logging"`
	ReloadTime int              `json:"reload_time,omitempty" yaml:"reload_time,omitempty" desc:"Configuration reload interval in seconds (0 to disable)"`
}

// LoadConfigFromFile loads configuration from a YAML or JSON file
func LoadConfigFromFile(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", filename, err)
	}

	config := &Config{}

	// Determine file format by extension
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config file %s: %w", filename, err)
		}
	case ".json":
		if err := json.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config file %s: %w", filename, err)
		}
	default:
		// Try YAML first, then JSON
		if err := yaml.Unmarshal(data, config); err != nil {
			if jsonErr := json.Unmarshal(data, config); jsonErr != nil {
				return nil, fmt.Errorf("failed to parse config file %s as YAML or JSON: YAML error: %v, JSON error: %v", filename, err, jsonErr)
			}
		}
	}
	return config, nil
}
