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
	Enabled            bool   `json:"enabled" yaml:"enabled" flag:"clickhouse-tls" desc:"Enable TLS for ClickHouse connection"`
	CaCert             string `json:"ca_cert" yaml:"ca_cert" flag:"clickhouse-tls-ca-cert" desc:"Path to CA certificate for ClickHouse connection"`
	ClientCert         string `json:"client_cert" yaml:"client_cert" flag:"clickhouse-tls-client-cert" desc:"Path to client certificate for ClickHouse connection"`
	ClientKey          string `json:"client_key" yaml:"client_key" flag:"clickhouse-tls-client-key" desc:"Path to client key for ClickHouse connection"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify" yaml:"insecure_skip_verify" flag:"clickhouse-tls-insecure-skip-verify" desc:"Skip server certificate verification"`
}

// ClickHouseConfig defines configuration for connecting to ClickHouse
type ClickHouseConfig struct {
	Host             string             `json:"host" yaml:"host" flag:"clickhouse-host" desc:"ClickHouse server host"`
	Port             int                `json:"port" yaml:"port" flag:"clickhouse-port" desc:"ClickHouse server port"`
	Database         string             `json:"database" yaml:"database" flag:"clickhouse-database" desc:"ClickHouse database name"`
	Username         string             `json:"username" yaml:"username" flag:"clickhouse-username" desc:"ClickHouse username"`
	Password         string             `json:"password" yaml:"password" flag:"clickhouse-password" desc:"ClickHouse password"`
	Protocol         ClickHouseProtocol `json:"protocol" yaml:"protocol" flag:"clickhouse-protocol" desc:"ClickHouse connection protocol (http/tcp)"`
	TLS              TLSConfig          `json:"tls" yaml:"tls"`
	ReadOnly         bool               `json:"read_only" yaml:"read_only" flag:"read-only" desc:"Connect to ClickHouse in read-only mode"`
	MaxExecutionTime int                `json:"max_execution_time" yaml:"max_execution_time" flag:"clickhouse-max-execution-time" desc:"ClickHouse max execution time in seconds"`
	Limit            int                `json:"limit" yaml:"limit" flag:"clickhouse-limit" desc:"Maximum limit for query results (0 means no limit)"`
	HttpHeaders      map[string]string  `json:"http_headers" yaml:"http_headers" flag:"clickhouse-http-headers" desc:"HTTP Headers for ClickHouse"`
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
	Enabled  bool   `json:"enabled" yaml:"enabled" flag:"server-tls" desc:"Enable TLS for the MCP server"`
	CertFile string `json:"cert_file" yaml:"cert_file" flag:"server-tls-cert-file" desc:"Path to TLS certificate file"`
	KeyFile  string `json:"key_file" yaml:"key_file" flag:"server-tls-key-file" desc:"Path to TLS key file"`
	CaCert   string `json:"ca_cert" yaml:"ca_cert" flag:"server-tls-ca-cert" desc:"Path to CA certificate for client certificate validation"`
}

// JWEConfig defines configuration for JWE authentication
type JWEConfig struct {
	Enabled      bool   `json:"enabled" yaml:"enabled" flag:"allow-jwe-auth" desc:"Enable JWE encryption for ClickHouse connection"`
	JWESecretKey string `json:"jwe_secret_key" yaml:"jwe_secret_key" flag:"jwe-secret-key" desc:"Secret key for JWE token encryption/decryption"`
	JWTSecretKey string `json:"jwt_secret_key" yaml:"jwt_secret_key" flag:"jwt-secret-key" desc:"Secret key for JWT signature verification"`
}

// OAuthConfig defines configuration for OAuth 2.0 authentication
type OAuthConfig struct {
	// Enabled enables OAuth authentication
	Enabled bool `json:"enabled" yaml:"enabled" flag:"oauth-enabled" desc:"Enable OAuth 2.0 authentication"`

	// Issuer is the OAuth token issuer URL for token validation (e.g., "https://accounts.google.com")
	Issuer string `json:"issuer" yaml:"issuer" flag:"oauth-issuer" desc:"OAuth token issuer URL for validation"`

	// JWKSURL is the URL to fetch JSON Web Key Set for token validation
	// If empty, will be discovered from issuer's .well-known/openid-configuration
	JWKSURL string `json:"jwks_url" yaml:"jwks_url" flag:"oauth-jwks-url" desc:"URL to fetch JWKS for token validation"`

	// Audience is the expected audience claim in the token
	Audience string `json:"audience" yaml:"audience" flag:"oauth-audience" desc:"Expected audience claim in OAuth token"`

	// ClientID is the OAuth client ID (used for client credentials flow or validation)
	ClientID string `json:"client_id" yaml:"client_id" flag:"oauth-client-id" desc:"OAuth client ID"`

	// ClientSecret is the OAuth client secret (used for client credentials flow)
	ClientSecret string `json:"client_secret" yaml:"client_secret" flag:"oauth-client-secret" desc:"OAuth client secret"`

	// TokenURL is the OAuth token endpoint URL (used for client credentials flow)
	TokenURL string `json:"token_url" yaml:"token_url" flag:"oauth-token-url" desc:"OAuth token endpoint URL"`

	// AuthURL is the OAuth authorization endpoint URL (used for authorization code flow)
	AuthURL string `json:"auth_url" yaml:"auth_url" flag:"oauth-auth-url" desc:"OAuth authorization endpoint URL"`

	// Scopes is the list of OAuth scopes to request
	Scopes []string `json:"scopes" yaml:"scopes" flag:"oauth-scopes" desc:"OAuth scopes to request"`

	// RequiredScopes is the list of scopes required for access (token must have all of these)
	RequiredScopes []string `json:"required_scopes" yaml:"required_scopes" flag:"oauth-required-scopes" desc:"Required OAuth scopes for access"`

	// ForwardToClickHouse enables forwarding OAuth token to ClickHouse via HTTP headers
	ForwardToClickHouse bool `json:"forward_to_clickhouse" yaml:"forward_to_clickhouse" flag:"oauth-forward-to-clickhouse" desc:"Forward OAuth token to ClickHouse via HTTP headers"`

	// ClickHouseHeaderName is the header name to use when forwarding OAuth token to ClickHouse
	// Default: "Authorization" (sends as "Bearer {token}")
	// When set to a custom header, the raw token is sent without "Bearer " prefix
	ClickHouseHeaderName string `json:"clickhouse_header_name" yaml:"clickhouse_header_name" flag:"oauth-clickhouse-header-name" desc:"Header name for forwarding OAuth token to ClickHouse"`

	// ForwardAccessToken forwards the access token itself (vs. just claims)
	ForwardAccessToken bool `json:"forward_access_token" yaml:"forward_access_token" flag:"oauth-forward-access-token" desc:"Forward raw access token to ClickHouse"`

	// ClearClickHouseCredentials clears ClickHouse username/password when forwarding OAuth token
	// This is needed when ClickHouse authenticates via token_processors (JWT/OIDC)
	// where the user identity comes from the token's sub claim, not from basic auth
	ClearClickHouseCredentials bool `json:"clear_clickhouse_credentials" yaml:"clear_clickhouse_credentials" flag:"oauth-clear-clickhouse-credentials" desc:"Clear ClickHouse credentials when forwarding OAuth token"`

	// ClaimsToHeaders maps OAuth token claims to ClickHouse HTTP headers
	// Example: {"sub": "X-ClickHouse-User", "email": "X-ClickHouse-Email"}
	ClaimsToHeaders map[string]string `json:"claims_to_headers" yaml:"claims_to_headers" desc:"Map OAuth claims to ClickHouse HTTP headers"`
}

// ServerConfig defines configuration for the MCP server
type ServerConfig struct {
	Transport          MCPTransport    `json:"transport" yaml:"transport" flag:"transport" desc:"MCP transport type (stdio/http/sse)"`
	Address            string          `json:"address" yaml:"address" flag:"address" desc:"Server address for HTTP/SSE transport"`
	Port               int             `json:"port" yaml:"port" flag:"port" desc:"Server port for HTTP/SSE transport"`
	TLS                ServerTLSConfig `json:"tls" yaml:"tls"`
	JWE                JWEConfig       `json:"jwe" yaml:"jwe"`
	OAuth              OAuthConfig     `json:"oauth" yaml:"oauth"`
	OpenAPI            OpenAPIConfig   `json:"openapi" yaml:"openapi" desc:"OpenAPI endpoints configuration"`
	CORSOrigin         string          `json:"cors_origin" yaml:"cors_origin" flag:"cors-origin" desc:"CORS origin for HTTP/SSE transports (default: *)"`
	ForwardHTTPHeaders []string        `json:"forward_http_headers" yaml:"forward_http_headers" desc:"Header name patterns forwarded to ClickHouse (supports * wildcard)"`
	// DynamicTools defines rules for generating tools from ClickHouse views
	DynamicTools []DynamicToolRule `json:"dynamic_tools" yaml:"dynamic_tools"`
}

// OpenAPIConfig defines OpenAPI endpoints configuration
type OpenAPIConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled" desc:"Enable OpenAPI endpoints"`
	TLS     bool `json:"tls" yaml:"tls" desc:"Use TLS (https) for OpenAPI endpoints"`
}

// DynamicToolRule describes a rule to create dynamic tools from views
type DynamicToolRule struct {
	Name   string `json:"name" yaml:"name"`
	Regexp string `json:"regexp" yaml:"regexp"`
	Prefix string `json:"prefix" yaml:"prefix"`
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
	Level LogLevel `json:"level" yaml:"level" flag:"log-level" desc:"Logging level (debug/info/warn/error)"`
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
