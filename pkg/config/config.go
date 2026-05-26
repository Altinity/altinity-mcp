package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/altinity/go-mcp-oauth-sdk/oauth"
	"gopkg.in/yaml.v3"
)

// OAuthConfig is an alias for oauth.OAuthConfig so existing call sites that
// reference config.OAuthConfig continue to compile. The struct definition and
// the NormalizedMode/IsForwardMode/IsGatingMode helpers live in pkg/oauth.
type OAuthConfig = oauth.OAuthConfig

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
	// Limit is DEPRECATED; use MaxResultRows. Retained as a silent alias: when
	// MaxResultRows is unset (0) and Limit > 0, EffectiveMaxResultRows() returns Limit.
	Limit          int               `json:"limit,omitempty" yaml:"limit,omitempty" flag:"clickhouse-limit" env:"CLICKHOUSE_LIMIT" desc:"DEPRECATED: alias for max_result_rows"`
	MaxResultRows  int               `json:"max_result_rows,omitempty" yaml:"max_result_rows,omitempty" flag:"clickhouse-max-result-rows" env:"CLICKHOUSE_MAX_RESULT_ROWS" desc:"Per-request row cap on SELECT-like queries (0=default 500, <0=disable and defer to ClickHouse user profile)"`
	MaxResultBytes int               `json:"max_result_bytes,omitempty" yaml:"max_result_bytes,omitempty" flag:"clickhouse-max-result-bytes" env:"CLICKHOUSE_MAX_RESULT_BYTES" desc:"Per-request approximate byte cap on result body (0=default 50000, <0=disable)"`
	HttpHeaders    map[string]string `json:"http_headers" yaml:"http_headers" flag:"clickhouse-http-headers" env:"CLICKHOUSE_HTTP_HEADERS" desc:"HTTP Headers for ClickHouse"`
	ExtraSettings  map[string]string `json:"extra_settings,omitempty" yaml:"extra_settings,omitempty" desc:"Per-request ClickHouse settings injected by tool_input_settings"`
	// MaxQueryLength caps the size in bytes of a single SQL query string sent by a client.
	// Default 10 MB when 0. Set to a negative number to disable the check.
	MaxQueryLength int `json:"max_query_length,omitempty" yaml:"max_query_length,omitempty" flag:"clickhouse-max-query-length" env:"CLICKHOUSE_MAX_QUERY_LENGTH" desc:"Max bytes of SQL query string accepted from clients (0=default 10MB, <0=disabled)"`
}

// Defaults applied by the Effective* getters when the corresponding field is 0.
// A negative value disables the cap entirely.
const (
	defaultMaxQueryLength = 10 * 1024 * 1024 // 10 MiB
	defaultMaxResultRows  = 500
	defaultMaxResultBytes = 50000
)

// EffectiveMaxResultRows returns the per-request row cap for SELECT-like queries.
// Negative => disabled (defer to ClickHouse user profile); 0 => default 500;
// >0 => exact cap. The deprecated Limit field is consulted as a silent alias
// only when MaxResultRows is 0.
func (c ClickHouseConfig) EffectiveMaxResultRows() int {
	if c.MaxResultRows < 0 {
		return 0
	}
	if c.MaxResultRows > 0 {
		return c.MaxResultRows
	}
	if c.Limit > 0 {
		return c.Limit
	}
	return defaultMaxResultRows
}

// EffectiveMaxResultBytes returns the approximate per-request response-body cap.
// Negative => disabled; 0 => default 50000; >0 => exact cap.
func (c ClickHouseConfig) EffectiveMaxResultBytes() int {
	if c.MaxResultBytes < 0 {
		return 0
	}
	if c.MaxResultBytes > 0 {
		return c.MaxResultBytes
	}
	return defaultMaxResultBytes
}

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

// ServerConfig defines configuration for the MCP server
type ServerConfig struct {
	Transport           MCPTransport      `json:"transport" yaml:"transport" flag:"transport" env:"MCP_TRANSPORT" default:"stdio" desc:"MCP transport type (stdio/http/sse)"`
	Address             string            `json:"address" yaml:"address" flag:"address" env:"MCP_ADDRESS" default:"0.0.0.0" desc:"Server address for HTTP/SSE transport"`
	Port                int               `json:"port" yaml:"port" flag:"port" env:"MCP_PORT" default:"8080" desc:"Server port for HTTP/SSE transport"`
	TLS                 ServerTLSConfig   `json:"tls" yaml:"tls"`
	JWE                 JWEConfig         `json:"jwe" yaml:"jwe"`
	OAuth               oauth.OAuthConfig `json:"oauth" yaml:"oauth"`
	OpenAPI             OpenAPIConfig     `json:"openapi" yaml:"openapi" desc:"OpenAPI endpoints configuration"`
	CORSOrigin          string            `json:"cors_origin" yaml:"cors_origin" flag:"cors-origin" env:"MCP_CORS_ORIGIN" default:"*" desc:"CORS origin for HTTP/SSE transports"`
	ToolInputSettings   []string          `json:"tool_input_settings" yaml:"tool_input_settings" flag:"tool-input-settings" env:"TOOL_INPUT_SETTINGS" desc:"ClickHouse setting names allowed in tool arguments (e.g. custom_tenant_id)"`
	BlockedQueryClauses []string          `json:"blocked_query_clauses" yaml:"blocked_query_clauses" flag:"blocked-query-clauses" env:"BLOCKED_QUERY_CLAUSES" desc:"AST clause kinds to block: SQL-style names derived from clickhouse-sql-parser types (e.g. WHERE, SETTINGS, FORMAT, SET, EXPLAIN) or full type stems (WHERECLAUSE); INTO OUTFILE is a special form"`
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

	// RemovedKeyWarnings holds human-readable warnings about config keys
	// that LoadConfigFromFile observed in the input file but the current
	// codebase no longer honors (silently dropped on unmarshal). The
	// caller is responsible for emitting these via its own structured
	// logger after init. Not serialized — round-trips through YAML/JSON
	// as zero. See removedKeyWarnings + RemovedConfigKeys.
	RemovedKeyWarnings []string `json:"-" yaml:"-"`
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
	config.RemovedKeyWarnings = removedKeyWarnings(data)
	return config, nil
}

// RemovedConfigKeys names YAML/JSON keys this codebase used to honor but no
// longer does. When an operator upgrades MCP they may carry these over in
// their values file; YAML unmarshal silently drops unknown fields and the
// operator sees no warning. removedKeyWarnings re-parses the raw bytes
// into a generic map and reports any of these so the operator knows their
// override is now a no-op. Exported so external tooling (linters, CI
// gates, deploy automation) can share the same source of truth.
var RemovedConfigKeys = []RemovedKey{
	{Path: "clickhouse.cluster_secret", Replacement: "Use mode: gating + the ch-jwt-verify sidecar (github.com/altinity/altinity-oauth-helper). Drop cluster_secret + cluster_name from helm values and bind users with IDENTIFIED WITH http SERVER 'ch_jwt_verify' SCHEME 'BASIC'."},
	{Path: "clickhouse.cluster_name", Replacement: "Same as cluster_secret — drop both together."},
	{Path: "server.oauth.claims_to_headers", Replacement: "Removed — the gating-mode wire format no longer forwards arbitrary claims as headers. Per-scope ClickHouse session settings live in the sidecar's settings_from_scope config."},
	{Path: "server.oauth.clickhouse_header_name", Replacement: "Removed — forward mode always uses Authorization: Bearer."},
	{Path: "server.oauth.allowed_email_domains", Replacement: "Moved to the ch-jwt-verify sidecar's identity.allowed_email_domains."},
	{Path: "server.oauth.allowed_hosted_domains", Replacement: "Moved to the ch-jwt-verify sidecar's identity.allowed_hosted_domains."},
	{Path: "server.oauth.allow_unverified_email", Replacement: "Moved (inverted) to the ch-jwt-verify sidecar's identity.require_email_verified."},
}

// RemovedKey is a single removed-config-key entry: the dotted path under
// the config root and a human-readable migration hint.
type RemovedKey struct {
	Path        string
	Replacement string
}

// removedKeyWarnings returns a human-readable warning per removed key
// observed in data. Empty slice if data is unparseable or carries no
// removed keys. The caller is responsible for emitting these via its
// structured logger (we can't import the logger here without an import
// cycle; the config package is a leaf).
func removedKeyWarnings(data []byte) []string {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil || raw == nil {
		return nil
	}
	var out []string
	for _, rk := range RemovedConfigKeys {
		if hasNestedKey(raw, strings.Split(rk.Path, ".")) {
			out = append(out, fmt.Sprintf("config key %q is no longer honored (silently dropped on unmarshal). %s",
				rk.Path, rk.Replacement))
		}
	}
	return out
}

func hasNestedKey(m map[string]interface{}, parts []string) bool {
	if len(parts) == 0 {
		return false
	}
	v, ok := m[parts[0]]
	if !ok {
		return false
	}
	if len(parts) == 1 {
		return true
	}
	nested, ok := v.(map[string]interface{})
	if !ok {
		return false
	}
	return hasNestedKey(nested, parts[1:])
}
