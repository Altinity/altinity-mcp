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
	Limit            int                `json:"limit" yaml:"limit" flag:"clickhouse-limit" desc:"Default limit for query results"`
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

// JWTConfig defines configuration for JWT authentication
type JWTConfig struct {
	Enabled   bool   `json:"enabled" yaml:"enabled" flag:"allow-jwt-auth" desc:"Enable JWT authentication for ClickHouse connection"`
	SecretKey string `json:"secret_key" yaml:"secret_key" flag:"jwt-secret-key" desc:"Secret key for JWT token verification"`
}

// ServerConfig defines configuration for the MCP server
type ServerConfig struct {
	Transport    MCPTransport    `json:"transport" yaml:"transport" flag:"transport" desc:"MCP transport type (stdio/http/sse)"`
	Address      string          `json:"address" yaml:"address" flag:"address" desc:"Server address for HTTP/SSE transport"`
	Port         int             `json:"port" yaml:"port" flag:"port" desc:"Server port for HTTP/SSE transport"`
	TLS          ServerTLSConfig `json:"tls" yaml:"tls"`
	JWT          JWTConfig       `json:"jwt" yaml:"jwt"`
	OpenAPI      bool            `json:"openapi" yaml:"openapi" flag:"openapi" desc:"Enable OpenAPI endpoints"`
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
