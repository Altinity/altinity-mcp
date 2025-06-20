package config

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
	Enabled            bool   `json:"enabled" flag:"clickhouse-tls" desc:"Enable TLS for ClickHouse connection"`
	CaCert             string `json:"ca_cert" flag:"clickhouse-tls-ca-cert" desc:"Path to CA certificate for ClickHouse connection"`
	ClientCert         string `json:"client_cert" flag:"clickhouse-tls-client-cert" desc:"Path to client certificate for ClickHouse connection"`
	ClientKey          string `json:"client_key" flag:"clickhouse-tls-client-key" desc:"Path to client key for ClickHouse connection"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify" flag:"clickhouse-tls-insecure-skip-verify" desc:"Skip server certificate verification"`
}

// ClickHouseConfig defines configuration for connecting to ClickHouse
type ClickHouseConfig struct {
	Host             string             `json:"host" flag:"clickhouse-host" desc:"ClickHouse server host"`
	Port             int                `json:"port" flag:"clickhouse-port" desc:"ClickHouse server port"`
	Database         string             `json:"database" flag:"clickhouse-database" desc:"ClickHouse database name"`
	Username         string             `json:"username" flag:"clickhouse-username" desc:"ClickHouse username"`
	Password         string             `json:"password" flag:"clickhouse-password" desc:"ClickHouse password"`
	Protocol         ClickHouseProtocol `json:"protocol" flag:"clickhouse-protocol" desc:"ClickHouse connection protocol (http/tcp)"`
	TLS              TLSConfig          `json:"tls"`
	ReadOnly         bool               `json:"read_only" flag:"read-only" desc:"Connect to ClickHouse in read-only mode"`
	MaxExecutionTime int                `json:"max_execution_time" flag:"clickhouse-max-execution-time" desc:"ClickHouse max execution time in seconds"`
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
	Enabled  bool   `json:"enabled" flag:"server-tls" desc:"Enable TLS for the MCP server"`
	CertFile string `json:"cert_file" flag:"server-tls-cert-file" desc:"Path to TLS certificate file"`
	KeyFile  string `json:"key_file" flag:"server-tls-key-file" desc:"Path to TLS key file"`
	CaCert   string `json:"ca_cert" flag:"server-tls-ca-cert" desc:"Path to CA certificate for client certificate validation"`
}

// ServerConfig defines configuration for the MCP server
type ServerConfig struct {
	Transport MCPTransport    `json:"transport" flag:"transport" desc:"MCP transport type (stdio/http/sse)"`
	Address   string          `json:"address" flag:"address" desc:"Server address for HTTP/SSE transport"`
	Port      int             `json:"port" flag:"port" desc:"Server port for HTTP/SSE transport"`
	TLS       ServerTLSConfig `json:"tls"`
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
	Level LogLevel `json:"level" flag:"log-level" desc:"Logging level (debug/info/warn/error)"`
}

// Config is the main application configuration
type Config struct {
	ClickHouse ClickHouseConfig `json:"clickhouse"`
	Server     ServerConfig     `json:"server"`
	Logging    LoggingConfig    `json:"logging"`
}
