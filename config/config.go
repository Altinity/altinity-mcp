package config

import (
	"fmt"
)

// ClickHouseProtocol defines the protocol used to connect to ClickHouse
type ClickHouseProtocol string

const (
	// HTTPProtocol uses HTTP protocol for ClickHouse connection
	HTTPProtocol ClickHouseProtocol = "http"
	// TCPProtocol uses native TCP protocol for ClickHouse connection
	TCPProtocol ClickHouseProtocol = "tcp"
)

// ClickHouseConfig defines configuration for connecting to ClickHouse
type ClickHouseConfig struct {
	Host     string             `json:"host" flag:"clickhouse-host" desc:"ClickHouse server host"`
	Port     int                `json:"port" flag:"clickhouse-port" desc:"ClickHouse server port"`
	Database string             `json:"database" flag:"clickhouse-database" desc:"ClickHouse database name"`
	Username string             `json:"username" flag:"clickhouse-username" desc:"ClickHouse username"`
	Password string             `json:"password" flag:"clickhouse-password" desc:"ClickHouse password"`
	Protocol ClickHouseProtocol `json:"protocol" flag:"clickhouse-protocol" desc:"ClickHouse connection protocol (http/tcp)"`
}

// DSN returns the data source name for ClickHouse connection
func (c *ClickHouseConfig) DSN() string {
	switch c.Protocol {
	case HTTPProtocol:
		return fmt.Sprintf("http://%s:%s@%s:%d/%s", 
			c.Username, c.Password, c.Host, c.Port, c.Database)
	case TCPProtocol:
		return fmt.Sprintf("tcp://%s:%d?database=%s&username=%s&password=%s", 
			c.Host, c.Port, c.Database, c.Username, c.Password)
	default:
		return fmt.Sprintf("http://%s:%s@%s:%d/%s", 
			c.Username, c.Password, c.Host, c.Port, c.Database)
	}
}

// DefaultClickHouseConfig returns default ClickHouse configuration
func DefaultClickHouseConfig() ClickHouseConfig {
	return ClickHouseConfig{
		Host:     "localhost",
		Port:     8123,
		Database: "default",
		Username: "default",
		Password: "",
		Protocol: HTTPProtocol,
	}
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

// ServerConfig defines configuration for the MCP server
type ServerConfig struct {
	Transport MCPTransport `json:"transport" flag:"transport" desc:"MCP transport type (stdio/http/sse)"`
	Address   string       `json:"address" flag:"address" desc:"Server address for HTTP/SSE transport"`
	Port      int          `json:"port" flag:"port" desc:"Server port for HTTP/SSE transport"`
}

// DefaultServerConfig returns default server configuration
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Transport: StdioTransport,
		Address:   "0.0.0.0",
		Port:      8080,
	}
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

// DefaultLoggingConfig returns default logging configuration
func DefaultLoggingConfig() LoggingConfig {
	return LoggingConfig{
		Level: InfoLevel,
	}
}

// Config is the main application configuration
type Config struct {
	ClickHouse ClickHouseConfig `json:"clickhouse"`
	Server     ServerConfig     `json:"server"`
	Logging    LoggingConfig    `json:"logging"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() Config {
	return Config{
		ClickHouse: DefaultClickHouseConfig(),
		Server:     DefaultServerConfig(),
		Logging:    DefaultLoggingConfig(),
	}
}
