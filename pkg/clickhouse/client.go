package clickhouse

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/rs/zerolog/log"
)

// QueryResult represents the result of a query execution
type QueryResult struct {
	Columns []string        `json:"columns"`
	Types   []string        `json:"types"`
	Rows    [][]interface{} `json:"rows"`
	Count   int             `json:"count"`
	Error   string          `json:"error,omitempty"`
}

// TableInfo represents information about a table
type TableInfo struct {
	Name      string `json:"name"`
	Database  string `json:"database"`
	Engine    string `json:"engine"`
	CreatedAt string `json:"created_at,omitempty"`
}

// Client is a wrapper for ClickHouse connection
type Client struct {
	config     config.ClickHouseConfig
	conn       driver.Conn
	ctx        context.Context
	cancelFunc context.CancelFunc
}

// NewClient creates a new ClickHouse client
func NewClient(cfg config.ClickHouseConfig) (*Client, error) {
	ctx, cancel := context.WithCancel(context.Background())
	client := &Client{
		config:     cfg,
		ctx:        ctx,
		cancelFunc: cancel,
	}

	if err := client.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to ClickHouse: %w", err)
	}

	return client, nil
}

// connect establishes a ClickHouse connection
func (c *Client) connect() error {
	log.Debug().
		Str("host", c.config.Host).
		Int("port", c.config.Port).
		Str("database", c.config.Database).
		Str("protocol", string(c.config.Protocol)).
		Msg("Connecting to ClickHouse")

	tlsConfig, err := buildTLSConfig(&c.config.TLS)
	if err != nil {
		return fmt.Errorf("failed to build TLS config: %w", err)
	}

	var protocol clickhouse.Protocol
	switch c.config.Protocol {
	case config.HTTPProtocol:
		protocol = clickhouse.HTTP
	case config.TCPProtocol:
		protocol = clickhouse.TCP
	default:
		// This should not happen due to validation in main.go, but as a safeguard:
		return fmt.Errorf("unsupported clickhouse protocol: %s", c.config.Protocol)
	}

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)},
		Auth: clickhouse.Auth{
			Database: c.config.Database,
			Username: c.config.Username,
			Password: c.config.Password,
		},
		TLS:      tlsConfig,
		Protocol: protocol,
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		DialTimeout:     time.Second * 10,
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: time.Hour,
	})

	if err != nil {
		return err
	}

	c.conn = conn
	return nil
}

// GetDatabase returns the configured database name
func (c *Client) GetDatabase() string {
	return c.config.Database
}

// Close closes the ClickHouse connection
func (c *Client) Close() error {
	c.cancelFunc()

	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			return fmt.Errorf("error closing connection: %w", err)
		}
	}

	log.Debug().Msg("ClickHouse connection closed")
	return nil
}

// Ping tests the connection to ClickHouse
func (c *Client) Ping(ctx context.Context) error {
	if c.conn == nil {
		return fmt.Errorf("no active connection to ping")
	}
	if err := c.conn.Ping(ctx); err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}

	log.Debug().Msg("ClickHouse ping successful")
	return nil
}

// ListTables returns a list of tables in the database
func (c *Client) ListTables(ctx context.Context) ([]TableInfo, error) {
	query := `
		SELECT 
			name,
			database,
			engine,
			formatDateTime(creation_time, '%Y-%m-%d %H:%M:%S') as created_at
		FROM system.tables
		WHERE database = ?
		ORDER BY name
	`

	var tables []TableInfo

	rows, err := c.conn.Query(ctx, query, c.config.Database)
	if err != nil {
		return nil, fmt.Errorf("failed to list tables: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var table TableInfo
		if err := rows.Scan(&table.Name, &table.Database, &table.Engine, &table.CreatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan table info: %w", err)
		}
		tables = append(tables, table)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating table rows: %w", err)
	}

	log.Debug().Int("count", len(tables)).Msg("Retrieved tables list")
	return tables, nil
}

// ExecuteQuery executes a SQL query and returns results
func (c *Client) ExecuteQuery(ctx context.Context, query string, args ...interface{}) (*QueryResult, error) {
	// Check if the query is a SELECT query
	isSelect := isSelectQuery(query)

	if isSelect {
		return c.executeSelect(ctx, query, args...)
	}
	// For non-SELECT queries (DDL, DML)
	return c.executeNonSelect(ctx, query, args...)
}

// executeSelect executes a SELECT query
func (c *Client) executeSelect(ctx context.Context, query string, args ...interface{}) (*QueryResult, error) {
	result := &QueryResult{}

	rows, err := c.conn.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	// Get column information
	columnTypes := rows.ColumnTypes()
	result.Columns = make([]string, len(columnTypes))
	result.Types = make([]string, len(columnTypes))

	for i, ct := range columnTypes {
		result.Columns[i] = ct.Name()
		result.Types[i] = ct.DatabaseTypeName()
	}

	// Fetch rows
	for rows.Next() {
		// Create a slice of interface{} to hold the row values
		rowValues := make([]interface{}, len(columnTypes))
		rowPointers := make([]interface{}, len(columnTypes))

		for i := range rowValues {
			rowPointers[i] = &rowValues[i]
		}

		if err := rows.Scan(rowPointers...); err != nil {
			return nil, fmt.Errorf("failed to scan row: %w", err)
		}

		// Convert any specific ClickHouse types to standard Go types for JSON serialization
		for i := range rowValues {
			rowValues[i] = convertToSerializable(rowValues[i])
		}

		result.Rows = append(result.Rows, rowValues)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating rows: %w", err)
	}

	result.Count = len(result.Rows)
	log.Debug().
		Int("rows", result.Count).
		Int("columns", len(result.Columns)).
		Str("query", truncateString(query, 100)).
		Msg("Query executed successfully")

	return result, nil
}

// executeNonSelect executes a non-SELECT query
func (c *Client) executeNonSelect(ctx context.Context, query string, args ...interface{}) (*QueryResult, error) {
	result := &QueryResult{}

	err := c.conn.Exec(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	// For non-SELECT queries, we just return an empty result with success status
	result.Columns = []string{"status"}
	result.Types = []string{"String"}
	result.Rows = [][]interface{}{{"OK"}}
	result.Count = 1

	log.Debug().
		Str("query", truncateString(query, 100)).
		Msg("Non-SELECT query executed successfully")

	return result, nil
}

// buildTLSConfig creates a tls.Config from the ClickHouse configuration
func buildTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	log.Debug().Msg("Building TLS configuration")
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}

	if cfg.CaCert != "" {
		log.Debug().Str("ca_cert", cfg.CaCert).Msg("Loading CA certificate")
		caCert, err := os.ReadFile(cfg.CaCert)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		log.Debug().
			Str("client_cert", cfg.ClientCert).
			Str("client_key", cfg.ClientKey).
			Msg("Loading client key pair")
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client key pair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// Helper functions

// isSelectQuery determines if a query is a SELECT query
func isSelectQuery(query string) bool {
	// Simple check - can be improved with more sophisticated parsing if needed
	trimmed := strings.TrimSpace(strings.ToUpper(query))
	return strings.HasPrefix(trimmed, "SELECT") || strings.HasPrefix(trimmed, "WITH")
}

// truncateString truncates a string to the specified length
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// convertToSerializable converts ClickHouse-specific types to JSON-serializable types
func convertToSerializable(v interface{}) interface{} {
	switch val := v.(type) {
	case time.Time:
		return val.Format(time.RFC3339)
	case []byte:
		return string(val)
	default:
		return val
	}
}
