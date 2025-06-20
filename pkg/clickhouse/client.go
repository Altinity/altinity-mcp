package clickhouse

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"net/http"
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
	sqlDB      *sql.DB
	useNative  bool
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

	// Determine if we should use native or SQL interface
	client.useNative = cfg.Protocol == config.TCPProtocol

	var err error
	if client.useNative {
		err = client.connectNative()
	} else {
		err = client.connectSQL()
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to ClickHouse: %w", err)
	}

	return client, nil
}

// connectNative establishes a native ClickHouse connection
func (c *Client) connectNative() error {
	log.Debug().
		Str("host", c.config.Host).
		Int("port", c.config.Port).
		Str("database", c.config.Database).
		Str("protocol", string(c.config.Protocol)).
		Msg("Connecting to ClickHouse using native protocol")

	tlsConfig, err := buildTLSConfig(&c.config.TLS)
	if err != nil {
		return fmt.Errorf("failed to build TLS config: %w", err)
	}

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)},
		Auth: clickhouse.Auth{
			Database: c.config.Database,
			Username: c.config.Username,
			Password: c.config.Password,
		},
		TLS: tlsConfig,
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

// connectSQL establishes a SQL-based ClickHouse connection
func (c *Client) connectSQL() error {
	log.Debug().
		Str("host", c.config.Host).
		Int("port", c.config.Port).
		Str("database", c.config.Database).
		Str("protocol", string(c.config.Protocol)).
		Msg("Connecting to ClickHouse using HTTP protocol")

	if c.config.TLS.Enabled {
		tlsConfig, err := buildTLSConfig(&c.config.TLS)
		if err != nil {
			return fmt.Errorf("failed to build TLS config for HTTP: %w", err)
		}

		err = clickhouse.RegisterTransport("https", &http.Transport{
			TLSClientConfig: tlsConfig,
		})
		if err != nil {
			// It might be already registered. The driver returns an error if so.
			if !strings.Contains(err.Error(), "transport with name 'https' is already registered") {
				return fmt.Errorf("failed to register https transport: %w", err)
			}
		}
	}

	dsn := c.config.DSN()
	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		return err
	}

	// Set connection pool parameters
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(time.Hour)

	// Test the connection
	if err := db.Ping(); err != nil {
		return err
	}

	c.sqlDB = db
	return nil
}

// GetDatabase returns the configured database name
func (c *Client) GetDatabase() string {
	return c.config.Database
}

// Close closes the ClickHouse connection
func (c *Client) Close() error {
	c.cancelFunc()

	if c.useNative && c.conn != nil {
		if err := c.conn.Close(); err != nil {
			return fmt.Errorf("error closing native connection: %w", err)
		}
	} else if c.sqlDB != nil {
		if err := c.sqlDB.Close(); err != nil {
			return fmt.Errorf("error closing SQL connection: %w", err)
		}
	}

	log.Debug().Msg("ClickHouse connection closed")
	return nil
}

// Ping tests the connection to ClickHouse
func (c *Client) Ping(ctx context.Context) error {
	if c.useNative && c.conn != nil {
		if err := c.conn.Ping(ctx); err != nil {
			return fmt.Errorf("native ping failed: %w", err)
		}
	} else if c.sqlDB != nil {
		if err := c.sqlDB.PingContext(ctx); err != nil {
			return fmt.Errorf("SQL ping failed: %w", err)
		}
	} else {
		return fmt.Errorf("no active connection to ping")
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

	if c.useNative {
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
	} else {
		rows, err := c.sqlDB.QueryContext(ctx, query, c.config.Database)
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
	}

	log.Debug().Int("count", len(tables)).Msg("Retrieved tables list")
	return tables, nil
}

// ExecuteQuery executes a SQL query and returns results
func (c *Client) ExecuteQuery(ctx context.Context, query string, args ...interface{}) (*QueryResult, error) {
	// Check if the query is a SELECT query
	isSelect := isSelectQuery(query)

	if isSelect {
		if c.useNative {
			return c.executeNativeSelect(ctx, query, args...)
		} else {
			return c.executeSQLSelect(ctx, query, args...)
		}
	} else {
		// For non-SELECT queries (DDL, DML)
		if c.useNative {
			return c.executeNativeNonSelect(ctx, query, args...)
		} else {
			return c.executeSQLNonSelect(ctx, query, args...)
		}
	}
}

// executeNativeSelect executes a SELECT query using native interface
func (c *Client) executeNativeSelect(ctx context.Context, query string, args ...interface{}) (*QueryResult, error) {
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

// executeSQLSelect executes a SELECT query using SQL interface
func (c *Client) executeSQLSelect(ctx context.Context, query string, args ...interface{}) (*QueryResult, error) {
	result := &QueryResult{}

	rows, err := c.sqlDB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer rows.Close()

	// Get column information
	columns, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to get columns: %w", err)
	}
	result.Columns = columns

	columnTypes, err := rows.ColumnTypes()
	if err != nil {
		return nil, fmt.Errorf("failed to get column types: %w", err)
	}

	result.Types = make([]string, len(columnTypes))
	for i, ct := range columnTypes {
		result.Types[i] = ct.DatabaseTypeName()
	}

	// Fetch rows
	for rows.Next() {
		// Create a slice of interface{} to hold the row values
		rowValues := make([]interface{}, len(columns))
		rowPointers := make([]interface{}, len(columns))

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

// executeNativeNonSelect executes a non-SELECT query using native interface
func (c *Client) executeNativeNonSelect(ctx context.Context, query string, args ...interface{}) (*QueryResult, error) {
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

// executeSQLNonSelect executes a non-SELECT query using SQL interface
func (c *Client) executeSQLNonSelect(ctx context.Context, query string, args ...interface{}) (*QueryResult, error) {
	result := &QueryResult{}

	res, err := c.sqlDB.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}

	// Try to get affected rows, though ClickHouse might not support this properly
	rowsAffected, _ := res.RowsAffected()

	// For non-SELECT queries, we just return a simple result
	result.Columns = []string{"status", "rows_affected"}
	result.Types = []string{"String", "UInt64"}
	result.Rows = [][]interface{}{{"OK", rowsAffected}}
	result.Count = 1

	log.Debug().
		Str("query", truncateString(query, 100)).
		Int64("rows_affected", rowsAffected).
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
	queryPrefix := getQueryPrefix(query)
	return queryPrefix == "SELECT" || queryPrefix == "WITH"
}

// getQueryPrefix gets the first word of a query (normalized to uppercase)
func getQueryPrefix(query string) string {
	var prefix string
	fmt.Sscanf(query, "%s", &prefix)
	return prefix
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
