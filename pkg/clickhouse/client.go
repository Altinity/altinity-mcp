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
	Name     string `ch:"name" json:"name"`
	Database string `ch:"database" json:"database"`
	Engine   string `ch:"engine" json:"engine"`
}

// ColumnInfo represents all the information about a column
type ColumnInfo struct {
	Name              string `ch:"name" json:"name"`
	Type              string `ch:"type" json:"type"`
	DefaultKind       string `ch:"default_kind" json:"default_kind"`
	DefaultExpression string `ch:"default_expression" json:"default_expression"`
	Comment           string `ch:"comment" json:"comment"`
	IsInPartitionKey  uint8  `ch:"is_in_partition_key" json:"is_in_partition_key"`
	IsInSortingKey    uint8  `ch:"is_in_sorting_key" json:"is_in_sorting_key"`
	IsInPrimaryKey    uint8  `ch:"is_in_primary_key" json:"is_in_primary_key"`
	IsInSamplingKey   uint8  `ch:"is_in_sampling_key" json:"is_in_sampling_key"`
}

// Client is a wrapper for ClickHouse connection
type Client struct {
	config     config.ClickHouseConfig
	conn       driver.Conn
	ctx        context.Context
	cancelFunc context.CancelFunc
}

// NewClient creates a new ClickHouse client
func NewClient(ctx context.Context, cfg config.ClickHouseConfig) (*Client, error) {
	clickhouseCtx, cancel := context.WithCancel(ctx)
	client := &Client{
		config:     cfg,
		ctx:        clickhouseCtx,
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
		protocol = clickhouse.Native
	default:
		// This should not happen due to validation in main.go, but as a safeguard:
		return fmt.Errorf("unsupported clickhouse protocol: %s", c.config.Protocol)
	}

	settings := clickhouse.Settings{}
	if !c.config.ReadOnly {
		settings["max_execution_time"] = c.config.MaxExecutionTime
	}

	conn, openErr := clickhouse.Open(&clickhouse.Options{
		Addr: []string{fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)},
		Auth: clickhouse.Auth{
			Database: c.config.Database,
			Username: c.config.Username,
			Password: c.config.Password,
		},
		TLS:             tlsConfig,
		Protocol:        protocol,
		Settings:        settings,
		DialTimeout:     time.Second * 10,
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: time.Hour,
	})

	if openErr != nil {
		log.Error().
			Err(openErr).
			Str("host", c.config.Host).
			Int("port", c.config.Port).
			Str("database", c.config.Database).
			Str("protocol", string(c.config.Protocol)).
			Msg("ClickHouse connection failed")
		return openErr
	}

	c.conn = conn

	if pingErr := c.conn.Ping(context.Background()); pingErr != nil {
		log.Error().
			Err(pingErr).
			Str("host", c.config.Host).
			Int("port", c.config.Port).
			Str("database", c.config.Database).
			Str("protocol", string(c.config.Protocol)).
			Msg("ClickHouse ping failed during connection")
		_ = c.conn.Close()
		c.conn = nil
		return fmt.Errorf("connection ping failed: %w", pingErr)
	}

	return nil
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
		log.Error().
			Err(err).
			Str("host", c.config.Host).
			Int("port", c.config.Port).
			Msg("ClickHouse ping failed")
		return fmt.Errorf("ping failed: %w", err)
	}

	log.Debug().Msg("ClickHouse ping successful")
	return nil
}

// DescribeTable returns column information for a given table
func (c *Client) DescribeTable(ctx context.Context, database, tableName string) ([]ColumnInfo, error) {
	query := `
		SELECT
			name,
			type,
			default_kind,
			default_expression,
			comment,
			is_in_partition_key,
			is_in_sorting_key,
			is_in_primary_key,
			is_in_sampling_key
		FROM system.columns
		WHERE database = ? AND table = ?
		ORDER BY position
	`

	rows, err := c.conn.Query(ctx, query, database, tableName)
	if err != nil {
		log.Error().
			Err(err).
			Str("database", database).
			Str("table", tableName).
			Str("query", query).
			Msg("ClickHouse query failed: describe table")
		return nil, fmt.Errorf("failed to query table description for %s: %w", tableName, err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("DescribeTable: can't close rows")
		}
	}()

	var columns []ColumnInfo
	for rows.Next() {
		var col ColumnInfo
		if err := rows.ScanStruct(&col); err != nil {
			log.Error().
				Err(err).
				Str("database", database).
				Str("table", tableName).
				Msg("ClickHouse scan failed: describe table row")
			return nil, fmt.Errorf("failed to scan row for describe table %s: %w", tableName, err)
		}
		columns = append(columns, col)
	}

	if err := rows.Err(); err != nil {
		log.Error().
			Err(err).
			Str("database", database).
			Str("table", tableName).
			Msg("ClickHouse iteration failed: describe table rows")
		return nil, fmt.Errorf("error iterating rows for describe table %s: %w", tableName, err)
	}
	if len(columns) == 0 {
		return nil, fmt.Errorf("`%s`.`%s` columns not found", database, tableName)
	}
	log.Debug().Int("column_count", len(columns)).Str("database", database).Str("table", tableName).Msg("Retrieved table description")
	return columns, nil
}

// ListTables returns a list of tables in the database.
// If the database parameter is empty, it lists tables from all databases.
func (c *Client) ListTables(ctx context.Context, database string) ([]TableInfo, error) {
	query := `
		SELECT
			name,
			database,
			engine
		FROM system.tables
	`
	args := make([]interface{}, 0)
	if database != "" {
		query += " WHERE database = ?"
		args = append(args, database)
	}
	query += " ORDER BY database, name"

	// Initialize the slice to ensure it's never nil
	tables := make([]TableInfo, 0)
	if err := c.conn.Select(ctx, &tables, query, args...); err != nil {
		log.Error().
			Err(err).
			Str("database", database).
			Str("query", query).
			Msg("ClickHouse query failed: list tables")
		return nil, fmt.Errorf("failed to list tables: %w", err)
	}

	log.Debug().Int("count", len(tables)).Msg("Retrieved tables list")
	return tables, nil
}

// Column is a wrapper for a column value that can be scanned
type Column struct {
	Value interface{}
}

// Scan implements the driver.ColumnScanner interface
func (c *Column) Scan(src interface{}) error {
	c.Value = src
	return nil
}

// scanRow scans a single row from the rows object
func scanRow(rows driver.Rows) ([]interface{}, error) {
	columnTypes := rows.ColumnTypes()
	columns := make([]Column, len(columnTypes))
	scannables := make([]interface{}, len(columnTypes))
	for i := range columns {
		scannables[i] = &columns[i]
	}

	if err := rows.Scan(scannables...); err != nil {
		log.Error().
			Err(err).
			Int("column_count", len(scannables)).
			Msg("ClickHouse scan failed: query result row")
		return nil, fmt.Errorf("failed to scan row: %w", err)
	}

	rowValues := make([]interface{}, len(columnTypes))
	for i, col := range columns {
		rowValues[i] = convertToSerializable(col.Value)
	}

	return rowValues, nil
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
		log.Error().
			Err(err).
			Str("query", truncateString(query, 200)).
			Int("arg_count", len(args)).
			Msg("ClickHouse query failed: execute select")
		return nil, fmt.Errorf("failed to execute query: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			log.Error().Err(closeErr).Msg("executeSelect: can't close rows")
		}
	}()

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
		rowValues, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		result.Rows = append(result.Rows, rowValues)
	}

	if err := rows.Err(); err != nil {
		log.Error().
			Err(err).
			Str("query", truncateString(query, 200)).
			Int("rows_processed", len(result.Rows)).
			Msg("ClickHouse iteration failed: select query rows")
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
		log.Error().
			Err(err).
			Str("query", truncateString(query, 200)).
			Int("arg_count", len(args)).
			Msg("ClickHouse exec failed: execute non-select")
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
