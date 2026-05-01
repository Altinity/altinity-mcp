package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog/log"
)

// RegisterResources adds ClickHouse resources to the MCP server
func RegisterResources(srv AltinityMCPServer) {
	// Database catalog resource
	schemaResource := &mcp.Resource{
		URI:         "clickhouse://schema",
		Name:        "Database Catalog",
		Description: "Inventory of visible ClickHouse tables and views with database and engine information",
		MIMEType:    "application/json",
	}

	srv.AddResource(schemaResource, HandleSchemaResource)

	// Table Structure Template Resource
	tableTemplate := &mcp.ResourceTemplate{
		URITemplate: "clickhouse://table/{database}/{table_name}",
		Name:        "Table Structure",
		Description: "Detailed column-level schema information for a specific table",
		MIMEType:    "application/json",
	}

	srv.AddResourceTemplate(tableTemplate, HandleTableResource)

	log.Info().Int("resource_count", 2).Msg("ClickHouse resources registered")
}

// HandleSchemaResource handles the schema resource
func HandleSchemaResource(ctx context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	log.Debug().Msg("Reading database schema resource")

	// Get the ClickHouse JWE server from context
	chJweServer := GetClickHouseJWEServerFromContext(ctx)
	if chJweServer == nil {
		return nil, fmt.Errorf("can't get JWEServer from context")
	}

	// Get ClickHouse client (handles both JWE and OAuth from context)
	chClient, err := chJweServer.GetClickHouseClientFromCtx(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get ClickHouse client")
		return nil, fmt.Errorf("failed to get ClickHouse client: %w", err)
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().
				Err(closeErr).
				Msg("clickhouse://schema: can't close clickhouse")
		}
	}()

	// With an empty database string, ListTables will return tables from all databases
	tables, err := chClient.ListTables(ctx, "")
	if err != nil {
		log.Error().
			Err(err).
			Str("resource", "schema").
			Msg("ClickHouse operation failed: get schema")
		return nil, fmt.Errorf("failed to get schema: %w", err)
	}

	schema := map[string]interface{}{
		"tables": tables,
		"count":  len(tables),
	}

	jsonData, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal schema: %w", err)
	}

	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{
			{
				URI:      "clickhouse://schema",
				MIMEType: "application/json",
				Text:     string(jsonData),
			},
		},
	}, nil
}

// HandleTableResource handles the table resource
func HandleTableResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	// Extract database and table name from URI
	uri := req.Params.URI
	parts := strings.Split(uri, "/")
	// expected clickhouse://table/{database}/{table_name}
	if len(parts) < 5 || parts[0] != "clickhouse:" || parts[1] != "" || parts[2] != "table" {
		return nil, fmt.Errorf("invalid table URI format: %s", uri)
	}
	database := parts[len(parts)-2]
	tableName := parts[len(parts)-1]

	// Validate that database and table name are not empty
	if database == "" || tableName == "" {
		return nil, fmt.Errorf("invalid table URI format: %s", uri)
	}

	log.Debug().Str("database", database).Str("table", tableName).Msg("Reading table structure resource")

	// Get the ClickHouse JWE server from context
	chJweServer := GetClickHouseJWEServerFromContext(ctx)
	if chJweServer == nil {
		return nil, fmt.Errorf("can't get JWEServer from context")
	}

	// Get ClickHouse client (handles both JWE and OAuth from context)
	chClient, err := chJweServer.GetClickHouseClientFromCtx(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get ClickHouse client")
		return nil, fmt.Errorf("failed to get ClickHouse client: %w", err)
	}
	defer func() {
		if closeErr := chClient.Close(); closeErr != nil {
			log.Error().
				Err(closeErr).
				Msgf("clickhouse://table/%s/%s: can't close clickhouse", database, tableName)
		}
	}()

	columns, err := chClient.DescribeTable(ctx, database, tableName)
	if err != nil {
		log.Error().
			Err(err).
			Str("database", database).
			Str("table", tableName).
			Str("resource", "table_structure").
			Msg("ClickHouse operation failed: get table structure")
		return nil, fmt.Errorf("failed to get table structure: %s", ErrJSONEscaper.Replace(err.Error()))
	}

	jsonData, err := json.MarshalIndent(columns, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal table structure: %w", err)
	}

	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{
			{
				URI:      uri,
				MIMEType: "application/json",
				Text:     string(jsonData),
			},
		},
	}, nil
}

// RegisterPrompts adds ClickHouse prompts to the MCP server
func RegisterPrompts(srv AltinityMCPServer) {
	// No prompts registered
	log.Info().Int("prompt_count", 0).Msg("ClickHouse prompts registered")
}
