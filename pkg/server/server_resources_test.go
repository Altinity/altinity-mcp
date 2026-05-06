package server

import (
	"context"
	"testing"

	"github.com/altinity/altinity-mcp/pkg/config"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

// TestHandleSchemaResource tests the schema resource handler
func TestHandleSchemaResource(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	ctx = context.WithValue(ctx, CHJWEServerKey, srv)

	t.Run("returns_schema", func(t *testing.T) {
		t.Parallel()
		result, err := HandleSchemaResource(ctx, &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{}})
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Len(t, result.Contents, 1)
		require.Equal(t, "clickhouse://schema", result.Contents[0].URI)
		require.Equal(t, "application/json", result.Contents[0].MIMEType)
		require.NotEmpty(t, result.Contents[0].Text)
	})

	t.Run("no_server_in_context", func(t *testing.T) {
		t.Parallel()
		_, err := HandleSchemaResource(context.Background(), &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{}})
		require.Error(t, err)
	})
}

// TestHandleTableResource tests the table resource handler
func TestHandleTableResource(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	ctx = context.WithValue(ctx, CHJWEServerKey, srv)

	t.Run("returns_table_structure", func(t *testing.T) {
		t.Parallel()
		req := &mcp.ReadResourceRequest{
			Params: &mcp.ReadResourceParams{URI: "clickhouse://table/default/test"},
		}

		result, err := HandleTableResource(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Len(t, result.Contents, 1)
		require.Equal(t, "clickhouse://table/default/test", result.Contents[0].URI)
		require.NotEmpty(t, result.Contents[0].Text)
	})

	t.Run("invalid_uri_format", func(t *testing.T) {
		t.Parallel()
		req := &mcp.ReadResourceRequest{
			Params: &mcp.ReadResourceParams{URI: "invalid://uri"},
		}

		_, err := HandleTableResource(ctx, req)
		require.Error(t, err)
	})

	t.Run("no_server_in_context", func(t *testing.T) {
		t.Parallel()
		req := &mcp.ReadResourceRequest{
			Params: &mcp.ReadResourceParams{URI: "clickhouse://table/default/test"},
		}

		_, err := HandleTableResource(context.Background(), req)
		require.Error(t, err)
	})
}

// TestResourceHandlers_NoServerInContext tests error handling when server is missing from context
func TestResourceHandlers_NoServerInContext(t *testing.T) {
	t.Parallel()
	// Directly call handlers with empty context to cover error paths
	_, err := HandleSchemaResource(context.Background(), &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{}})
	require.Error(t, err)

	req := &mcp.ReadResourceRequest{
		Params: &mcp.ReadResourceParams{URI: "clickhouse://table/db/t"},
	}
	_, err = HandleTableResource(context.Background(), req)
	require.Error(t, err)
}

// TestHandleTableResource_EmptyDatabaseOrTable tests invalid URI with empty parts
func TestHandleTableResource_EmptyDatabaseOrTable(t *testing.T) {
	t.Parallel()
	srv := &ClickHouseJWEServer{
		Config:       config.Config{Server: config.ServerConfig{JWE: config.JWEConfig{Enabled: false}}},
		dynamicTools: map[string]dynamicToolMeta{},
	}

	ctx := context.WithValue(context.Background(), CHJWEServerKey, srv)

	t.Run("empty_database", func(t *testing.T) {
		t.Parallel()
		req := &mcp.ReadResourceRequest{
			Params: &mcp.ReadResourceParams{URI: "clickhouse://table//test"},
		}
		_, err := HandleTableResource(ctx, req)
		require.Error(t, err)
	})

	t.Run("empty_table", func(t *testing.T) {
		t.Parallel()
		req := &mcp.ReadResourceRequest{
			Params: &mcp.ReadResourceParams{URI: "clickhouse://table/default/"},
		}
		_, err := HandleTableResource(ctx, req)
		require.Error(t, err)
	})
}

func TestHandleSchemaResourceE2E(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	ctx := context.WithValue(context.Background(), CHJWEServerKey, srv)

	result, err := HandleSchemaResource(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Contents, 1)
	require.Contains(t, result.Contents[0].Text, "test")
	require.Equal(t, "application/json", result.Contents[0].MIMEType)
}

func TestHandleSchemaResourceE2E_NoServer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, err := HandleSchemaResource(ctx, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "can't get JWEServer from context")
}

func TestHandleTableResourceE2E(t *testing.T) {
	t.Parallel()
	chConfig := setupEmbeddedClickHouse(t)

	srv := NewClickHouseMCPServer(config.Config{
		ClickHouse: *chConfig,
		Server:     config.ServerConfig{JWE: config.JWEConfig{Enabled: false}},
	}, "test")

	ctx := context.WithValue(context.Background(), CHJWEServerKey, srv)

	t.Run("valid_table", func(t *testing.T) {
		req := &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "clickhouse://table/default/test"}}
		result, err := HandleTableResource(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Len(t, result.Contents, 1)
		require.Contains(t, result.Contents[0].Text, "id")
	})

	t.Run("invalid_uri_format", func(t *testing.T) {
		req := &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "invalid-uri"}}
		_, err := HandleTableResource(ctx, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid table URI format")
	})

	t.Run("empty_database", func(t *testing.T) {
		req := &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "clickhouse://table//test"}}
		_, err := HandleTableResource(ctx, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid table URI format")
	})

	t.Run("nonexistent_table", func(t *testing.T) {
		req := &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "clickhouse://table/default/nonexistent_table_xyz"}}
		_, err := HandleTableResource(ctx, req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get table structure")
	})

	t.Run("no_server_in_context", func(t *testing.T) {
		req := &mcp.ReadResourceRequest{Params: &mcp.ReadResourceParams{URI: "clickhouse://table/default/test"}}
		_, err := HandleTableResource(context.Background(), req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "can't get JWEServer from context")
	})
}
