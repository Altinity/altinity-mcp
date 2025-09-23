# Altinity MCP Server

[![Coverage Status](https://coveralls.io/repos/github/Altinity/altinity-mcp/badge.svg)](https://coveralls.io/github/Altinity/altinity-mcp)

A Model Context Protocol (MCP) server that provides tools for interacting with ClickHouse® databases. This server enables AI assistants and other MCP clients to query, analyze, and interact with ClickHouse® databases through a standardized protocol.

## Features

- **Multiple Transport Options**: Support for STDIO, HTTP, and Server-Sent Events (SSE) transports
- **JWE Authentication**: Optional JWE-based authentication with encryption for secure database access
- **TLS Support**: Full TLS encryption support for both ClickHouse® connections and MCP server endpoints
- **Comprehensive Tools**: Built-in tools for listing tables, describing schemas, and executing queries
- **Resource Templates**: Dynamic resource discovery for database schemas and table information
- **Query Prompts**: AI-assisted query building and optimization prompts
- **Configuration Management**: Flexible configuration via files, environment variables, or CLI flags
- **Hot Reload**: Dynamic configuration reloading without server restart

## Table of Contents
- [Quick Start](#quick-start)
- [Integration Guide](#integration-guide)
- [Installation & Deployment](#installation--deployment)
- [Configuration](#configuration)
- [Available Tools](#available-tools)
- [Available Resources](#available-resources)
- [Available Prompts](#available-prompts)
- [OpenAI GPTs Integration](#openai-gpts-integration)
- [JWE Authentication](#jwe-authentication)
- [TLS Configuration](#tls-configuration)
- [Testing](#testing)
- [Development](#development)
- [CLI Reference](#cli-reference)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

## Quick Start

### Using STDIO Transport (Default)

```bash
# Basic usage with default settings
./altinity-mcp --clickhouse-host localhost --clickhouse-port 8123

# With custom database and credentials
./altinity-mcp \
  --clickhouse-host clickhouse.example.com \
  --clickhouse-port 9000 \
  --clickhouse-protocol tcp \
  --clickhouse-database analytics \
  --clickhouse-username reader \
  --clickhouse-password secret123 \
  --clickhouse-limit 5000
```

### Using HTTP Transport with OpenAPI

```bash
./altinity-mcp \
  --transport http \
  --address 0.0.0.0 \
  --port 8080 \
  --clickhouse-host localhost \
  --openapi http
```

### Using SSE Transport with JWE Authentication and OpenAPI

```bash
./altinity-mcp \
  --transport sse \
  --port 8080 \
  --allow-jwe-auth \
  --jwe-secret-key "your-jwe-encryption-secret" \
  --jwt-secret-key "your-jwt-signing-secret" \
  --clickhouse-host localhost \
  --openapi http
```

## Integration Guide

For detailed instructions on integrating Altinity MCP with various AI tools and platforms, see our [Integration Guide](docs/howto_integrate.md).

## Installation & Deployment

### Using Docker

```bash
docker run -it --rm ghcr.io/altinity/altinity-mcp:latest --clickhouse-host clickhouse
```

### Kubernetes with Helm

From OCI helm registry (recommended)
```bash
# Install from OCI registry
helm install altinity-mcp oci://ghcr.io/altinity/altinity-mcp/helm/altinity-mcp \
  --set config.clickhouse.host=clickhouse.example.com \
  --set config.clickhouse.database=default \
  --set config.clickhouse.limit=5000
```

From local helm chart
```bash
git clone https://github.com/Altinity/altinity-mcp
cd altinity-mcp
helm install altinity-mcp ./helm/altinity-mcp \
  --set config.clickhouse.host=clickhouse-service \
  --set config.clickhouse.database=analytics \
  --set config.server.transport=http \
  --set config.server.port=8080
```

For detailed Helm chart configuration options, see [Helm Chart README](helm/altinity-mcp/README.md).

### Docker Compose

```yaml
version: '3.8'
services:
  altinity-mcp:
    build: .
    ports:
      - "8080:8080"
    environment:
      - CLICKHOUSE_HOST=clickhouse
      - MCP_TRANSPORT=http
      - MCP_PORT=8080
    depends_on:
      - clickhouse
    entrypoint: ["/bin/sh", "-c", "/bin/altinity-mcp"]
  
  clickhouse:
    image: clickhouse/clickhouse-server:latest
    ports:
      - "8123:8123"
```

### From Source

```bash
git clone https://github.com/altinity/altinity-mcp.git
cd altinity-mcp
go build -o altinity-mcp ./cmd/altinity-mcp
```


## Configuration

### Configuration File

Create a YAML or JSON configuration file:

```yaml
# config.yaml
clickhouse:
  host: "localhost"
  port: 8123
  database: "default"
  username: "default"
  password: ""
  protocol: "http"
  read_only: false
  max_execution_time: 600
  tls:
    enabled: false
    ca_cert: ""
    client_cert: ""
    client_key: ""
    insecure_skip_verify: false

server:
  transport: "stdio"
  address: "0.0.0.0"
  port: 8080
  tls:
    enabled: false
    cert_file: ""
    key_file: ""
    ca_cert: ""
  jwt:
    enabled: false
    secret_key: ""
  openapi:
    enabled: false
    tls: false

logging:
  level: "info"
```

Use the configuration file:

```bash
./altinity-mcp --config config.yaml
```

### Environment Variables

All configuration options can be set via environment variables:

```bash
export CLICKHOUSE_HOST=localhost
export CLICKHOUSE_PORT=8123
export CLICKHOUSE_DATABASE=analytics
export CLICKHOUSE_LIMIT=5000
export MCP_TRANSPORT=http
export MCP_PORT=8080
export LOG_LEVEL=debug

./altinity-mcp
```

## Available Tools

### `list_tables`
Lists all tables in a ClickHouse® database with detailed information.

**Parameters:**
- `database` (optional): The database to list tables from

### `describe_table`
Describes the schema of a specific table including column types, constraints, and metadata.

**Parameters:**
- `database` (required): The database name
- `table_name` (required): The table name

### `execute_query`
Executes SQL queries against ClickHouse® with optional result limiting.

**Parameters:**
- `query` (required): The SQL query to execute
- `limit` (optional): Maximum number of rows to return (default: server configured limit, max: 10,000)

## Available Resources

### `clickhouse://schema`
Provides complete schema information for the ClickHouse® database in JSON format.

### `clickhouse://table/{database}/{table}`
Provides detailed information about a specific table including schema, sample data, and statistics.

## Available Prompts

### `query_builder`
Helps build efficient ClickHouse® SQL queries with context about available tables and best practices.

**Arguments:**
- `database` (required): Name of the database
- `table_name` (optional): Specific table to focus on
- `query_type` (optional): Type of query (SELECT, INSERT, etc.)

## OpenAI GPTs Integration

The Altinity MCP Server supports seamless integration with OpenAI GPTs through its OpenAPI-compatible endpoints. These endpoints enable GPT assistants to perform ClickHouse® database operations directly.

### Authentication
- **With JWE**: Add the JWE token to either:
  1. Path parameter: `/{jwe_token}/openapi/...` (now required)
  2. Authorization header: `Bearer {token}` (alternative)
  3. `x-altinity-mcp-key` header (alternative)
- **Without JWE**: Use server-configured credentials (no auth needed in requests)

### Available Actions

#### 1. List Tables in Database
**Path**: `/openapi/list_tables`  
**Parameters**:
- `jwe_token` (path param): JWE authentication token
- `database` (query param): Name of database (optional, returns all databases if omitted)

**Example OpenAPI Path**:
```
GET /{jwe_token}/openapi/list_tables?database={db_name}
```

#### 2. Describe Table Structure
**Path**: `/openapi/describe_table`  
**Parameters**:
- `jwe_token` (path param): JWE authentication token
- `database` (query param): Name of database (required)
- `table_name` (query param): Name of table to describe (required)

**Example OpenAPI Path**:
```
GET /{jwe_token}/openapi/describe_table?database={db_name}&table_name={table_name}
```

#### 3. Execute SQL Query
**Path**: `/openapi/execute_query`  
**Parameters**:
- `jwe_token` (path param): JWE authentication token
- `query` (query param): SQL query to execute (required)
- `limit` (query param): Maximum rows to return (optional, default 1000, max 10000)

**Example OpenAPI Path**:
```
GET /{jwe_token}/openapi/execute_query?query=SELECT%20*%20FROM%20table&limit=500
```

### Configuration Example for GPTs
```json
{
  "openapi": "3.1.0",
  "info": {
    "title": "ClickHouse® SQL Interface",
    "version": "1.0.0"
  },
  "servers": [
    {"url": "https://your-server:8080/{token}"}
  ],
  "paths": {
    "/{jwe_token}/openapi/list_tables": {
      "get": {
        "operationId": "list_tables",
        "parameters": [
          {
            "name": "jwe_token",
            "in": "path",
            "required": true,
            "schema": {"type": "string"}
          },
          {
            "name": "database",
            "in": "query",
            "schema": {"type": "string"}
          }
        ]
      }
    },
    "/{jwe_token}/openapi/describe_table": {
      "get": {
        "operationId": "describe_table",
        "parameters": [
          {
            "name": "jwe_token",
            "in": "path",
            "required": true,
            "schema": {"type": "string"}
          },
          {
            "name": "database",
            "in": "query",
            "required": true
          },
          {
            "name": "table_name",
            "in": "query",
            "required": true
          }
        ]
      }
    },
    "/{jwe_token}/openapi/execute_query": {
      "get": {
        "operationId": "execute_query",
        "parameters": [
          {
            "name": "jwe_token",
            "in": "path",
            "required": true,
            "schema": {"type": "string"}
          },
          {
            "name": "query",
            "in": "query",
            "required": true
          },
          {
            "name": "limit",
            "in": "query",
            "schema": {"type": "integer"}
          }
        ]
      }
    }
  }
}
```

> **Note**: For Altinity Cloud deployments, use the provided endpoint URL with your organization-specific token.

## JWE Authentication

When JWE authentication is enabled, the server expects tokens encrypted using AES Key Wrap (A256KW) and AES-GCM (A256GCM). These tokens contain ClickHouse® connection parameters:

```json
{
  "host": "clickhouse.example.com",
  "port": 8123,
  "database": "analytics",
  "username": "user123",
  "password": "secret",
  "protocol": "http",
  "secure": "false"
}
```

Generate tokens using the provided utility. 

```bash
go run ./cmd/jwe_auth/jwe_token_generator.go \
  --jwe-secret-key "your-jwe-encryption-secret" \
  --jwt-secret-key "your-jwt-signing-secret" \
  --host "clickhouse.example.com" \
  --port 8123 \
  --database "analytics" \
  --username "user123" \
  --password "password123" \
  --expiry 86400
```
More details in [jwe_authentication.md](docs/jwe_authentication.md)

## TLS Configuration

### ClickHouse® TLS

```bash
./altinity-mcp \
  --clickhouse-tls \
  --clickhouse-tls-ca-cert /path/to/ca.crt \
  --clickhouse-tls-client-cert /path/to/client.crt \
  --clickhouse-tls-client-key /path/to/client.key
```

### Server TLS

```bash
./altinity-mcp \
  --transport https \
  --server-tls \
  --server-tls-cert-file /path/to/server.crt \
  --server-tls-key-file /path/to/server.key
```

## Testing

### Test ClickHouse® Connection

```bash
./altinity-mcp test-connection \
  --clickhouse-host localhost \
  --clickhouse-port 8123 \
  --clickhouse-database default
```

### Run Tests

```bash
go test ./...
```

### Integration Tests

Integration tests use Docker containers and require Docker to be running:

```bash
go test -v ./cmd/altinity-mcp/...
```

## Development

### Prerequisites

- Go 1.24 or later
- Docker (for integration tests)
- ClickHouse® server (for development)

### Building

```bash
go build -o altinity-mcp ./cmd/altinity-mcp
```

### Running Tests

```bash
# Unit tests
go test ./pkg/...

# Integration tests (requires Docker)
go test -v ./cmd/altinity-mcp/...
```

## CLI Reference

### Global Flags

- `--config`: Path to configuration file (YAML or JSON)
- `--log-level`: Logging level (debug/info/warn/error)
- `--clickhouse-limit`: Default limit for query results (default: 1000)
- `--openapi`: Enable OpenAPI endpoints (disable/http/https) (default: disable)

### ClickHouse® Flags

- `--clickhouse-host`: ClickHouse® server host
- `--clickhouse-port`: ClickHouse® server port
- `--clickhouse-database`: Database name
- `--clickhouse-username`: Username
- `--clickhouse-password`: Password
- `--clickhouse-protocol`: Protocol (http/tcp)
- `--read-only`: Read-only mode
- `--clickhouse-max-execution-time`: Query timeout in seconds
- `--clickhouse-http-headers`: HTTP headers for ClickHouse requests (key=value pairs)

### Server Flags

- `--transport`: Transport type (stdio/http/sse)
- `--address`: Server address
- `--port`: Server port
- `--allow-jwe-auth`: Enable JWE authentication
- `--jwe-secret-key`: Secret key for JWE token decryption (must be 32 bytes for A256KW).
- `--jwt-secret-key`: Secret key for JWT signature verification

### Commands

- `version`: Show version information
- `test-connection`: Test ClickHouse® connection

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the Apache License 2.0. See the LICENSE file for details.

## Support

For support and questions:
- GitHub Issues: [https://github.com/altinity/altinity-mcp/issues](https://github.com/altinity/altinity-mcp/issues)
- Email: support@altinity.com
