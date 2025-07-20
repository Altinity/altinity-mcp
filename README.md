# Altinity MCP Server

[![Coverage Status](https://coveralls.io/repos/github/Altinity/altinity-mcp/badge.svg)](https://coveralls.io/github/Altinity/altinity-mcp)

A Model Context Protocol (MCP) server that provides tools for interacting with ClickHouse databases. This server enables AI assistants and other MCP clients to query, analyze, and interact with ClickHouse databases through a standardized protocol.

## Features

- **Multiple Transport Options**: Support for STDIO, HTTP, and Server-Sent Events (SSE) transports
- **JWT Authentication**: Optional JWT-based authentication for secure database access
- **TLS Support**: Full TLS encryption support for both ClickHouse connections and MCP server endpoints
- **Comprehensive Tools**: Built-in tools for listing tables, describing schemas, and executing queries
- **Resource Templates**: Dynamic resource discovery for database schemas and table information
- **Query Prompts**: AI-assisted query building and optimization prompts
- **Configuration Management**: Flexible configuration via files, environment variables, or CLI flags
- **Hot Reload**: Dynamic configuration reloading without server restart

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

### Using SSE Transport with JWT Authentication and OpenAPI

```bash
./altinity-mcp \
  --transport sse \
  --port 8080 \
  --allow-jwt-auth \
  --jwt-secret-key "your-secret-key" \
  --clickhouse-host localhost \
  --openapi http
```

## Installation

### From Source

```bash
git clone https://github.com/altinity/altinity-mcp.git
cd altinity-mcp
go build -o altinity-mcp ./cmd/altinity-mcp
```

### Using Docker

```bash
docker build -t altinity-mcp .
docker run -it altinity-mcp --clickhouse-host host.docker.internal
```

### Using Helm

```bash
git checkout https://github.com/Altinity/altinity-mcp
cd altinity-mcp
helm install altinity-mcp ./helm/altinity-mcp \
  --set config.clickhouse.host=clickhouse.example.com \
  --set config.clickhouse.database=default \
  --set config.limit=5000
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
Lists all tables in a ClickHouse database with detailed information.

**Parameters:**
- `database` (optional): The database to list tables from

### `describe_table`
Describes the schema of a specific table including column types, constraints, and metadata.

**Parameters:**
- `database` (required): The database name
- `table_name` (required): The table name

### `execute_query`
Executes SQL queries against ClickHouse with optional result limiting.

**Parameters:**
- `query` (required): The SQL query to execute
- `limit` (optional): Maximum number of rows to return (default: server configured limit, max: 10,000)

## Available Resources

### `clickhouse://schema`
Provides complete schema information for the ClickHouse database in JSON format.

### `clickhouse://table/{database}/{table}`
Provides detailed information about a specific table including schema, sample data, and statistics.

## Available Prompts

### `query_builder`
Helps build efficient ClickHouse SQL queries with context about available tables and best practices.

**Arguments:**
- `database` (required): Name of the database
- `table_name` (optional): Specific table to focus on
- `query_type` (optional): Type of query (SELECT, INSERT, etc.)

## OpenAI GPTs Integration

The Altinity MCP Server supports seamless integration with OpenAI GPTs through its OpenAPI-compatible endpoints. These endpoints enable GPT assistants to perform ClickHouse database operations directly.

### Authentication
- **With JWT**: Add the JWT token to either:
  1. Path parameter: ``/{token}/openapi/...``
  2. Authorization header: ``Bearer {token}``
  3. ``x-altinity-mcp-key`` header
- **Without JWT**: Use server-configured credentials (no auth needed in requests)

### Available Actions

#### 1. List Tables in Database
**Path**: `/{token}/openapi/list_tables`  
**Parameters**:
- `database`: Name of database (optional, returns all databases if omitted)

**Example OpenAPI Path**:
```
GET /{token}/openapi/list_tables?database={db_name}
```

#### 2. Describe Table Structure
**Path**: `/{token}/openapi/describe_table`  
**Parameters**:
- `database`: Name of database (required)
- `table_name`: Name of table to describe (required)

**Example OpenAPI Path**:
```
GET /{token}/openapi/describe_table?database={db_name}&table_name={table_name}
```

#### 3. Execute SQL Query
**Path**: `/{token}/openapi/execute_query`  
**Parameters**:
- `query`: SQL query to execute (required)
- `limit`: Maximum rows to return (optional, default 1000, max 10000)

**Example OpenAPI Path**:
```
GET /{token}/openapi/execute_query?query=SELECT%20*%20FROM%20table&limit=500
```

### Configuration Example for GPTs
```json
{
  "openapi": "3.1.0",
  "info": {
    "title": "ClickHouse SQL Interface",
    "version": "1.0.0"
  },
  "servers": [
    {"url": "https://your-server:8080/{token}"}
  ],
  "paths": {
    "/openapi/list_tables": {
      "get": {
        "operationId": "list_tables",
        "parameters": [
          {"name": "database", "in": "query", "schema": {"type": "string"}}
        ]
      }
    },
    "/openapi/describe_table": {
      "get": {
        "operationId": "describe_table",
        "parameters": [
          {"name": "database", "in": "query", "required": true},
          {"name": "table_name", "in": "query", "required": true}
        ]
      }
    },
    "/openapi/execute_query": {
      "get": {
        "operationId": "execute_query",
        "parameters": [
          {"name": "query", "in": "query", "required": true},
          {"name": "limit", "in": "query", "schema": {"type": "integer"}}
        ]
      }
    }
  }
}
```

> **Note**: For Altinity Cloud deployments, use the provided endpoint URL with your organization-specific token.

## JWT Authentication

When JWT authentication is enabled, the server expects JWT tokens containing ClickHouse connection parameters:

```json
{
  "host": "clickhouse.example.com",
  "port": 8123,
  "database": "analytics",
  "username": "user123",
  "password": "secret",
  "protocol": "http"
}
```

Generate tokens using the provided utility:

```bash
go run ./jwe_auth/examples/jwt_token_generator.go \
  --secret "your-secret-key" \
  --host "clickhouse.example.com" \
  --database "analytics" \
  --username "user123"
```
More details in [jwt_authentication.md](./jwt_auth/docs/jwt_authentication.md)

## TLS Configuration

### ClickHouse TLS

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

### Test ClickHouse Connection

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

- Go 1.21 or later
- Docker (for integration tests)
- ClickHouse server (for development)

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

## Deployment

### Kubernetes with Helm

```bash
helm install altinity-mcp ./helm/altinity-mcp \
  --set config.clickhouse.host=clickhouse-service \
  --set config.clickhouse.database=analytics \
  --set config.server.transport=http \
  --set config.server.port=8080
```

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
  
  clickhouse:
    image: clickhouse/clickhouse-server:latest
    ports:
      - "8123:8123"
```

## CLI Reference

### Global Flags

- `--config`: Path to configuration file (YAML or JSON)
- `--log-level`: Logging level (debug/info/warn/error)
- `--clickhouse-limit`: Default limit for query results (default: 1000)
- `--openapi`: Enable OpenAPI endpoints (disable/http/https) (default: disable)

### ClickHouse Flags

- `--clickhouse-host`: ClickHouse server host
- `--clickhouse-port`: ClickHouse server port
- `--clickhouse-database`: Database name
- `--clickhouse-username`: Username
- `--clickhouse-password`: Password
- `--clickhouse-protocol`: Protocol (http/tcp)
- `--read-only`: Read-only mode
- `--clickhouse-max-execution-time`: Query timeout in seconds

### Server Flags

- `--transport`: Transport type (stdio/http/sse)
- `--address`: Server address
- `--port`: Server port
- `--allow-jwt-auth`: Enable JWT authentication
- `--jwt-secret-key`: JWT secret key
- `--jwt-token-param`: JWT token parameter name

### Commands

- `version`: Show version information
- `test-connection`: Test ClickHouse connection

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
