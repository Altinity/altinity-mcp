# JWE (JSON Web Encryption) for Altinity MCP Server

This document explains how to use JWE (JSON Web Encryption) authentication with the Altinity MCP Server to securely connect to ClickHouse® instances.

## Overview

JWE authentication allows you to:

- Securely pass ClickHouse® connection parameters without exposing them in plain text
- Create per-request ClickHouse® connections with different parameters
- Support dynamic connection parameters rather than using a single global connection
- Implement token-based access control with expiration

## Self-contained connection contract

Tokens must carry nonempty string `host` and `username` claims. A token missing
either is rejected with `jwe: token must carry host and username claims` in
JWE-only mode. `password` may be absent or empty for password-less ClickHouse
users; it is never inherited from the server.

The connection uses token claims for its endpoint, database, credentials, and
TLS settings. Server `host`, `connect_host`, `port`, `database`, `username`,
`password`, HTTP headers, TLS material, and roles are never inherited. Only
`protocol` (default `http`), `read_only`, `max_execution_time`, `max_result_rows`,
`max_result_bytes`, `max_query_length`, and a separate copy of `extra_settings`
come from the operator configuration. If the token omits `port`, it defaults to
8123 for the effective HTTP protocol or 9000 for TCP. Set the port explicitly
for TLS endpoints such as 8443 or 9440.

When both JWE and OAuth are enabled, a complete JWE takes priority without an
OAuth overlay. A valid encrypted JWE missing `host` or `username` falls through
to OAuth, which uses the operator's ClickHouse endpoint and ignores all partial
JWE connection claims. A malformed or undecryptable JWE remains an error even
when an OAuth bearer is present.

**Migration:** regenerate tokens that relied on server connection defaults,
including the required `host` and `username` and any intended database, port,
password, or TLS settings. Static credentials and headers no longer supply
missing token fields.

### TLS material allowlist

Token `tls_ca_cert`, `tls_client_cert`, and `tls_client_key` values are server-side
file paths. Nonempty values are denied by default. To allow them, mount only
intended certificate/key files in an operator-controlled directory and set
`server.jwe.tls_material_dir`, `--jwe-tls-material-dir`, or
`MCP_JWE_TLS_MATERIAL_DIR` to that directory:

```yaml
server:
  jwe:
    enabled: true
    tls_material_dir: /etc/altinity-mcp/jwe-tls
```

Token paths must be absolute and inside that directory. Traversal, sibling
paths, and symlinks escaping the directory are rejected before file contents
are read, even when `tls_enabled` is false. Symlinks pointing within the
allowlist are accepted and resolved. The directory and its files must not be
writable by token holders; keep mounted material read-only. Validation and TLS
material loading errors omit paths, file contents, and underlying loader errors.
An ordinary TLS connection using public trust roots needs no file claims or
allowlist.

## Command Line Options

The following CLI options are available for JWE authentication:

```
--allow-jwe-auth                  Enable JWE encryption for ClickHouse® connection
--jwe-secret-key string           Secret key for JWE token decryption
--jwt-secret-key string           Secret key for nested JWT signature verification (optional)
--jwe-tls-material-dir string     Directory allowlist for token TLS file paths (empty denies paths)
```

You can also set these options using environment variables:

```
MCP_ALLOW_JWE_AUTH=true
MCP_JWE_SECRET_KEY=jwe-encryption-secret
MCP_JWT_SECRET_KEY=jwt-signing-secret
MCP_JWE_TLS_MATERIAL_DIR=/etc/altinity-mcp/jwe-tls
```

## Starting the Server with JWE Authentication

To start the server with JWE authentication enabled:

```bash
./altinity-mcp --allow-jwe-auth --jwe-secret-key="your-jwe-secret" --jwt-secret-key="your-jwt-secret" --transport=sse
```

This will start the server with JWE authentication enabled, using the provided keys for token processing.

Then use the token generator tool to create JWE tokens:

```bash
go run cmd/jwe_auth/jwe_token_generator.go \
  --jwe-secret-key="your-jwe-encryption-secret" \
  --jwt-secret-key="your-jwt-signing-secret" \
  --host=clickhouse.example.com \
  --port=8123 \
  --database=my_database \
  --username=my_user \
  --password=my_password \
  --protocol=http \
  --expiry=3600
```

For TLS-enabled connections with custom material, first configure the server
allowlist as described above. The paths below refer to files mounted on the
server, not on the token generator machine:

```bash
go run cmd/jwe_auth/jwe_token_generator.go \
  --jwe-secret-key="your-jwe-encryption-secret" \
  --jwt-secret-key="your-jwt-signing-secret" \
  --host=clickhouse.example.com \
  --port=9440 \
  --database=my_database \
  --username=my_user \
  --password=my_password \
  --protocol=tcp \
  --tls \
  --tls-ca-cert=/etc/altinity-mcp/jwe-tls/ca.crt \
  --tls-client-cert=/etc/altinity-mcp/jwe-tls/client.crt \
  --tls-client-key=/etc/altinity-mcp/jwe-tls/client.key \
  --expiry=3600
```

This will generate a signed with --jwt-secret-key JWT token containing the specified ClickHouse® connection parameters, valid for 1 hour (3600 seconds).
And encrypt it with AES using --jwe-secret-key

To generate tokens without JWT signing (using JSON serialization instead), simply omit the `--jwt-secret-key` parameter:

```bash
go run cmd/jwe_auth/jwe_token_generator.go \
  --jwe-secret-key="your-jwe-encryption-secret" \
  --host=clickhouse.example.com \
  --port=8123 \
  --database=my_database \
  --username=my_user \
  --password=my_password \
  --protocol=http \
  --expiry=3600
```

### JWE Token Generation Endpoint

The Altinity MCP server provides a `/jwe-token-generator` endpoint that allows you to generate JWE tokens dynamically. This is useful for integrations where you need to generate tokens on the fly without using the command-line tool.

To use this endpoint, you must have JWE authentication enabled on the server.

**Endpoint:** `POST /jwe-token-generator`

**Request Body:** A JSON object with the desired claims for the token. The claims are the same as the parameters for the CLI generator.

**Example Request for HTTP:**
```bash
curl -X POST http://localhost:8080/jwe-token-generator \
-H "Content-Type: application/json" \
-d '{
    "host": "clickhouse.example.com",
    "port": 8123,
    "database": "my_database",
    "username": "my_user",
    "password": "my_password",
    "protocol": "http",
    "expiry": 3600
}'
```
**Example Request for HTTPS/TLS:**

Protocol is always http but with TLS enabled we need to add a couple of tls params:

```bash
curl -X POST http://localhost:8080/jwe-token-generator \
-H "Content-Type: application/json" \
-d '{
    "host": "clickhouse.example.com",
    "port": 8443,
    "database": "my_database",
    "username": "my_user",
    "password": "my_password",
    "protocol": "http",
    "tls_enabled": true,
    "tls_insecure_skip_verify": false,
    "expiry": 3600
}'
```

**Successful Response:** A JSON object containing the generated token.

```json
{
    "token": "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMjU2R0NNIiwiY3R5IjoiSldUIiwidHlwIjoiSldFIn0. ..."
}
```

**Error Responses:**
- `403 Forbidden`: If JWE authentication is not enabled on the server.
- `405 Method Not Allowed`: If a method other than `POST` is used.
- `400 Bad Request`: If the request body is not valid JSON.

## Token Generation and Validation

The JWE token generation supports two modes:

1. **JWT-signed tokens** (when `--jwt-secret-key` is provided):
   - Claims are serialized to JSON and signed using HS256 algorithm
   - The signed JWT is then encrypted using JWE
   - Provides both encryption and signature verification

2. **JSON-encrypted tokens** (when `--jwt-secret-key` is omitted):
   - Claims are serialized directly to JSON
   - The JSON is then encrypted using JWE
   - Provides encryption without signature verification

## JWT Token Structure

The JWT token contains the following claims:

- `host`: ClickHouse® server hostname (required nonempty string)
- `port`: ClickHouse® server port (optional; defaults to 8123 for HTTP or 9000 for TCP)
- `database`: ClickHouse® database name
- `username`: ClickHouse® username (required nonempty string)
- `password`: ClickHouse® password (optional)
- `protocol`: ClickHouse® connection protocol (http/tcp)
- `tls_enabled`: Boolean indicating if TLS is enabled (optional)
- `tls_ca_cert`: Absolute path to CA certificate file in `tls_material_dir` (optional)
- `tls_client_cert`: Absolute path to client certificate file in `tls_material_dir` (optional)
- `tls_client_key`: Absolute path to client key file in `tls_material_dir` (optional)
- `tls_insecure_skip_verify`: Boolean to skip certificate verification (optional)
- `exp`: Token expiration timestamp

## Connecting to the Server with a JWE Token

### Standard URL Parameter Method

If using the SSE transport with dynamic paths:

```
http://localhost:8080/<generated-jwe-token>/sse
```

## Security Considerations

- Always use HTTPS when transmitting JWE tokens to prevent token interception
- Use a strong, random secret key for token signing
- Set appropriate token expiration times
- To implementing token revocation if needed for additional security, change using jwe-secret-key in `altinity-mcp` configuration

Dynamic catalogs and OpenAPI schemas are isolated by the effective request credential. The exact `/openapi` route also requires authentication; server credentials cannot supply anonymous discovery. In combined JWE/OAuth mode, a self-contained JWE takes priority and a partial JWE uses OAuth when available. SSE GET and POST must use the same effective credential, and clients must reconnect after an effective configuration change. Unchanged reload polls preserve sessions. See [dynamic discovery](tools.md#dynamic-discovery).
