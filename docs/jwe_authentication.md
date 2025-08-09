# JWE (JSON Web Encryption) for Altinity MCP Server

This document explains how to use JWE (JSON Web Encryption) authentication with the Altinity MCP Server to securely connect to ClickHouse® instances.

## Overview

JWE authentication allows you to:

- Securely pass ClickHouse® connection parameters without exposing them in plain text
- Create per-request ClickHouse® connections with different parameters
- Support dynamic connection parameters rather than using a single global connection
- Implement token-based access control with expiration

## Command Line Options

The following CLI options are available for JWE authentication:

```
--allow-jwe-auth                  Enable JWE encryption for ClickHouse® connection
--jwe-secret-key string           Secret key for JWE token decryption
--jwt-secret-key string           Secret key for nested JWT signature verification
```

You can also set these options using environment variables:

```
MCP_ALLOW_JWE_AUTH=true
MCP_JWE_SECRET_KEY=jwe-encryption-secret
MCP_JWT_SECRET_KEY=jwt-signing-secret
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

For TLS-enabled connections:

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
  --tls-ca-cert=/path/to/ca.crt \
  --tls-client-cert=/path/to/client.crt \
  --tls-client-key=/path/to/client.key \
  --expiry=3600
```

This will generate a signed with --jwt-secret-key JWT token containing the specified ClickHouse® connection parameters, valid for 1 hour (3600 seconds).
And encrypt it with AES using --jwe-secret-key

### JWE Token Generation Endpoint

The Altinity MCP server provides a `/jwe-token-generator` endpoint that allows you to generate JWE tokens dynamically. This is useful for integrations where you need to generate tokens on the fly without using the command-line tool.

To use this endpoint, you must have JWE authentication enabled on the server.

**Endpoint:** `POST /jwe-token-generator`

**Request Body:** A JSON object with the desired claims for the token. The claims are the same as the parameters for the CLI generator.

**Example Request:**
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

## JWT Token Structure

The JWT token contains the following claims:

- `host`: ClickHouse® server hostname
- `port`: ClickHouse® server port
- `database`: ClickHouse® database name
- `username`: ClickHouse® username
- `password`: ClickHouse® password (optional)
- `protocol`: ClickHouse® connection protocol (http/tcp)
- `tls_enabled`: Boolean indicating if TLS is enabled (optional)
- `tls_ca_cert`: Path to CA certificate file (optional)
- `tls_client_cert`: Path to client certificate file (optional)
- `tls_client_key`: Path to client key file (optional)
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
