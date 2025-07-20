# JWE (JSON Web Encryption) for Altinity MCP Server

This document explains how to use JWE (JSON Web Encryption) authentication with the Altinity MCP Server to securely connect to ClickHouse instances.

## Overview

JWE authentication allows you to:

- Securely pass ClickHouse connection parameters without exposing them in plain text
- Create per-request ClickHouse connections with different parameters
- Support dynamic connection parameters rather than using a single global connection
- Implement token-based access control with expiration

## Command Line Options

The following CLI options are available for JWE authentication:

```
--allow-jwe-auth                  Enable JWE encryption for ClickHouse connection
--jwe-secret-key string           RSA private key for JWE token decryption
-jwt-secret-key string            Secret key for JWT signature verification
--jwe-token-param string          URL parameter name for JWE token (default "token")
```

You can also set these options using environment variables:

```
MCP_ALLOW_JWE_AUTH=true
MCP_JWE_SECRET_KEY=<RSA_PRIVATE_KEY>
MCP_JWT_SECRET_KEY=jwt-signing-secret
MCP_JWE_TOKEN_PARAM=token
```

## Starting the Server with JWE Authentication

To start the server with JWE authentication enabled:

```bash
./altinity-mcp --allow-jwe-auth --jwe-secret-key="your-jwe-secret" --jwt-secret-key="your-jwt-secret" --transport=sse
```

This will start the server with JWE authentication enabled, using the provided keys for token processing.

## Generating JWE Tokens

First generate an RSA private key for JWE encryption/decryption:

```bash
JWE_SECRET_KEY="$(openssl genrsa 4096)"
echo "Generated RSA private key:"
echo "${JWE_SECRET_KEY}"
```

Then use the token generator tool to create JWE tokens:

```bash
go run cmd/jwe_auth/jwe_token_generator.go \
  --jwe-secret-key="${JWE_SECRET_KEY}" \
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
  --jwe-secret-key="${JWE_SECRET_KEY}" \
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

This will generate a JWT token containing the specified ClickHouse connection parameters, valid for 1 hour (3600 seconds).

## JWT Token Structure

The JWT token contains the following claims:

- `host`: ClickHouse server hostname
- `port`: ClickHouse server port
- `database`: ClickHouse database name
- `username`: ClickHouse username
- `password`: ClickHouse password (optional)
- `protocol`: ClickHouse connection protocol (http/tcp)
- `tls_enabled`: Boolean indicating if TLS is enabled (optional)
- `tls_ca_cert`: Path to CA certificate file (optional)
- `tls_client_cert`: Path to client certificate file (optional)
- `tls_client_key`: Path to client key file (optional)
- `tls_insecure_skip_verify`: Boolean to skip certificate verification (optional)
- `exp`: Token expiration timestamp

## Connecting to the Server with a JWT Token

### Standard URL Parameter Method

When connecting to the MCP server, include the JWT token as a URL parameter:

```
http://localhost:8080/sse?token=<your-jwt-token>
```

### Dynamic Path Method (Go 1.22+)

If using the SSE transport with dynamic paths:

```
http://localhost:8080/<your-jwt-token>/sse
```

## Security Considerations

- Always use HTTPS when transmitting JWT tokens to prevent token interception
- Use a strong, random secret key for token signing
- Set appropriate token expiration times
- Avoid including sensitive information in tokens if not necessary
- Consider implementing token revocation if needed for additional security
