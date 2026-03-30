# Development and Testing

This document collects the local development workflow and the repository's test entry points in one place.

## Prerequisites

- Go 1.24 or later
- Docker, for integration tests and the optional OAuth e2e test
- A local or reachable ClickHouse server, if you want to run `test-connection` manually

## Build

Build the main binary:

```bash
go build -o altinity-mcp ./cmd/altinity-mcp
```

Check the current build:

```bash
./altinity-mcp version
```

## Quick Local Check

Validate that the binary can reach ClickHouse before running broader tests:

```bash
./altinity-mcp test-connection \
  --clickhouse-host localhost \
  --clickhouse-port 8123 \
  --clickhouse-database default
```

## Test Matrix

### Full Default Suite

Run the default repository test suite:

```bash
go test ./...
```

This is the baseline command for day-to-day work. It runs unit tests plus the Docker-backed integration tests that are enabled by default in the repository.

### Package-Focused Runs

Run package tests only:

```bash
go test ./pkg/...
```

Run CLI and HTTP handler tests:

```bash
go test -v ./cmd/altinity-mcp/...
```

Run OAuth-focused tests only:

```bash
go test ./pkg/server ./cmd/altinity-mcp ./pkg/config -run OAuth -count=1 -v
```

## Docker-Backed Integration Tests

Several tests start temporary ClickHouse containers with `testcontainers-go`. Before running them, make sure Docker is running and the current user can access the Docker socket.

If Docker is unavailable, the default suite will not be reliable.

## OAuth End-to-End Test

The repository includes an opt-in OAuth e2e test for bearer-token forwarding to ClickHouse:

- Keycloak acts as the OIDC provider
- `altinity/clickhouse-server:25.8.16.20001.altinityantalya` provides `token_processors`
- `altinity-mcp` runs in OAuth forward mode

Run it explicitly:

```bash
RUN_OAUTH_E2E=1 go test ./pkg/server -run TestOAuthE2EWithKeycloak -count=1 -v
```

Notes:

- The test is skipped unless `RUN_OAUTH_E2E=1` is set.
- It is also skipped when running `go test -short`.
- The Antalya image is required because standard upstream ClickHouse images do not include the bearer-token authentication support used by this test.

For configuration background and provider-specific setup, see [oauth_authorization.md](./oauth_authorization.md).

## Suggested Contributor Workflow

For a typical code change:

1. Build the binary with `go build -o altinity-mcp ./cmd/altinity-mcp`
2. Run focused tests for the area you changed
3. Run `go test ./...`
4. Run the opt-in OAuth e2e test when touching OAuth forwarding or broker flow behavior

## Troubleshooting

### Docker Tests Fail Immediately

- Verify Docker is running
- Verify container pulls are allowed from the current environment
- Re-run the failing package with `-v` to see which container-backed test failed

### OAuth E2E Test Is Skipped

Set `RUN_OAUTH_E2E=1` explicitly:

```bash
RUN_OAUTH_E2E=1 go test ./pkg/server -run TestOAuthE2EWithKeycloak -count=1 -v
```

### ClickHouse OAuth E2E Fails with Standard ClickHouse Images

Use the Antalya build referenced above. The standard upstream image does not provide the `token_processors` support this test depends on.
