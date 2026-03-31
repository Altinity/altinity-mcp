# Development and Testing

This document collects the local development workflow and the repository's test entry points in one place.

## Prerequisites

- Go 1.25 or later
- Docker, for integration tests (including OAuth e2e tests)
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

## OAuth End-to-End Tests

OAuth e2e tests validate bearer-token forwarding through MCP to ClickHouse. They use a lightweight in-process mock OIDC provider and an `altinity/clickhouse-server:25.8.16.20001.altinityantalya` container (required for `token_processors` support — standard ClickHouse images do not include it).

These tests run automatically as part of `go test ./...` (skipped with `-short`).

For configuration background and provider-specific setup, see [oauth_authorization.md](./oauth_authorization.md).

## Suggested Contributor Workflow

For a typical code change:

1. Build the binary with `go build -o altinity-mcp ./cmd/altinity-mcp`
2. Run focused tests for the area you changed
3. Run `go test ./...`
4. OAuth e2e tests run automatically — no extra flags needed

## Troubleshooting

### Docker Tests Fail Immediately

- Verify Docker is running
- Verify container pulls are allowed from the current environment
- Re-run the failing package with `-v` to see which container-backed test failed

### OAuth E2E Test Fails with Standard ClickHouse Images

The OAuth e2e tests require the Antalya ClickHouse build (`altinity/clickhouse-server:25.8.16.20001.altinityantalya`). Standard upstream images do not provide the `token_processors` support these tests depend on. The test pulls this image automatically via testcontainers.
