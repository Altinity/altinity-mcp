# Isolator Docker API Allowlist Spec for Testcontainers Support

## Problem

The isolator Docker proxy (`/var/run/isolator-docker/altinity.sock`) blocks Docker API endpoints required by testcontainers-go. Only a minimal set of endpoints are currently allowed, making it impossible to run integration tests that spin up ClickHouse containers.

## Current State

Audit of the isolator allowlist as of 2026-04-16:

| Endpoint | Status | Required By |
|----------|--------|-------------|
| `GET /_ping` | ✅ Allowed | Docker SDK version negotiation |
| `GET /v{ver}/info` | ✅ Allowed | testcontainers host detection |
| `GET /info` (no version) | ❌ Blocked | Docker SDK without `DOCKER_API_VERSION` |
| `GET /v{ver}/version` | ✅ Allowed | Docker CLI |
| `GET /v{ver}/containers/json` | ✅ Allowed | Container listing |
| `GET /v{ver}/volumes` | ✅ Allowed | Volume listing |
| `GET /v{ver}/networks/{name}` | ✅ Allowed | Network inspect by name |
| `POST /v{ver}/containers/create` | ✅ Allowed | Container creation |
| `POST /v{ver}/images/create?fromImage=...` | ✅ Allowed | Image pull |
| `GET /v{ver}/networks` | ❌ **Blocked** | testcontainers default network setup |
| `GET /v{ver}/images/json` | ❌ **Blocked** | testcontainers image check |
| `GET /v{ver}/events` | ❌ **Blocked** | testcontainers event streaming |
| `POST /v{ver}/networks/create` | ❌ **Blocked** | testcontainers network creation |
| `GET /v{ver}/containers/{id}/json` | ❌ **Blocked** | Container inspect |
| `GET /v{ver}/containers/{id}/logs` | ❌ **Blocked** | Container logs |
| `POST /v{ver}/containers/{id}/start` | ❌ **Blocked** | Container start |
| `POST /v{ver}/containers/{id}/stop` | ❌ **Blocked** | Container stop |
| `POST /v{ver}/containers/{id}/kill` | ❌ **Blocked** | Container kill |
| `POST /v{ver}/containers/{id}/wait` | ❌ **Blocked** | Container wait |
| `DELETE /v{ver}/containers/{id}` | ❌ **Blocked** | Container removal |
| `POST /v{ver}/networks/{id}/connect` | ❌ **Blocked** | Network attach |
| `POST /v{ver}/networks/{id}/disconnect` | ❌ **Blocked** | Network detach |
| `DELETE /v{ver}/networks/{id}` | ❌ **Blocked** | Network removal |

### Root Cause

The isolator appears to use a literal path allowlist. Paths with dynamic segments (e.g., `/containers/{id}/start`) are not matched because the allowlist doesn't support wildcard patterns for container/network IDs.

Additionally, `GET /info` (without API version prefix) is blocked while `GET /v1.44/info` is allowed. The Go Docker SDK calls `/info` without version prefix when `DOCKER_API_VERSION` is not set, which causes the first failure.

## Required Endpoints for Testcontainers-Go

Testcontainers-go (v0.41.0) requires the following Docker API endpoints during a typical test run:

### Phase 1: Host Detection & Initialization

```
GET  /_ping                              # API version negotiation
GET  /info                               # Host detection (unversioned)
GET  /v{ver}/info                        # Host detection (versioned)
GET  /v{ver}/version                     # Version check
```

### Phase 2: Network Setup

```
GET  /v{ver}/networks                    # List networks (find default bridge)
POST /v{ver}/networks/create             # Create testcontainers network if needed
GET  /v{ver}/networks/{id}               # Inspect network by name/ID
```

### Phase 3: Image Management

```
GET  /v{ver}/images/json                 # Check if image exists locally
POST /v{ver}/images/create?fromImage=... # Pull image from registry
GET  /v{ver}/images/{name}/json          # Inspect image
```

### Phase 4: Container Lifecycle

```
POST   /v{ver}/containers/create          # Create container
POST   /v{ver}/containers/{id}/start      # Start container
GET    /v{ver}/containers/{id}/json       # Inspect (get ports, status)
GET    /v{ver}/containers/{id}/logs       # Stream container logs
POST   /v{ver}/containers/{id}/stop       # Stop container
POST   /v{ver}/containers/{id}/kill       # Force kill container
POST   /v{ver}/containers/{id}/wait       # Wait for container exit
DELETE /v{ver}/containers/{id}            # Remove container
```

### Phase 5: Network Attachment

```
POST /v{ver}/networks/{id}/connect       # Attach container to network
POST /v{ver}/networks/{id}/disconnect    # Detach container from network
```

### Phase 6: Cleanup (Reaper/Ryuk)

```
DELETE /v{ver}/networks/{id}             # Remove testcontainers network
GET    /v{ver}/events                    # Watch for container events (optional)
```

## Proposed Allowlist

The isolator should allow these endpoint patterns. All patterns should match with or without the `/v{version}/` prefix (e.g., both `/info` and `/v1.44/info`).

```
# Version negotiation
GET  /_ping

# System info (must work with AND without version prefix)
GET  /info
GET  /v{ver}/info
GET  /v{ver}/version

# Container operations
GET    /v{ver}/containers/json
POST   /v{ver}/containers/create
GET    /v{ver}/containers/*/json
GET    /v{ver}/containers/*/logs
POST   /v{ver}/containers/*/start
POST   /v{ver}/containers/*/stop
POST   /v{ver}/containers/*/kill
POST   /v{ver}/containers/*/wait
DELETE /v{ver}/containers/*

# Image operations
GET    /v{ver}/images/json
GET    /v{ver}/images/*/json
POST   /v{ver}/images/create    # with query params for pull

# Network operations
GET    /v{ver}/networks
GET    /v{ver}/networks/*
POST   /v{ver}/networks/create
POST   /v{ver}/networks/*/connect
POST   /v{ver}/networks/*/disconnect
DELETE /v{ver}/networks/*

# Volume operations (already allowed)
GET    /v{ver}/volumes

# Events (optional but useful for testcontainers log streaming)
GET    /v{ver}/events
```

Where:
- `{ver}` matches any API version string (e.g., `1.24`, `1.44`, `1.51`)
- `*` matches any container ID, network ID, or image name

## Implementation Suggestion

### Option A: Wildcard Pattern Matching

Replace literal path matching with glob/regex patterns:

```
# Pattern format: METHOD /path/with/wildcards
GET    /v[0-9]+\.[0-9]+/containers/[a-f0-9]+/json
POST   /v[0-9]+\.[0-9]+/containers/[a-f0-9]+/start
# etc.
```

### Option B: Prefix-Based Matching

Allow all sub-paths under approved prefixes:

```
# Allow all container operations
/v*/containers/    → allow GET, POST, DELETE
# Allow all network operations
/v*/networks/      → allow GET, POST, DELETE
# Allow all image operations
/v*/images/        → allow GET, POST
```

### Option C: Unversioned Path Support

At minimum, ensure all versioned-allowed endpoints also work without the version prefix:

```
# If GET /v1.44/info is allowed, also allow:
GET /info
```

This is critical because the Go Docker SDK uses `WithAPIVersionNegotiation()` which may call endpoints without the version prefix before negotiation completes.

## Workarounds (Current)

Without isolator changes, these workarounds partially help:

1. **`DOCKER_API_VERSION=1.44`** — Forces version prefix on all SDK calls (fixes `/info` issue but not network/container lifecycle blocks)

2. **`TESTCONTAINERS_RYUK_DISABLED=true`** — Disables the reaper container (reduces some API calls but doesn't fix core lifecycle)

3. **Skip integration tests locally** — Run only in CI where Docker is unrestricted. Current approach but limits local development.

## Verification

After updating the isolator allowlist, verify with:

```bash
# Set API version to avoid negotiation issues
export DOCKER_API_VERSION=1.44

# Run a simple testcontainer
cd /Users/Workspaces/altinity/altinity-mcp
go test -count=1 -run "TestTestConnection_Additions/success" -v ./cmd/altinity-mcp/

# Run full integration tests
go test -count=1 -v ./pkg/server/ ./cmd/altinity-mcp/
```

Expected: All tests that create ClickHouse containers should pass.
