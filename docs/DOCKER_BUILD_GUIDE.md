# Docker Build and Publish Guide - Issue #35

This guide covers building and publishing the Altinity MCP Docker image with the Issue #35 implementation (unified tools configuration + dynamic write tools).

## Overview

- **Image Registry**: GitHub Container Registry (ghcr.io)
- **Image Name**: `ghcr.io/altinity/altinity-mcp`
- **Platforms**: linux/amd64, linux/arm64
- **Base Image**: Alpine Linux (minimal footprint)
- **Included Binaries**:
  - `altinity-mcp` - Main MCP server
  - `jwe-token-generator` - Token generation utility

## Quick Start

### Option 1: Using GitHub Actions (Recommended)

The project has an automated CI/CD pipeline that builds and publishes images:

```bash
# Create a release tag to trigger the workflow
git tag v0.1.0-issue35
git push origin v0.1.0-issue35

# The workflow will:
# 1. Build binaries for amd64 and arm64
# 2. Build Docker images for both platforms
# 3. Create a multi-platform manifest
# 4. Publish to ghcr.io
```

**GitHub Actions Workflow**: `.github/workflows/build-altinity-mcp.yml`

### Option 2: Manual Build (Local)

#### Prerequisites

```bash
# Install Docker buildx for multi-platform builds
docker buildx version  # Should show buildx is available

# For ghcr.io, set GitHub credentials
export GITHUB_ACTOR=<your-github-username>
export GITHUB_TOKEN=<your-github-token>
```

#### Build Binaries

```bash
# Build Go binaries for all platforms
./scripts/build-docker.sh build issue35

# Output:
# build/linux/amd64/altinity-mcp
# build/linux/amd64/jwe-token-generator
# build/linux/arm64/altinity-mcp
# build/linux/arm64/jwe-token-generator
```

#### Build Docker Image

```bash
# Build image with buildx (multi-platform)
./scripts/build-docker.sh docker issue35 ghcr.io

# Or manually with docker buildx:
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag ghcr.io/altinity/altinity-mcp:issue35 \
  --tag ghcr.io/altinity/altinity-mcp:latest \
  --push \
  .
```

#### Publish to Registry

```bash
# With authentication
export GITHUB_TOKEN=<token>
export GITHUB_ACTOR=<username>

# Publish image
./scripts/build-docker.sh publish issue35 ghcr.io

# Or manually:
echo $GITHUB_TOKEN | docker login ghcr.io -u $GITHUB_ACTOR --password-stdin
docker push ghcr.io/altinity/altinity-mcp:issue35
docker push ghcr.io/altinity/altinity-mcp:latest
```

### Option 3: Using Docker Compose (Local Testing)

```bash
# Start with docker-compose for local testing
docker-compose up -d

# Test the server
docker exec altinity-mcp altinity-mcp --help
```

## Docker Image Contents

### Filesystem Layout

```
/bin/altinity-mcp              # Main MCP server binary
/bin/jwe-token-generator       # Token generation utility
/docker/entrypoint.sh          # Container entrypoint
/etc/ca-certificates/          # SSL certificates (from Alpine)
```

### Dockerfile Stages

```dockerfile
# Single-stage Alpine build
FROM alpine:latest
RUN apk --no-cache add ca-certificates curl bash
WORKDIR /bin/
COPY altinity-mcp .
COPY jwe-token-generator .
COPY docker/entrypoint.sh /docker/entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/docker/entrypoint.sh"]
```

### Entrypoint Behavior

The entrypoint script (`docker/entrypoint.sh`):
1. If no arguments provided → runs `altinity-mcp` with default config
2. If arguments provided → executes them (allows custom commands)

Examples:
```bash
# Run with default config
docker run ghcr.io/altinity/altinity-mcp:issue35

# Run with custom config
docker run -v config.yaml:/etc/altinity-mcp/config.yaml \
  ghcr.io/altinity/altinity-mcp:issue35 \
  --config /etc/altinity-mcp/config.yaml

# Run with debug logging
docker run ghcr.io/altinity/altinity-mcp:issue35 \
  --log-level debug
```

## Testing the Image

### Local Testing

```bash
# Build locally (amd64 only)
docker build -t altinity-mcp:test .

# Run container
docker run --rm \
  -e CLICKHOUSE_HOST=localhost \
  -e CLICKHOUSE_PORT=9000 \
  altinity-mcp:test \
  --help

# Or with interactive shell
docker run -it --rm altinity-mcp:test /bin/bash
```

### Registry Testing

```bash
# Pull from registry
docker pull ghcr.io/altinity/altinity-mcp:issue35

# Run from registry
docker run --rm ghcr.io/altinity/altinity-mcp:issue35 \
  --version
```

### Kubernetes Testing

```bash
# Apply deployment (ensure ClickHouse is running in cluster)
kubectl apply -f k8s/deployment.yaml

# Check deployment status
kubectl get deployment altinity-mcp
kubectl get pods -l app=altinity-mcp

# View logs
kubectl logs -l app=altinity-mcp
kubectl logs -l app=altinity-mcp --follow

# Port forward for testing
kubectl port-forward svc/altinity-mcp 8080:8080

# Test the service
curl -X POST http://localhost:8080/tools/execute_query \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT 1"}'
```

## Image Tags and Versioning

### Semantic Versioning

```bash
# Release version (from git tags)
v0.1.0          # Full semantic version
```

### Branch-based Tags

```bash
# Current implementation
issue35         # Testing tag for Issue #35
latest          # Latest release
```

### Commit-based Tags

GitHub Actions workflow generates:
```bash
# Short commit SHA
sha-a1b2c3d

# Platform-specific
amd64-a1b2c3d
arm64-a1b2c3d
```

## GitHub Container Registry (ghcr.io)

### Authentication

```bash
# Login with GitHub token
export CR_PAT=<your-token>
echo $CR_PAT | docker login ghcr.io -u <username> --password-stdin

# Or with GitHub CLI
gh auth login
```

### Permissions

Ensure your GitHub token has these scopes:
- `packages:write` - Push/publish packages
- `packages:read` - Pull packages
- `contents:read` - Read repository contents

### Access Control

Image visibility (can be set in GitHub repo settings):
- **Public**: Anyone can pull without authentication
- **Private**: Authentication required for pull

## CI/CD Pipeline

### GitHub Actions Workflow

File: `.github/workflows/build-altinity-mcp.yml`

Triggers:
- Push to `main` or `master` branches
- Push of version tags (`v*.*.*`)
- Manual workflow dispatch

Steps:
1. **Test Phase** - Run `go test`, `go vet`, coverage reporting
2. **Build Phase** - Build binaries for amd64 and arm64
3. **Docker Build & Push** - Build Docker images per platform
4. **Manifest** - Create multi-platform Docker manifest
5. **Release** - Create GitHub release with binaries and packages

### Local Equivalent

```bash
# 1. Run tests
go test -v ./...

# 2. Build binaries
./scripts/build-docker.sh build issue35

# 3. Build Docker
./scripts/build-docker.sh docker issue35

# 4. Push to registry
./scripts/build-docker.sh publish issue35 ghcr.io
```

## Configuration in Container

### Using ConfigMap (Kubernetes)

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: altinity-mcp-config
data:
  config.yaml: |
    logging:
      level: info
    clickhouse:
      host: clickhouse
      port: 9000
    server:
      transport: stdio
      tools:
        - type: "read"
          name: "execute_query"
        - type: "write"
          regexp: "^.*_table$"
          prefix: "insert_"
          mode: "insert"
```

### Using Environment Variables

```bash
docker run -e CLICKHOUSE_HOST=localhost \
           -e CLICKHOUSE_PORT=9000 \
           ghcr.io/altinity/altinity-mcp:issue35
```

### Using Volume Mount

```bash
docker run -v /path/to/config.yaml:/etc/altinity-mcp/config.yaml \
  ghcr.io/altinity/altinity-mcp:issue35 \
  --config /etc/altinity-mcp/config.yaml
```

## Troubleshooting

### Image Build Failures

```bash
# Check Docker buildx status
docker buildx ls

# Create new builder if needed
docker buildx create --use --name altinity-builder

# Build with debug output
docker buildx build --progress=plain \
  --platform linux/amd64 \
  -f Dockerfile -t test:latest .
```

### Registry Push Failures

```bash
# Verify authentication
docker login ghcr.io

# Check image name format (must be lowercase)
IMAGE_NAME=$(echo "ghcr.io/Altinity/altinity-mcp" | tr '[:upper:]' '[:lower:]')
echo $IMAGE_NAME

# Push with explicit retry
docker push --retry 3 $IMAGE_NAME:issue35
```

### Container Runtime Issues

```bash
# Check container logs
docker logs <container-id>

# Run with extended logging
docker run -e LOG_LEVEL=debug ghcr.io/altinity/altinity-mcp:issue35

# Test binary directly
docker run -it ghcr.io/altinity/altinity-mcp:issue35 \
  /bin/bash
```

## Security Considerations

### Image Security

- Alpine base: minimal attack surface
- Non-root capable: configure runAsNonRoot
- Read-only filesystem: recommended for production
- No unnecessary packages: curl, bash added for debugging (consider removing)

### Example Secure Kubernetes Config

```yaml
securityContext:
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 1000
  allowPrivilegeEscalation: false
  capabilities:
    drop:
    - ALL
```

## Next Steps

1. **Immediate**: Verify image builds successfully
   ```bash
   ./scripts/build-docker.sh docker issue35
   ```

2. **Test in ClickHouse**: Deploy to local cluster
   ```bash
   docker-compose up
   ```

3. **Publish**: Push to ghcr.io when ready
   ```bash
   ./scripts/build-docker.sh publish issue35 ghcr.io
   ```

4. **Kubernetes**: Deploy with provided manifests
   ```bash
   kubectl apply -f k8s/deployment.yaml
   ```

## References

- [Dockerfile Best Practices](https://docs.docker.com/develop/dev-best-practices/dockerfile_best-practices/)
- [Docker buildx Documentation](https://docs.docker.com/build/)
- [GitHub Container Registry Docs](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
