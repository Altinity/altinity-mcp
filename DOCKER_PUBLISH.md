# Docker Image Publishing Guide - Issue #35

The Docker image for the Issue #35 implementation (unified tools configuration + dynamic write tools) is ready to build and publish.

## Current State

✅ **Code**: Issue #35 implementation committed to `tools` branch
✅ **Binaries**: `altinity-mcp` and `jwe-token-generator` built and ready
✅ **Dockerfile**: Existing Alpine-based build is compatible
✅ **CI/CD**: GitHub Actions workflow ready to build and publish
✅ **Kubernetes**: Deployment manifests created in `k8s/deployment.yaml`

## Publishing Options

### Option 1: GitHub Actions (Automated) ⭐ RECOMMENDED

**Easiest and most reliable way to build multi-platform images.**

```bash
# Create a release tag to trigger the build workflow
git tag v0.1.0-issue35
git push origin v0.1.0-issue35

# The GitHub Actions workflow will automatically:
# 1. Run tests (go vet, go test)
# 2. Build binaries for amd64 and arm64
# 3. Build Docker images for both platforms
# 4. Create multi-platform manifest
# 5. Publish to ghcr.io
# 6. Create GitHub Release with binaries
```

**What gets published:**
- `ghcr.io/altinity/altinity-mcp:0.1.0` (version tag)
- `ghcr.io/altinity/altinity-mcp:latest` (latest stable)
- Both amd64 and arm64 platform images
- Helm chart (if applicable)

**Time**: ~5-10 minutes
**Requires**: GitHub repository access (already have it)

### Option 2: Manual Docker Build (Local)

**For local testing before publishing:**

```bash
# 1. Build binaries locally
./scripts/build-docker.sh build issue35

# 2. Build Docker image (amd64 only, without buildx)
docker build -t altinity-mcp:issue35 .

# 3. Test locally
docker run --rm altinity-mcp:issue35 --help

# 4. Test with ClickHouse
docker-compose up -d
docker run --rm \
  -e CLICKHOUSE_HOST=host.docker.internal \
  -e CLICKHOUSE_PORT=9000 \
  altinity-mcp:issue35 \
  --help
```

**Note**: This builds for local architecture only (amd64 on Intel/M1). To publish multi-platform, use buildx or GitHub Actions.

### Option 3: Manual Docker Buildx (Advanced)

**For building multi-platform images locally:**

```bash
# 1. Ensure docker buildx is available
docker buildx version

# 2. Create builder (if needed)
docker buildx create --use --name altinity-builder

# 3. Build and optionally push
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag ghcr.io/altinity/altinity-mcp:issue35 \
  --tag ghcr.io/altinity/altinity-mcp:latest \
  --push \
  .

# Note: Add --push to publish directly to registry
```

**Requires**:
- `docker buildx` installed
- GitHub credentials: `GITHUB_TOKEN` and `GITHUB_ACTOR` environment variables
- Proper authentication to ghcr.io

## Next Steps

### Step 1: Test Locally (Optional)

```bash
# Build and run locally
./scripts/build-docker.sh build issue35
docker build -t altinity-mcp:test .
docker run --rm altinity-mcp:test --help
```

### Step 2: Publish

**Recommended**: Use GitHub Actions

```bash
git tag v0.1.0-issue35
git push origin v0.1.0-issue35

# Then monitor the workflow:
# https://github.com/Altinity/altinity-mcp/actions/workflows/build-altinity-mcp.yml
```

### Step 3: Verify Publication

```bash
# Pull the published image
docker pull ghcr.io/altinity/altinity-mcp:issue35

# Run it
docker run --rm \
  -e CLICKHOUSE_HOST=localhost \
  -e CLICKHOUSE_PORT=9000 \
  ghcr.io/altinity/altinity-mcp:issue35 \
  --help
```

### Step 4: Deploy to Kubernetes

```bash
# Apply the deployment
kubectl apply -f k8s/deployment.yaml

# Monitor deployment
kubectl get deployment altinity-mcp
kubectl logs -l app=altinity-mcp
```

## Docker Image Details

**Registry**: `ghcr.io` (GitHub Container Registry)
**Image**: `ghcr.io/altinity/altinity-mcp`
**Tags**: 
- `issue35` - Current testing version
- `latest` - Latest release
- `v0.1.0` - Semantic version (from git tags)

**Size**: ~15-20 MB (Alpine base)

**Included**:
- `altinity-mcp` - Main MCP server
- `jwe-token-generator` - Token generation utility
- `ca-certificates`, `curl`, `bash` - Base tools

**Architecture**: Multi-platform (amd64, arm64)

## Files Changed

```
scripts/
  └── build-docker.sh          # Build automation script
k8s/
  └── deployment.yaml          # Kubernetes manifests
docs/
  └── DOCKER_BUILD_GUIDE.md   # Detailed Docker guide
.github/workflows/
  └── build-altinity-mcp.yml  # CI/CD workflow (existing)
```

## Verification Checklist

- [ ] Code committed to `tools` branch
- [ ] Binaries build successfully: `go build ./cmd/altinity-mcp`
- [ ] Tests pass: `go test ./...`
- [ ] Docker image builds: `docker build -t test:latest .`
- [ ] GitHub Actions workflow configured (already exists)
- [ ] Kubernetes manifests reviewed and ready
- [ ] Ready to publish to ghcr.io

## Troubleshooting

### Docker Build Fails

```bash
# Check prerequisites
go version           # Ensure Go is installed
docker --version    # Ensure Docker is available
docker buildx version  # For multi-platform builds

# Rebuild binaries explicitly
rm -f altinity-mcp jwe-token-generator
go build -o altinity-mcp ./cmd/altinity-mcp
go build -o jwe-token-generator ./cmd/jwe_auth

# Try building
docker build -t test:latest .
```

### GitHub Actions Workflow Issues

```bash
# Check workflow syntax
gh workflow list
gh workflow view build-altinity-mcp.yml

# View run logs
gh run list --workflow build-altinity-mcp.yml
gh run view <run-id> --log
```

### Image Push Fails

```bash
# Verify GitHub token
echo $GITHUB_TOKEN | docker login ghcr.io -u $GITHUB_ACTOR --password-stdin

# Ensure image name is lowercase
IMAGE_NAME=$(echo "ghcr.io/Altinity/altinity-mcp" | tr '[:upper:]' '[:lower:]')
echo $IMAGE_NAME

# Try push again
docker push $IMAGE_NAME:issue35
```

## References

- **Build Script**: `scripts/build-docker.sh`
- **Docker Guide**: `docs/DOCKER_BUILD_GUIDE.md`
- **GitHub Actions Workflow**: `.github/workflows/build-altinity-mcp.yml`
- **Kubernetes Manifests**: `k8s/deployment.yaml`

## Summary

The Docker infrastructure for Issue #35 is complete and ready. Choose one of these options:

1. **Easiest (Recommended)**: Use GitHub Actions
   ```bash
   git tag v0.1.0-issue35 && git push origin v0.1.0-issue35
   ```

2. **For Testing**: Build locally
   ```bash
   ./scripts/build-docker.sh docker issue35
   ```

3. **For Multi-Platform**: Use buildx
   ```bash
   docker buildx build --platform linux/amd64,linux/arm64 --push -t ghcr.io/altinity/altinity-mcp:issue35 .
   ```

All scripts and manifests are in place. Ready to build and publish! 🚀
