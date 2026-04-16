# Trigger Docker Build - Issue #35

## Status

✅ **Commits Fixed**: All Issue #35 commits now have correct author (Boris Tyshkevich <btyshkevich@altinity.com>)
✅ **Tag Created**: `v0.1.0-issue35` (local, needs to be pushed)
⏳ **Action Required**: Push tag to GitHub to trigger CI/CD pipeline

## Commits Fixed

```
f6d95f3 Add Docker publishing guide for Issue #35
cc72bee Add Docker build infrastructure and Kubernetes deployment manifests for Issue #35
1ff86a2 Implement Issue #35: Unified tools config with dynamic write tools (Phases 1-5)
0eb5af1 docs: Add comprehensive MCP tool design documentation
```

**Author**: Boris Tyshkevich <btyshkevich@altinity.com> ✓

## Next Step: Push Tag to Trigger Build

Run this command in your terminal:

```bash
cd /Users/Workspaces/altinity/altinity-mcp
git push origin v0.1.0-issue35
```

Or use the GitHub CLI:

```bash
gh release create v0.1.0-issue35 --generate-notes \
  --title "Altinity MCP Issue #35: Unified Tools & Dynamic Write Tools" \
  --notes "
  ## Features
  - Unified tools configuration (static + dynamic in single array)
  - Dynamic write tool discovery from ClickHouse tables
  - Intelligent column filtering (excludes alias/materialized/virtual)
  - INSERT query generation with parameter validation
  - Full backwards compatibility with old dynamic_tools config
  - Docker image for multi-platform deployment (amd64, arm64)
  
  ## What's Included
  - Complete implementation of Phases 1-5
  - Kubernetes deployment manifests
  - Docker build infrastructure
  - Comprehensive documentation
  "
```

## What Happens After Push

The GitHub Actions workflow (`.github/workflows/build-altinity-mcp.yml`) will automatically:

1. ✅ Run all tests
2. ✅ Build binaries for amd64 and arm64
3. ✅ Build Docker images for both platforms
4. ✅ Create multi-platform Docker manifest
5. ✅ Publish to ghcr.io
6. ✅ Create GitHub Release with artifacts

**Estimated Time**: 5-10 minutes

**Registry**: `ghcr.io/altinity/altinity-mcp:0.1.0-issue35`

## Current Tag Status

```
Tag: v0.1.0-issue35
Commit: f6d95f3e874671881c2d94f033a120ec472e9d3d
Branch: tools
Author: Boris Tyshkevich <btyshkevich@altinity.com>
```

## Verify Tag Locally

```bash
git tag -l v0.1.0-issue35
git log --oneline -1 v0.1.0-issue35
```

## Monitor Build Progress

After pushing the tag:

1. Go to: https://github.com/Altinity/altinity-mcp/actions
2. Find workflow: "Build Altinity MCP"
3. Click on the run with tag "v0.1.0-issue35"
4. Monitor the steps

## After Build Completes

### Pull the Docker Image

```bash
docker pull ghcr.io/altinity/altinity-mcp:0.1.0-issue35
```

### Deploy to Kubernetes

```bash
kubectl apply -f k8s/deployment.yaml
```

### Test the Image

```bash
docker run --rm ghcr.io/altinity/altinity-mcp:0.1.0-issue35 --help
```

---

**Ready?** Push the tag when you're ready:

```bash
! git push origin v0.1.0-issue35
```

(The `!` prefix runs the command in this session)
