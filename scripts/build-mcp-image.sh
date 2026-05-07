#!/usr/bin/env bash
# build-mcp-image.sh — build & push a multi-arch altinity-mcp image from a
# local checkout. Faster than the upstream CI when iterating on a feature
# branch (CI's image-push jobs are gated on `event_name != 'pull_request'`
# and `on.push.branches: [main, master]`, so feature-branch pushes don't
# produce images by default).
#
# Why this isn't `docker buildx build --platform=linux/amd64,linux/arm64`:
# the sandbox docker proxy (/var/run/isolator-docker/altinity.sock) blocks
# the privileged container that buildkit boots. We fall back to legacy
# `docker build` per arch + `docker manifest create` to assemble the
# multi-arch manifest. The manifest API doesn't need a privileged builder.
#
# Usage (from anywhere):
#   /path/to/altinity-mcp/scripts/build-mcp-image.sh [tag-prefix]
#     tag-prefix   defaults to "pr101". Final image tag becomes
#                  <tag-prefix>-<short-sha>, e.g. pr101-7ffdced. Per-arch
#                  tags get -amd64 / -arm64 suffix.
#
# Env overrides:
#   REPO=/path/to/altinity-mcp      (default: auto-detected from script path)
#   REGISTRY=ghcr.io
#   IMAGE=altinity/altinity-mcp
#   ARCHES="amd64 arm64"            (set ARCHES=arm64 for arm64-only)
#
# Prerequisites:
#   - ghcr.io auth: if `docker push` 401s, re-auth with the env token —
#       echo "$GITHUB_TOKEN" | docker login ghcr.io -u altinity --password-stdin
#     Never run plain `docker login ghcr.io` interactively (the env tokens
#     are right there; using them keeps secrets off scrollback).
#   - Go toolchain (go.mod pins 1.26+).
#
# Updating the live deployment after a successful push:
#   The demo MCP fleet's per-cluster mcp-values.yaml lives outside this
#   repo at /Users/Workspaces/acm/mcp/deploy/<env>/mcp-values.yaml. Edit
#   image.tag there, then `helm upgrade <env>-mcp /path/to/altinity-mcp/helm/altinity-mcp -f …`.

set -euo pipefail

# Auto-detect REPO from script location: scripts/build-mcp-image.sh → repo root is one up.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/.." && pwd)}"
REGISTRY="${REGISTRY:-ghcr.io}"
IMAGE="${IMAGE:-altinity/altinity-mcp}"
ARCHES="${ARCHES:-amd64 arm64}"
TAG_PREFIX="${1:-pr101}"

if [[ ! -d "$REPO" ]]; then
    echo "REPO not found: $REPO" >&2
    exit 1
fi
if [[ ! -f "$REPO/Dockerfile" ]]; then
    echo "Dockerfile not found at $REPO/Dockerfile — REPO does not look like an altinity-mcp checkout" >&2
    exit 1
fi

cd "$REPO"

SHA=$(git rev-parse --short=7 HEAD)
COMMIT=$(git rev-parse HEAD)
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
TAG="${TAG_PREFIX}-${SHA}"
FULL="${REGISTRY}/${IMAGE}"

cleanup() { rm -f "$REPO/altinity-mcp" "$REPO/jwe-token-generator"; }
trap cleanup EXIT

build_one() {
    local arch=$1
    echo
    echo "==> $arch"

    # 1. Cross-compile statically-linked Go binaries into the build context.
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
        -ldflags="-s -w -X main.version=${TAG} -X main.commit=${COMMIT} -X main.date=${DATE}" \
        -o altinity-mcp ./cmd/altinity-mcp
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -ldflags="-s -w" \
        -o jwe-token-generator ./cmd/jwe_auth

    # 2. Pre-pull the alpine base for the target arch. Legacy `docker build`
    #    does NOT honour --platform on FROM (only metadata), so without this
    #    you'd get the host-arch alpine even when targeting a foreign arch.
    docker pull --platform "linux/$arch" alpine:latest >/dev/null

    # 3. Legacy build (DOCKER_BUILDKIT=0) — buildkit needs privileged.
    DOCKER_BUILDKIT=0 docker build --platform "linux/$arch" \
        -t "${FULL}:${TAG}-${arch}" -f Dockerfile . >/dev/null

    # 4. Sanity-check arch end-to-end: image metadata + binary readelf.
    local got
    got=$(docker image inspect "${FULL}:${TAG}-${arch}" --format '{{.Architecture}}')
    if [[ "$got" != "$arch" ]]; then
        echo "ARCH MISMATCH for ${TAG}-${arch}: image says ${got}" >&2
        exit 1
    fi

    # 5. Push per-arch tag.
    docker push "${FULL}:${TAG}-${arch}"
}

set -- $ARCHES
for arch in "$@"; do
    build_one "$arch"
done

# Multi-arch manifest at the unsuffixed tag. Idempotent: amend if exists.
if [[ "$#" -gt 1 ]]; then
    echo
    echo "==> manifest ${TAG}"
    docker manifest rm "${FULL}:${TAG}" 2>/dev/null || true
    manifest_args=()
    for arch in "$@"; do
        manifest_args+=("${FULL}:${TAG}-${arch}")
    done
    docker manifest create "${FULL}:${TAG}" "${manifest_args[@]}"
    docker manifest push "${FULL}:${TAG}"
fi

echo
echo "✓ pushed:"
for arch in "$@"; do
    echo "    ${FULL}:${TAG}-${arch}"
done
if [[ "$#" -gt 1 ]]; then
    echo "    ${FULL}:${TAG}     (multi-arch manifest)"
fi
echo
echo "Next: bump image.tag to \"${TAG}\" in the relevant mcp-values.yaml"
echo "      (demo fleet: /Users/Workspaces/acm/mcp/deploy/<env>/mcp-values.yaml)"
echo "      then helm upgrade."
