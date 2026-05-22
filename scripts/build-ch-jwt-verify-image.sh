#!/usr/bin/env bash
# build-ch-jwt-verify-image.sh — build & push the ch-jwt-verify sidecar
# image. Same shape as scripts/build-mcp-image.sh: cross-compile a static
# Go binary per arch, legacy `docker build`, then `docker manifest` for the
# multi-arch tag.
#
# Usage:
#   scripts/build-ch-jwt-verify-image.sh [tag-prefix]
#     tag-prefix defaults to "sidecar". Final tag: <tag-prefix>-<short-sha>,
#     e.g. sidecar-49ecb42. Per-arch tags get -amd64 / -arm64 suffix.
#
# Env overrides:
#   REPO, REGISTRY, IMAGE, ARCHES (see build-mcp-image.sh for semantics)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/.." && pwd)}"
REGISTRY="${REGISTRY:-ghcr.io}"
IMAGE="${IMAGE:-altinity/ch-jwt-verify}"
ARCHES="${ARCHES:-amd64 arm64}"
TAG_PREFIX="${1:-sidecar}"

if [[ ! -f "$REPO/Dockerfile.ch-jwt-verify" ]]; then
    echo "Dockerfile.ch-jwt-verify not found at $REPO — REPO does not look like an altinity-mcp checkout" >&2
    exit 1
fi

cd "$REPO"

SHA=$(git rev-parse --short=7 HEAD)
COMMIT=$(git rev-parse HEAD)
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
TAG="${TAG_PREFIX}-${SHA}"
FULL="${REGISTRY}/${IMAGE}"

cleanup() { rm -f "$REPO/ch-jwt-verify"; }
trap cleanup EXIT

build_one() {
    local arch=$1
    echo
    echo "==> $arch"

    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
        -ldflags="-s -w -X main.version=${TAG}" \
        -o ch-jwt-verify ./cmd/ch-jwt-verify

    docker pull --platform "linux/$arch" alpine:latest >/dev/null

    DOCKER_BUILDKIT=0 docker build --platform "linux/$arch" \
        -t "${FULL}:${TAG}-${arch}" -f Dockerfile.ch-jwt-verify . >/dev/null

    local got
    got=$(docker image inspect "${FULL}:${TAG}-${arch}" --format '{{.Architecture}}')
    if [[ "$got" != "$arch" ]]; then
        echo "ARCH MISMATCH for ${TAG}-${arch}: image says ${got}" >&2
        exit 1
    fi

    docker push "${FULL}:${TAG}-${arch}"
}

set -- $ARCHES
for arch in "$@"; do
    build_one "$arch"
done

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
