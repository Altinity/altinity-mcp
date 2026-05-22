#!/usr/bin/env bash
# build-synthetic-idp-image.sh — build & push the synthetic-idp stress-test
# image. Same shape as scripts/build-ch-jwt-verify-image.sh.
#
# Usage:
#   scripts/build-synthetic-idp-image.sh [tag-prefix]
#     tag-prefix defaults to "synthetic-idp". Final tag:
#     <tag-prefix>-<short-sha>, e.g. synthetic-idp-fbdd04c.
#
# Defaults to arm64 only (the otel demo cluster's only arch). Override
# with ARCHES="amd64 arm64" if you need both.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="${REPO:-$(cd "$SCRIPT_DIR/.." && pwd)}"
REGISTRY="${REGISTRY:-ghcr.io}"
IMAGE="${IMAGE:-altinity/synthetic-idp}"
ARCHES="${ARCHES:-arm64}"
TAG_PREFIX="${1:-synthetic-idp}"

if [[ ! -f "$REPO/Dockerfile.synthetic-idp" ]]; then
    echo "Dockerfile.synthetic-idp not found at $REPO" >&2
    exit 1
fi

cd "$REPO"

SHA=$(git rev-parse --short=7 HEAD)
TAG="${TAG_PREFIX}-${SHA}"
FULL="${REGISTRY}/${IMAGE}"

cleanup() { rm -f "$REPO/synthetic-idp"; }
trap cleanup EXIT

build_one() {
    local arch=$1
    echo
    echo "==> $arch"

    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
        -ldflags="-s -w -X main.version=${TAG}" \
        -o synthetic-idp ./cmd/synthetic-idp

    docker pull --platform "linux/$arch" alpine:latest >/dev/null

    DOCKER_BUILDKIT=0 docker build --platform "linux/$arch" \
        -t "${FULL}:${TAG}-${arch}" -f Dockerfile.synthetic-idp . >/dev/null

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
