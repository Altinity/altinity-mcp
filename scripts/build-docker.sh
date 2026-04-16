#!/bin/bash
set -e

# Build and publish Docker image for altinity-mcp
# Usage: ./scripts/build-docker.sh [version] [registry] [platforms]

VERSION="${1:-issue35}"
REGISTRY="${2:-ghcr.io}"
PLATFORMS="${3:-linux/amd64,linux/arm64}"
IMAGE_NAME="${REGISTRY}/altinity/altinity-mcp"
IMAGE_NAME_LOWER=$(echo "${IMAGE_NAME}" | tr '[:upper:]' '[:lower:]')

echo "Building Docker image for altinity-mcp"
echo "Version: ${VERSION}"
echo "Registry: ${IMAGE_NAME_LOWER}"
echo "Platforms: ${PLATFORMS}"
echo ""

# Build binaries for all platforms
build_binaries() {
    local platforms_array=("${PLATFORMS//,/ }")

    for platform in "${platforms_array[@]}"; do
        local os_arch="${platform//\//}"
        local GOOS="${os_arch%"${os_arch##*[!0-9]}"}"
        local GOARCH="${os_arch##*[!0-9]}"

        # Handle platform format conversions
        case "$platform" in
            "linux/amd64") GOOS="linux"; GOARCH="amd64" ;;
            "linux/arm64") GOOS="linux"; GOARCH="arm64" ;;
        esac

        echo "[*] Building for ${platform} (${GOOS}/${GOARCH})"

        mkdir -p "build/${platform}"

        CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" go build \
            -ldflags "-X main.version=${VERSION} -X main.commit=$(git rev-parse --short HEAD) -X main.date=$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
            -o "build/${platform}/altinity-mcp" ./cmd/altinity-mcp

        CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" go build \
            -ldflags "-X main.version=${VERSION} -X main.commit=$(git rev-parse --short HEAD) -X main.date=$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
            -o "build/${platform}/jwe-token-generator" ./cmd/jwe_auth
    done
}

# Build with docker buildx
build_with_buildx() {
    # Ensure buildx builder exists
    if ! docker buildx ls | grep -q "^.*linux"; then
        echo "[*] Creating buildx builder for multi-platform builds"
        docker buildx create --use --name altinity-builder
    fi

    echo "[*] Building multi-platform image with docker buildx"
    docker buildx build \
        --platform "${PLATFORMS}" \
        --tag "${IMAGE_NAME_LOWER}:${VERSION}" \
        --tag "${IMAGE_NAME_LOWER}:latest" \
        --load \
        .
}

# Publish image
publish() {
    echo "[*] Logging into ${REGISTRY}"

    # For ghcr.io, use GitHub credentials
    if [[ "${REGISTRY}" == "ghcr.io" ]]; then
        if [[ -z "${GITHUB_TOKEN}" ]]; then
            echo "ERROR: GITHUB_TOKEN not set. Required for ghcr.io authentication."
            echo "Set: export GITHUB_TOKEN=<your-github-token>"
            return 1
        fi
        echo "${GITHUB_TOKEN}" | docker login ghcr.io -u "${GITHUB_ACTOR}" --password-stdin
    fi

    echo "[*] Pushing image to registry"
    docker push "${IMAGE_NAME_LOWER}:${VERSION}"
    docker push "${IMAGE_NAME_LOWER}:latest"

    echo "[*] Image published successfully!"
    echo "    ${IMAGE_NAME_LOWER}:${VERSION}"
    echo "    ${IMAGE_NAME_LOWER}:latest"
}

# Main
case "${1:-build}" in
    "build")
        build_binaries
        echo "[✓] Binaries built successfully"
        ;;
    "docker")
        build_binaries
        build_with_buildx
        echo "[✓] Docker image built successfully"
        ;;
    "publish")
        build_binaries
        build_with_buildx
        publish
        echo "[✓] Docker image published successfully"
        ;;
    *)
        echo "Usage: $0 [build|docker|publish] [version] [registry] [platforms]"
        echo ""
        echo "Examples:"
        echo "  $0 build issue35"
        echo "  $0 docker issue35 ghcr.io"
        echo "  $0 publish issue35 ghcr.io linux/amd64,linux/arm64"
        exit 1
        ;;
esac
