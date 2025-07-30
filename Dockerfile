# Build stage
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

# Build arguments
ARG TARGETOS
ARG TARGETARCH
ARG VERSION
ARG COMMIT
ARG DATE

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /src

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /app/altinity-mcp ./cmd/altinity-mcp

# Final stage
FROM alpine:latest

# Install ca-certificates and curl for HTTPS requests and debug
RUN apk --no-cache add ca-certificates curl

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/altinity-mcp .

# Expose port (default for HTTP transport)
EXPOSE 8080

# Run the application
ENTRYPOINT ["./altinity-mcp"]
