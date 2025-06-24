# Build stage
FROM golang:latest AS builder

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o altinity-mcp ./cmd/altinity-mcp

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1001 -S altinity && \
    adduser -u 1001 -S altinity -G altinity

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/altinity-mcp .

# Change ownership to non-root user
RUN chown altinity:altinity /app/altinity-mcp

# Switch to non-root user
USER altinity

# Expose port (default for HTTP transport)
EXPOSE 8080

# Run the application
ENTRYPOINT ["./altinity-mcp"]
