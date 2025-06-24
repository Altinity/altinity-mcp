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
RUN CGO_ENABLED=0 GOOS=linux go build -o altinity-mcp ./cmd/altinity-mcp

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
