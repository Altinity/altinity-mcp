# Final stage
FROM alpine:latest

# Install ca-certificates and curl for HTTPS requests and debug
RUN apk --no-cache add ca-certificates curl

# Set working directory
WORKDIR /app

# Copy the pre-built binary
COPY altinity-mcp .

# Expose port (default for HTTP transport)
EXPOSE 8080

# Run the application
ENTRYPOINT ["./altinity-mcp"]
