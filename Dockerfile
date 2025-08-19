# Final stage
FROM alpine:latest

# Install ca-certificates and curl for HTTPS requests and debug
RUN apk --no-cache add ca-certificates curl bash

# Set working directory
WORKDIR /bin/

# Copy the pre-built binaries
COPY altinity-mcp .
COPY jwe-token-generator .
COPY docker/entrypoint.sh /docker/entrypoint.sh

# Make entrypoint script executable
RUN chmod +x /docker/entrypoint.sh

# Set entrypoint
ENTRYPOINT ["/docker/entrypoint.sh"]

# Expose port (default for HTTP transport)
EXPOSE 8080
