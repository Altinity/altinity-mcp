# Final stage
FROM debian:stable-slim

# Install ca-certificates, curl and bash for HTTPS requests and debugging
RUN apt-get update && apt-get install -y ca-certificates curl bash && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /bin/

# Copy the pre-built binaries
COPY altinity-mcp .
COPY jwe-token-generator .

# Expose port (default for HTTP transport)
EXPOSE 8080

# No default entrypoint; the binary to run can be specified at container start
