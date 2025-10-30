# Multi-platform Dockerfile for kernel-delay
# Supports both ARM64 and x86 architectures

# Use a minimal base image
FROM alpine:latest

# Install required runtime dependencies
RUN apk add --no-cache \
    libelf \
    libpcap

# Create non-root user
RUN addgroup -S -g 1001 appgroup &&\
    adduser -S -u 1001 -G appgroup appuser

# Copy the pre-built binary
COPY target/release/kernel-delay /usr/local/bin/kernel-delay

# Change ownership
RUN chown appuser:appgroup /usr/local/bin/kernel-delay

# Switch to non-root user
USER appuser

# Set entrypoint
ENTRYPOINT ["/usr/local/bin/kernel-delay"]