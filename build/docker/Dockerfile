# GoReleaser Dockerfile - uses pre-built binary
FROM alpine:latest

# Install only essential runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    git \
    bash \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -S pqswitch && adduser -S pqswitch -G pqswitch

# Create application directories
RUN mkdir -p /app /usr/local/share/pqswitch

# Copy the pre-built binary from GoReleaser
COPY pqswitch /usr/local/bin/pqswitch-bin

# Create rules directory (empty for now, will be populated by app)
RUN mkdir -p /usr/local/share/pqswitch/rules

# Create optimized wrapper script
RUN echo '#!/bin/bash' > /usr/local/bin/pqswitch && \
    echo 'set -e' >> /usr/local/bin/pqswitch && \
    echo '' >> /usr/local/bin/pqswitch && \
    echo '# Configuration' >> /usr/local/bin/pqswitch && \
    echo 'CONFIG_FILE="$HOME/.pqswitch.yaml"' >> /usr/local/bin/pqswitch && \
    echo 'RULES_DIR="/usr/local/share/pqswitch/rules"' >> /usr/local/bin/pqswitch && \
    echo '' >> /usr/local/bin/pqswitch && \
    echo '# Create default config if needed' >> /usr/local/bin/pqswitch && \
    echo 'if [ ! -f "$CONFIG_FILE" ]; then' >> /usr/local/bin/pqswitch && \
    echo '    echo "Creating default config..."' >> /usr/local/bin/pqswitch && \
    echo '    mkdir -p "$(dirname "$CONFIG_FILE")"' >> /usr/local/bin/pqswitch && \
    echo '    cat > "$CONFIG_FILE" << EOF' >> /usr/local/bin/pqswitch && \
    echo 'scanner:' >> /usr/local/bin/pqswitch && \
    echo '  max_file_size: 10485760' >> /usr/local/bin/pqswitch && \
    echo '  parallel: 4' >> /usr/local/bin/pqswitch && \
    echo '  enable_ast: false  # Disabled for Docker' >> /usr/local/bin/pqswitch && \
    echo '  ignore_patterns:' >> /usr/local/bin/pqswitch && \
    echo '    - "vendor/*"' >> /usr/local/bin/pqswitch && \
    echo '    - "node_modules/*"' >> /usr/local/bin/pqswitch && \
    echo '    - "*.test.go"' >> /usr/local/bin/pqswitch && \
    echo '    - ".git/*"' >> /usr/local/bin/pqswitch && \
    echo 'output:' >> /usr/local/bin/pqswitch && \
    echo '  default_format: "json"' >> /usr/local/bin/pqswitch && \
    echo '  include_source: true' >> /usr/local/bin/pqswitch && \
    echo '  verbose: false' >> /usr/local/bin/pqswitch && \
    echo 'EOF' >> /usr/local/bin/pqswitch && \
    echo 'fi' >> /usr/local/bin/pqswitch && \
    echo '' >> /usr/local/bin/pqswitch && \
    echo '# Clean up known false positives' >> /usr/local/bin/pqswitch && \
    echo 'find . -name "*.yaml" -path "*/scanner/rules/*" -delete 2>/dev/null || true' >> /usr/local/bin/pqswitch && \
    echo 'find . -name "*.yml" -path "*/scanner/rules/*" -delete 2>/dev/null || true' >> /usr/local/bin/pqswitch && \
    echo '' >> /usr/local/bin/pqswitch && \
    echo '# Remove package lock files (dependency metadata, not source code)' >> /usr/local/bin/pqswitch && \
    echo 'rm -f ./package-lock.json ./pnpm-lock.yaml ./yarn.lock ./Cargo.lock \\' >> /usr/local/bin/pqswitch && \
    echo '      ./Pipfile.lock ./poetry.lock ./go.sum ./composer.lock ./Gemfile.lock 2>/dev/null || true' >> /usr/local/bin/pqswitch && \
    echo '' >> /usr/local/bin/pqswitch && \
    echo '# Run the scanner' >> /usr/local/bin/pqswitch && \
    echo 'exec /usr/local/bin/pqswitch-bin --config "$CONFIG_FILE" "$@"' >> /usr/local/bin/pqswitch

# Make wrapper and binary executable
RUN chmod +x /usr/local/bin/pqswitch /usr/local/bin/pqswitch-bin

# Set proper ownership
RUN chown -R pqswitch:pqswitch /app /usr/local/share/pqswitch && \
    chown pqswitch:pqswitch /usr/local/bin/pqswitch /usr/local/bin/pqswitch-bin

# Switch to non-root user
USER pqswitch

# Set working directory for scans
WORKDIR /tmp/workspace

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /usr/local/bin/pqswitch-bin --version || exit 1

# Default command
CMD ["/usr/local/bin/pqswitch", "--help"] 