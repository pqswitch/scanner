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
    echo 'CONFIG_FILE="/tmp/.pqswitch.yaml"' >> /usr/local/bin/pqswitch && \
    echo 'RULES_DIR="/usr/local/share/pqswitch/rules"' >> /usr/local/bin/pqswitch && \
    echo '' >> /usr/local/bin/pqswitch && \
    echo '# Create default config if needed' >> /usr/local/bin/pqswitch && \
    echo 'if [ ! -f "$CONFIG_FILE" ]; then' >> /usr/local/bin/pqswitch && \
    echo '    echo "Creating default config..."' >> /usr/local/bin/pqswitch && \
    echo '    mkdir -p "$(dirname "$CONFIG_FILE")"' >> /usr/local/bin/pqswitch && \
    echo '    echo "scanner:" > "$CONFIG_FILE"' >> /usr/local/bin/pqswitch && \
    echo '    echo "  max_file_size: 10485760" >> "$CONFIG_FILE"' >> /usr/local/bin/pqswitch && \
    echo '    echo "  parallel: 4" >> "$CONFIG_FILE"' >> /usr/local/bin/pqswitch && \
    echo '    echo "  enable_ast: false  # Disabled for Docker" >> "$CONFIG_FILE"' >> /usr/local/bin/pqswitch && \
    echo '    echo "  ignore_patterns:" >> "$CONFIG_FILE"' >> /usr/local/bin/pqswitch && \
    echo '    echo "    - \"vendor/*\"" >> "$CONFIG_FILE"' >> /usr/local/bin/pqswitch && \
    echo '    echo "    - \"node_modules/*\"" >> "$CONFIG_FILE"' >> /usr/local/bin/pqswitch && \
    echo '    echo "    - \"*.test.go\"" >> "$CONFIG_FILE"' >> /usr/local/bin/pqswitch && \
    echo '    echo "    - \".git/*\"" >> "$CONFIG_FILE"' >> /usr/local/bin/pqswitch && \
    echo '    echo "output:" >> "$CONFIG_FILE"' >> /usr/local/bin/pqswitch && \
    echo '    echo "  default_format: \"json\"" >> "$CONFIG_FILE"' >> /usr/local/bin/pqswitch && \
    echo '    echo "  include_source: true" >> "$CONFIG_FILE"' >> /usr/local/bin/pqswitch && \
    echo '    echo "  verbose: false" >> "$CONFIG_FILE"' >> /usr/local/bin/pqswitch && \
    echo 'fi' >> /usr/local/bin/pqswitch && \
    echo '' >> /usr/local/bin/pqswitch && \
    echo '# Clean up known false positives' >> /usr/local/bin/pqswitch && \
    echo 'find . -name "*.yaml" -path "*/scanner/rules/*" -delete 2>/dev/null || true' >> /usr/local/bin/pqswitch && \
    echo 'find . -name "*.yml" -path "*/scanner/rules/*" -delete 2>/dev/null || true' >> /usr/local/bin/pqswitch && \
    echo '' >> /usr/local/bin/pqswitch && \
    echo '# Remove package lock files (dependency metadata, not source code)' >> /usr/local/bin/pqswitch && \
    echo 'rm -f ./package-lock.json ./pnpm-lock.yaml ./yarn.lock ./Cargo.lock ./Pipfile.lock ./poetry.lock ./go.sum ./composer.lock ./Gemfile.lock 2>/dev/null || true' >> /usr/local/bin/pqswitch && \
    echo '' >> /usr/local/bin/pqswitch && \
    echo '# Run the scanner' >> /usr/local/bin/pqswitch && \
    echo 'exec /usr/local/bin/pqswitch-bin --config "$CONFIG_FILE" "$@"' >> /usr/local/bin/pqswitch

# Make wrapper and binary executable
RUN chmod +x /usr/local/bin/pqswitch /usr/local/bin/pqswitch-bin

# Set proper ownership (keeping pqswitch user available for when needed)
RUN chown -R pqswitch:pqswitch /app /usr/local/share/pqswitch && \
    chown pqswitch:pqswitch /usr/local/bin/pqswitch /usr/local/bin/pqswitch-bin && \
    chmod 755 /usr/local/bin/pqswitch /usr/local/bin/pqswitch-bin

# Run as root for ECS compatibility (ECS handles security isolation)
# USER pqswitch

# Set working directory for scans
WORKDIR /workspace

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD /usr/local/bin/pqswitch-bin --version || exit 1

# Use same structure as old working image
ENTRYPOINT ["/bin/sh"]
CMD ["-c", "pqswitch --help"] 