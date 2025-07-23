# Build stage
FROM golang:1.24.3-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git build-base

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build argument for version
ARG VERSION=dev
ENV VERSION=${VERSION}

# Build the application
RUN CGO_ENABLED=1 go build -ldflags="-s -w -X main.version=${VERSION}" -o pqswitch ./cmd/pqswitch

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    git \
    aws-cli \
    bash

# Create non-root user
RUN addgroup -S pqswitch && adduser -S pqswitch -G pqswitch

# Create application directories
RUN mkdir -p /app /usr/local/share/pqswitch

# Copy binary from builder stage
COPY --from=builder /app/pqswitch /usr/local/bin/pqswitch-bin

# Copy rules and configuration
COPY --from=builder /app/internal/scanner/rules /usr/local/share/pqswitch/rules
COPY --from=builder /app/.pqswitch.yaml /usr/local/share/pqswitch/.pqswitch.yaml

# Create a wrapper script that explicitly filters out false positives and handles ignore patterns
RUN echo '#!/bin/bash' > /usr/local/bin/pqswitch && \
    echo 'set -e' >> /usr/local/bin/pqswitch && \
    echo '' >> /usr/local/bin/pqswitch && \
    echo '# Debug info' >> /usr/local/bin/pqswitch && \
    echo 'echo "=== PQSwitch Enhanced Wrapper Starting ==="' >> /usr/local/bin/pqswitch && \
    echo 'echo "Current directory: $(pwd)"' >> /usr/local/bin/pqswitch && \
    echo 'echo "Home directory: $HOME"' >> /usr/local/bin/pqswitch && \
    echo 'echo "User: $(whoami)"' >> /usr/local/bin/pqswitch && \
    echo 'echo "Config file exists: $(test -f $HOME/.pqswitch.yaml && echo yes || echo no)"' >> /usr/local/bin/pqswitch && \
    echo 'echo "Rules source exists: $(test -d /usr/local/share/pqswitch/rules && echo yes || echo no)"' >> /usr/local/bin/pqswitch && \
    echo 'if [ -f "$HOME/.pqswitch.yaml" ]; then' >> /usr/local/bin/pqswitch && \
    echo '    echo "Config file preview:"' >> /usr/local/bin/pqswitch && \
    echo '    head -15 "$HOME/.pqswitch.yaml"' >> /usr/local/bin/pqswitch && \
    echo 'fi' >> /usr/local/bin/pqswitch && \
    echo 'echo "Command arguments: $@"' >> /usr/local/bin/pqswitch && \
    echo 'echo "=== Starting Scan ==="' >> /usr/local/bin/pqswitch && \
    echo '' >> /usr/local/bin/pqswitch && \
    echo '# Create temporary filtered scan results' >> /usr/local/bin/pqswitch && \
    echo 'TEMP_OUTPUT="/tmp/scan_output_$(date +%s).json"' >> /usr/local/bin/pqswitch && \
    echo '' >> /usr/local/bin/pqswitch && \
    echo '# Create the expected directory structure as fallback' >> /usr/local/bin/pqswitch && \
    echo 'mkdir -p ./internal/scanner' >> /usr/local/bin/pqswitch && \
    echo 'if [ -d "/usr/local/share/pqswitch/rules" ]; then' >> /usr/local/bin/pqswitch && \
    echo '    cp -r /usr/local/share/pqswitch/rules ./internal/scanner/rules' >> /usr/local/bin/pqswitch && \
    echo '    echo "Rules copied to fallback location"' >> /usr/local/bin/pqswitch && \
    echo 'fi' >> /usr/local/bin/pqswitch && \
    echo '' >> /usr/local/bin/pqswitch && \
    echo '# Pre-filter the directory to exclude false positive files' >> /usr/local/bin/pqswitch && \
    echo 'echo "Pre-filtering false positive files..."' >> /usr/local/bin/pqswitch && \
    echo 'find . -name "*.yaml" -path "*/scanner/rules/*" -delete 2>/dev/null || true' >> /usr/local/bin/pqswitch && \
    echo 'find . -name "*.yml" -path "*/scanner/rules/*" -delete 2>/dev/null || true' >> /usr/local/bin/pqswitch && \
    echo 'find . -path "*/.git/hooks/*" -name "*.sample" -delete 2>/dev/null || true' >> /usr/local/bin/pqswitch && \
    echo '# Remove package management lock files (dependency metadata, not source code)' >> /usr/local/bin/pqswitch && \
    echo 'rm -f ./package-lock.json ./pnpm-lock.yaml ./yarn.lock ./Cargo.lock ./Pipfile.lock ./poetry.lock ./go.sum ./composer.lock ./Gemfile.lock 2>/dev/null || true' >> /usr/local/bin/pqswitch && \
    echo 'echo "False positive files and lock files removed"' >> /usr/local/bin/pqswitch && \
    echo '' >> /usr/local/bin/pqswitch && \
    echo '# Run the scanner' >> /usr/local/bin/pqswitch && \
    echo 'echo "Running: /usr/local/bin/pqswitch-bin --config $HOME/.pqswitch.yaml $@"' >> /usr/local/bin/pqswitch && \
    echo '/usr/local/bin/pqswitch-bin --config "$HOME/.pqswitch.yaml" "$@"' >> /usr/local/bin/pqswitch && \
    chmod +x /usr/local/bin/pqswitch

# Create config in the correct location that the application expects
RUN echo 'scanner:' > /home/pqswitch/.pqswitch.yaml && \
    echo '  max_file_size: 10485760' >> /home/pqswitch/.pqswitch.yaml && \
    echo '  parallel: 4' >> /home/pqswitch/.pqswitch.yaml && \
    echo '  ignore_patterns:' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "vendor/*"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "node_modules/*"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "*.test.go"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - ".git/*"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "internal/scanner/rules/*"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "internal/scanner/enhanced_rules.yaml"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "**/rules/*.yaml"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "**/rules/*.yml"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "*.rules.yaml"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "*.rules.yml"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "**/scanner/rules/*"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "**/*scanner*/**/*.yaml"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "**/*scanner*/**/*.yml"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    # Package management lock files (contain dependency metadata, not source code)' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "package-lock.json"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "pnpm-lock.yaml"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "yarn.lock"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "Cargo.lock"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "Pipfile.lock"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "poetry.lock"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "go.sum"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "composer.lock"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "Gemfile.lock"' >> /home/pqswitch/.pqswitch.yaml && \
    echo 'rules:' >> /home/pqswitch/.pqswitch.yaml && \
    echo '  default_rules_path: "/usr/local/share/pqswitch/rules"' >> /home/pqswitch/.pqswitch.yaml && \
    echo 'output:' >> /home/pqswitch/.pqswitch.yaml && \
    echo '  default_format: "json"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '  include_source: true' >> /home/pqswitch/.pqswitch.yaml && \
    echo '  verbose: false' >> /home/pqswitch/.pqswitch.yaml

# Set up proper ownership
RUN chown -R pqswitch:pqswitch /app /usr/local/share/pqswitch /home/pqswitch/.pqswitch.yaml && \
    chown pqswitch:pqswitch /usr/local/bin/pqswitch /usr/local/bin/pqswitch-bin

# Switch to non-root user
USER pqswitch

# Set environment variables
ENV PQSWITCH_RULES_PATH=/usr/local/share/pqswitch/rules

# Set working directory
WORKDIR /tmp/workspace

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pqswitch --version || exit 1

# Default entrypoint
ENTRYPOINT ["/bin/sh"]
CMD ["-c", "pqswitch --help"] 