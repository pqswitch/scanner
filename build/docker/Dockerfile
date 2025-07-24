# Build stage
FROM golang:1.24.3-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git build-base

# Set working directory
WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./

# Download dependencies (cached layer)
RUN go mod download

# Copy source code
COPY . .

# Build argument for version
ARG VERSION=dev
ENV VERSION=${VERSION}

# Build argument for target architecture
ARG TARGETARCH
ARG TARGETOS

# Conditionally enable CGO based on architecture
# Use CGO for native builds, disable for cross-compilation to avoid hanging
RUN if [ "$TARGETARCH" = "amd64" ] && [ "$TARGETOS" = "linux" ]; then \
        echo "Building with CGO enabled for native linux/amd64"; \
        CGO_ENABLED=1 go build -ldflags="-s -w -X main.version=${VERSION}" -o pqswitch ./cmd/pqswitch; \
    else \
        echo "Building with CGO disabled for cross-compilation ($TARGETOS/$TARGETARCH)"; \
        CGO_ENABLED=0 go build -tags nocgo -ldflags="-s -w -X main.version=${VERSION}" -o pqswitch ./cmd/pqswitch; \
    fi

# Final stage - minimal runtime image
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

# Copy binary from builder stage
COPY --from=builder /app/pqswitch /usr/local/bin/pqswitch-bin

# Copy rules and configuration
COPY --from=builder /app/internal/scanner/rules /usr/local/share/pqswitch/rules
COPY --from=builder /app/.pqswitch.yaml /usr/local/share/pqswitch/.pqswitch.yaml

# Create optimized wrapper script
RUN echo '#!/bin/bash' > /usr/local/bin/pqswitch && \
    echo 'set -e' >> /usr/local/bin/pqswitch && \
    echo '' >> /usr/local/bin/pqswitch && \
    echo '# Configuration' >> /usr/local/bin/pqswitch && \
    echo 'CONFIG_FILE="$HOME/.pqswitch.yaml"' >> /usr/local/bin/pqswitch && \
    echo 'RULES_DIR="/usr/local/share/pqswitch/rules"' >> /usr/local/bin/pqswitch && \
    echo '' >> /usr/local/bin/pqswitch && \
    echo '# Ensure config exists' >> /usr/local/bin/pqswitch && \
    echo 'if [ ! -f "$CONFIG_FILE" ]; then' >> /usr/local/bin/pqswitch && \
    echo '    cp /usr/local/share/pqswitch/.pqswitch.yaml "$CONFIG_FILE"' >> /usr/local/bin/pqswitch && \
    echo 'fi' >> /usr/local/bin/pqswitch && \
    echo '' >> /usr/local/bin/pqswitch && \
    echo '# Create rules fallback if needed' >> /usr/local/bin/pqswitch && \
    echo 'if [ ! -d "./internal/scanner/rules" ] && [ -d "$RULES_DIR" ]; then' >> /usr/local/bin/pqswitch && \
    echo '    mkdir -p ./internal/scanner' >> /usr/local/bin/pqswitch && \
    echo '    cp -r "$RULES_DIR" ./internal/scanner/rules' >> /usr/local/bin/pqswitch && \
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

# Make wrapper executable
RUN chmod +x /usr/local/bin/pqswitch

# Create runtime configuration
RUN echo 'scanner:' > /home/pqswitch/.pqswitch.yaml && \
    echo '  max_file_size: 10485760' >> /home/pqswitch/.pqswitch.yaml && \
    echo '  parallel: 4' >> /home/pqswitch/.pqswitch.yaml && \
    echo '  enable_ast: false  # Disabled for Docker to avoid tree-sitter issues' >> /home/pqswitch/.pqswitch.yaml && \
    echo '  ignore_patterns:' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "vendor/*"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "node_modules/*"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "*.test.go"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - ".git/*"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "internal/scanner/rules/*"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "**/rules/*.yaml"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "**/rules/*.yml"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "package-lock.json"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "pnpm-lock.yaml"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "yarn.lock"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "Cargo.lock"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "Pipfile.lock"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "poetry.lock"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "go.sum"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "composer.lock"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '    - "Gemfile.lock"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '' >> /home/pqswitch/.pqswitch.yaml && \
    echo 'rules:' >> /home/pqswitch/.pqswitch.yaml && \
    echo '  default_rules_path: "/usr/local/share/pqswitch/rules"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '' >> /home/pqswitch/.pqswitch.yaml && \
    echo 'output:' >> /home/pqswitch/.pqswitch.yaml && \
    echo '  default_format: "json"' >> /home/pqswitch/.pqswitch.yaml && \
    echo '  include_source: true' >> /home/pqswitch/.pqswitch.yaml && \
    echo '  verbose: false' >> /home/pqswitch/.pqswitch.yaml

# Set proper ownership
RUN chown -R pqswitch:pqswitch /app /usr/local/share/pqswitch /home/pqswitch/.pqswitch.yaml && \
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