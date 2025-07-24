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
RUN cat << 'EOF' > /usr/local/bin/pqswitch
#!/bin/bash
set -e

# Configuration
CONFIG_FILE="$HOME/.pqswitch.yaml"
RULES_DIR="/usr/local/share/pqswitch/rules"

# Ensure config exists
if [ ! -f "$CONFIG_FILE" ]; then
    cp /usr/local/share/pqswitch/.pqswitch.yaml "$CONFIG_FILE"
fi

# Create rules fallback if needed
if [ ! -d "./internal/scanner/rules" ] && [ -d "$RULES_DIR" ]; then
    mkdir -p ./internal/scanner
    cp -r "$RULES_DIR" ./internal/scanner/rules
fi

# Clean up known false positives
find . -name "*.yaml" -path "*/scanner/rules/*" -delete 2>/dev/null || true
find . -name "*.yml" -path "*/scanner/rules/*" -delete 2>/dev/null || true

# Remove package lock files (dependency metadata, not source code)
rm -f ./package-lock.json ./pnpm-lock.yaml ./yarn.lock ./Cargo.lock \
      ./Pipfile.lock ./poetry.lock ./go.sum ./composer.lock ./Gemfile.lock 2>/dev/null || true

# Run the scanner
exec /usr/local/bin/pqswitch-bin --config "$CONFIG_FILE" "$@"
EOF

# Make wrapper executable
RUN chmod +x /usr/local/bin/pqswitch

# Create runtime configuration
RUN cat << 'EOF' > /home/pqswitch/.pqswitch.yaml
scanner:
  max_file_size: 10485760
  parallel: 4
  enable_ast: false  # Disabled for Docker to avoid tree-sitter issues
  ignore_patterns:
    - "vendor/*"
    - "node_modules/*"
    - "*.test.go"
    - ".git/*"
    - "internal/scanner/rules/*"
    - "**/rules/*.yaml"
    - "**/rules/*.yml"
    - "package-lock.json"
    - "pnpm-lock.yaml"
    - "yarn.lock"
    - "Cargo.lock"
    - "Pipfile.lock"
    - "poetry.lock"
    - "go.sum"
    - "composer.lock"
    - "Gemfile.lock"

rules:
  default_rules_path: "/usr/local/share/pqswitch/rules"

output:
  default_format: "json"
  include_source: true
  verbose: false
EOF

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