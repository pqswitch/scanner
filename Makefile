# PQSwitch Scanner Makefile
.PHONY: help init build test clean lint fmt vet deps check install run docker release

# Variables
BINARY_NAME := pqswitch
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(BUILD_DATE)"

# Go related variables
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod
GOFMT := gofmt
GOVET := $(GOCMD) vet

# Directories
BUILD_DIR := build
DIST_DIR := dist
COVERAGE_DIR := coverage

# Default target
help: ## Show this help message
	@echo "PQSwitch Scanner - Post-Quantum Cryptography Migration Tool"
	@echo ""
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

init: ## Initialize development environment
	@echo "🚀 Initializing development environment..."
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "📦 Installing development tools..."
	$(GOGET) -u golang.org/x/tools/cmd/goimports
	$(GOGET) -u github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GOGET) -u github.com/goreleaser/goreleaser@latest
	@echo "✅ Development environment ready!"

deps: ## Download and verify dependencies
	@echo "📦 Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) verify
	@echo "📦 Tidying dependencies (excluding ml-training)..."
	@# Temporarily rename ml-training to avoid go mod tidy issues with old repos
	@if [ -d "ml-training" ]; then \
		echo "Temporarily excluding ml-training from go mod tidy..."; \
		mv ml-training ml-training-backup; \
	fi
	$(GOMOD) tidy
	@# Restore ml-training directory
	@if [ -d "ml-training-backup" ]; then \
		echo "Restoring ml-training directory..."; \
		mv ml-training-backup ml-training; \
	fi

build: deps ## Build the binary
	@echo "🔨 Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/pqswitch
	@echo "✅ Binary built: $(BUILD_DIR)/$(BINARY_NAME)"

build-all: deps ## Build binaries for all platforms
	@echo "🔨 Building for all platforms..."
	@mkdir -p $(DIST_DIR)
	
	# Linux
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/pqswitch
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/pqswitch
	
	# macOS
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/pqswitch
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/pqswitch
	
	# Windows
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/pqswitch
	
	@echo "✅ All binaries built in $(DIST_DIR)/"

test: ## Run tests
	@echo "🧪 Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./cmd/... ./internal/... ./pkg/... ./examples/...
	@echo "✅ Tests completed"

test-coverage: test ## Run tests with coverage report
	@echo "📊 Generating coverage report..."
	@mkdir -p $(COVERAGE_DIR)
	$(GOCMD) tool cover -html=coverage.out -o $(COVERAGE_DIR)/coverage.html
	$(GOCMD) tool cover -func=coverage.out
	@echo "📈 Coverage report: $(COVERAGE_DIR)/coverage.html"

test-integration: ## Run integration tests
	@echo "🔧 Running integration tests..."
	$(GOTEST) -v -tags=integration ./test/integration/...

test-rules: ## Test detection rules
	@echo "📋 Testing detection rules..."
	$(GOTEST) -v ./internal/scanner/ -run "TestRuleEngine"

test-crypto-rules: ## Test crypto rules with comprehensive test suite
	@echo "🔍 Testing crypto rules with comprehensive test suite..."
	@cd test/crypto_rules/runner && $(GOCMD) run test_runner.go

benchmark: ## Run benchmarks
	@echo "⚡ Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./cmd/... ./internal/... ./pkg/... ./examples/...

lint: ## Run linter on main code directories
	@echo "🔍 Running linter on main code..."
	golangci-lint run ./cmd/... ./internal/... ./pkg/... ./examples/...

lint-all: ## Run linter on all code (including tests)
	@echo "🔍 Running linter on all code..."
	golangci-lint run ./cmd/... ./internal/... ./pkg/... ./examples/... ./test/...

lint-fast: ## Run linter with fewer checks (timeout mode)
	@echo "⚡ Running fast linter..."
	golangci-lint run --timeout=2m ./cmd/... ./internal/... ./pkg/... ./examples/...

lint-fix: ## Run linter with auto-fix enabled
	@echo "🔧 Running linter with auto-fix..."
	golangci-lint run --fix ./cmd/... ./internal/... ./pkg/... ./examples/...

lint-verbose: ## Run linter with verbose output
	@echo "🔍 Running verbose linter..."
	golangci-lint run --verbose ./cmd/... ./internal/... ./pkg/... ./examples/...

fmt: ## Format code
	@echo "🎨 Formatting code..."
	$(GOFMT) -s -w .
	$(shell go env GOPATH)/bin/goimports -w .

vet: ## Run go vet
	@echo "🔍 Running go vet..."
	$(GOVET) ./cmd/... ./internal/... ./pkg/... ./examples/...

check: fmt vet lint test test-crypto-rules ## Run all checks (format, vet, lint, test, crypto rules)

clean: ## Clean build artifacts
	@echo "🧹 Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -rf $(DIST_DIR)
	rm -rf $(COVERAGE_DIR)
	rm -f coverage.out
	@echo "✅ Cleaned"

install: build ## Install binary to GOPATH/bin
	@echo "📦 Installing $(BINARY_NAME)..."
	cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/
	@echo "✅ Installed to $(GOPATH)/bin/$(BINARY_NAME)"

run: build ## Build and run the scanner
	@echo "🚀 Running $(BINARY_NAME)..."
	./$(BUILD_DIR)/$(BINARY_NAME) $(ARGS)

run-example: build ## Run scanner on example directory
	@echo "🔍 Scanning examples directory..."
	./$(BUILD_DIR)/$(BINARY_NAME) scan examples/ --output json --verbose

docker-build: ## Build Docker image
	@echo "🐳 Building Docker image..."
	docker build -t pqswitch/scanner:$(VERSION) -f build/docker/Dockerfile .
	docker tag pqswitch/scanner:$(VERSION) pqswitch/scanner:latest
	@echo "✅ Docker image built: pqswitch/scanner:$(VERSION)"

docker-run: docker-build ## Run scanner in Docker
	@echo "🐳 Running scanner in Docker..."
	docker run --rm -v $(PWD):/workspace pqswitch/scanner:$(VERSION) scan /workspace

docker-push: docker-build ## Push Docker image
	@echo "🐳 Pushing Docker image..."
	docker push pqswitch/scanner:$(VERSION)
	docker push pqswitch/scanner:latest

release-dry: ## Dry run release
	@echo "🚀 Dry run release..."
	goreleaser release --snapshot --rm-dist

release: ## Create release
	@echo "🚀 Creating release..."
	goreleaser release --rm-dist

release-local: build-all ## Create local release artifacts
	@echo "📦 Creating local release artifacts..."
	@mkdir -p $(DIST_DIR)/checksums
	
	# Generate checksums
	cd $(DIST_DIR) && sha256sum $(BINARY_NAME)-* > checksums/sha256sums.txt
	
	# Create archives
	cd $(DIST_DIR) && tar -czf $(BINARY_NAME)-linux-amd64.tar.gz $(BINARY_NAME)-linux-amd64
	cd $(DIST_DIR) && tar -czf $(BINARY_NAME)-linux-arm64.tar.gz $(BINARY_NAME)-linux-arm64
	cd $(DIST_DIR) && tar -czf $(BINARY_NAME)-darwin-amd64.tar.gz $(BINARY_NAME)-darwin-amd64
	cd $(DIST_DIR) && tar -czf $(BINARY_NAME)-darwin-arm64.tar.gz $(BINARY_NAME)-darwin-arm64
	cd $(DIST_DIR) && zip $(BINARY_NAME)-windows-amd64.zip $(BINARY_NAME)-windows-amd64.exe
	
	@echo "✅ Release artifacts created in $(DIST_DIR)/"

generate: ## Generate code (protobuf, etc.)
	@echo "🔧 Generating code..."
	$(GOCMD) generate ./...

update-deps: ## Update dependencies
	@echo "📦 Updating dependencies..."
	$(GOGET) -u ./...
	$(GOMOD) tidy

security-scan: ## Run security scan
	@echo "🔒 Running security scan..."
	gosec ./...

pre-commit: fmt vet lint test ## Run pre-commit checks
	@echo "✅ Pre-commit checks passed"

ci: fmt vet lint test test-crypto-rules test-coverage ## Run CI pipeline
	@echo "🚀 CI pipeline completed"

ci-lint: ## Run linter for CI (timeout mode)
	@echo "🔍 Running CI linter..."
	golangci-lint run --timeout=5m ./cmd/... ./internal/... ./pkg/... ./examples/...

dev-setup: init ## Setup development environment
	@echo "🛠️ Setting up development environment..."
	@if [ ! -f .env ]; then \
		echo "Creating .env file..."; \
		echo "# PQSwitch Scanner Environment" > .env; \
		echo "PQSWITCH_LOG_LEVEL=debug" >> .env; \
		echo "PQSWITCH_RULES_PATH=internal/scanner/rules" >> .env; \
	fi
	@echo "✅ Development environment setup complete"

docs-serve: ## Serve documentation locally
	@echo "📚 Serving documentation..."
	@if command -v mkdocs >/dev/null 2>&1; then \
		mkdocs serve; \
	else \
		echo "❌ mkdocs not installed. Install with: pip install mkdocs mkdocs-material"; \
	fi

version: ## Show version information
	@echo "Version: $(VERSION)"
	@echo "Commit:  $(COMMIT)"
	@echo "Date:    $(BUILD_DATE)"

# Development helpers
watch-test: ## Watch for changes and run tests
	@echo "👀 Watching for changes..."
	@if command -v fswatch >/dev/null 2>&1; then \
		fswatch -o . | xargs -n1 -I{} make test; \
	else \
		echo "❌ fswatch not installed. Install with: brew install fswatch"; \
	fi

profile: ## Run with profiling
	@echo "📊 Running with profiling..."
	./$(BUILD_DIR)/$(BINARY_NAME) scan . --cpuprofile=cpu.prof --memprofile=mem.prof

# Example targets
example-go: build ## Scan Go example
	@echo "🔍 Scanning Go example..."
	./$(BUILD_DIR)/$(BINARY_NAME) scan examples/go/ --output html --output-file go-report.html

example-java: build ## Scan Java example
	@echo "🔍 Scanning Java example..."
	./$(BUILD_DIR)/$(BINARY_NAME) scan examples/java/ --output sarif --output-file java-results.sarif

# Show build info
info:
	@echo "Build Information:"
	@echo "  Binary:     $(BINARY_NAME)"
	@echo "  Version:    $(VERSION)"
	@echo "  Commit:     $(COMMIT)"
	@echo "  Build Date: $(BUILD_DATE)"
	@echo "  Go Version: $(shell $(GOCMD) version)"
	@echo "  Platform:   $(shell $(GOCMD) env GOOS)/$(shell $(GOCMD) env GOARCH)" 