#!/bin/bash

# Enhanced Scanner Image Builder
# Builds lite, standard, and full variants of the enhanced scanner

set -e

# Configuration
DOCKER_REPO="${DOCKER_REPO:-pqswitch/scanner}"
VERSION="${VERSION:-$(date +%Y.%m.%d)-$(git rev-parse --short HEAD 2>/dev/null || echo 'local')}"
DOCKERFILE="${DOCKERFILE:-build/docker/Dockerfile.enhanced}"
PLATFORMS="${PLATFORMS:-linux/amd64,linux/arm64}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
Enhanced Scanner Image Builder

Usage: $0 [OPTIONS] [VARIANTS...]

VARIANTS:
  lite      Build lightweight crypto-only scanner (~50MB)
  standard  Build standard scanner with common tools (~200MB)
  full      Build full scanner with all tools (~500MB)
  all       Build all variants (default)

OPTIONS:
  -h, --help              Show this help message
  -v, --version VERSION   Set version tag (default: date-commit)
  -r, --repo REPO         Set Docker repository (default: $DOCKER_REPO)
  -p, --platform PLATFORMS Set target platforms (default: $PLATFORMS)
  -f, --dockerfile FILE   Set Dockerfile path (default: $DOCKERFILE)
  --push                  Push images after building
  --latest                Also tag as latest
  --dry-run               Show commands without executing

EXAMPLES:
  $0                      # Build all variants
  $0 lite standard        # Build only lite and standard
  $0 --push --latest      # Build all, push, and tag as latest
  $0 -v v1.2.3 full      # Build full variant with specific version

ENVIRONMENT VARIABLES:
  DOCKER_REPO             Docker repository name
  VERSION                 Image version tag
  DOCKERFILE              Path to Dockerfile
  PLATFORMS               Target platforms for multi-arch builds
EOF
}

# Parse command line arguments
PUSH=false
LATEST=false
DRY_RUN=false
VARIANTS=()

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -r|--repo)
            DOCKER_REPO="$2"
            shift 2
            ;;
        -p|--platform)
            PLATFORMS="$2"
            shift 2
            ;;
        -f|--dockerfile)
            DOCKERFILE="$2"
            shift 2
            ;;
        --push)
            PUSH=true
            shift
            ;;
        --latest)
            LATEST=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        lite|standard|full|all)
            VARIANTS+=("$1")
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Default to all variants if none specified
if [ ${#VARIANTS[@]} -eq 0 ]; then
    VARIANTS=("all")
fi

# Expand "all" to individual variants
if [[ " ${VARIANTS[@]} " =~ " all " ]]; then
    VARIANTS=("lite" "standard" "full")
fi

# Validate Docker is available and buildx is set up
check_requirements() {
    log_info "Checking requirements..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    if ! docker buildx version &> /dev/null; then
        log_error "Docker buildx is not available"
        exit 1
    fi
    
    if [ ! -f "$DOCKERFILE" ]; then
        log_error "Dockerfile not found: $DOCKERFILE"
        exit 1
    fi
    
    log_success "Requirements check passed"
}

# Setup buildx builder if needed
setup_buildx() {
    log_info "Setting up Docker buildx..."
    
    # Check if builder exists
    if ! docker buildx inspect enhanced-builder &> /dev/null; then
        log_info "Creating buildx builder 'enhanced-builder'..."
        if [ "$DRY_RUN" = false ]; then
            docker buildx create --name enhanced-builder --use --platform "$PLATFORMS"
        else
            echo "DRY RUN: docker buildx create --name enhanced-builder --use --platform $PLATFORMS"
        fi
    else
        log_info "Using existing buildx builder 'enhanced-builder'"
        if [ "$DRY_RUN" = false ]; then
            docker buildx use enhanced-builder
        else
            echo "DRY RUN: docker buildx use enhanced-builder"
        fi
    fi
}

# Build a single variant
build_variant() {
    local variant=$1
    local target=$variant
    
    # Special handling for lite variant (uses base target)
    if [ "$variant" = "lite" ]; then
        target="base"
    fi
    
    log_info "Building $variant variant (target: $target)..."
    
    # Construct tags
    local tags=()
    tags+=("$DOCKER_REPO:$variant-$VERSION")
    
    if [ "$LATEST" = true ]; then
        tags+=("$DOCKER_REPO:$variant")
        if [ "$variant" = "standard" ]; then
            tags+=("$DOCKER_REPO:latest")
        fi
    fi
    
    # Build tag arguments
    local tag_args=""
    for tag in "${tags[@]}"; do
        tag_args="$tag_args -t $tag"
    done
    
    # Build command
    local build_cmd="docker buildx build"
    build_cmd="$build_cmd --platform $PLATFORMS"
    build_cmd="$build_cmd --target $target"
    build_cmd="$build_cmd --build-arg VERSION=$VERSION"
    build_cmd="$build_cmd $tag_args"
    build_cmd="$build_cmd -f $DOCKERFILE"
    
    if [ "$PUSH" = true ]; then
        build_cmd="$build_cmd --push"
    else
        build_cmd="$build_cmd --load"
    fi
    
    build_cmd="$build_cmd ."
    
    # Execute or show dry run
    if [ "$DRY_RUN" = true ]; then
        echo "DRY RUN: $build_cmd"
    else
        log_info "Executing: $build_cmd"
        eval $build_cmd
        if [ $? -eq 0 ]; then
            log_success "Successfully built $variant variant"
            for tag in "${tags[@]}"; do
                log_info "  Tagged as: $tag"
            done
        else
            log_error "Failed to build $variant variant"
            return 1
        fi
    fi
}

# Calculate estimated sizes
show_size_estimates() {
    log_info "Estimated image sizes:"
    echo "  📦 lite:      ~50MB  (crypto scanning only)"
    echo "  📦 standard:  ~200MB (crypto + common dependency tools)"
    echo "  📦 full:      ~500MB (crypto + comprehensive security tools)"
    echo ""
}

# Main execution
main() {
    log_info "Enhanced Scanner Image Builder"
    log_info "Version: $VERSION"
    log_info "Repository: $DOCKER_REPO"
    log_info "Platforms: $PLATFORMS"
    log_info "Variants to build: ${VARIANTS[*]}"
    echo ""
    
    show_size_estimates
    
    if [ "$DRY_RUN" = true ]; then
        log_warning "DRY RUN MODE - Commands will be shown but not executed"
    fi
    
    check_requirements
    setup_buildx
    
    # Build each variant
    local failed_variants=()
    for variant in "${VARIANTS[@]}"; do
        if ! build_variant "$variant"; then
            failed_variants+=("$variant")
        fi
        echo ""
    done
    
    # Summary
    log_info "Build Summary:"
    local successful_variants=()
    for variant in "${VARIANTS[@]}"; do
        if [[ ! " ${failed_variants[@]} " =~ " ${variant} " ]]; then
            successful_variants+=("$variant")
            log_success "  ✅ $variant"
        fi
    done
    
    for variant in "${failed_variants[@]}"; do
        log_error "  ❌ $variant"
    done
    
    echo ""
    
    if [ ${#failed_variants[@]} -eq 0 ]; then
        log_success "All variants built successfully! 🎉"
        
        if [ "$PUSH" = true ]; then
            log_info "Images pushed to registry:"
        else
            log_info "Images available locally:"
        fi
        
        for variant in "${successful_variants[@]}"; do
            echo "  🐳 $DOCKER_REPO:$variant-$VERSION"
            if [ "$LATEST" = true ]; then
                echo "  🐳 $DOCKER_REPO:$variant"
            fi
        done
        
        if [ "$LATEST" = true ] && [[ " ${successful_variants[@]} " =~ " standard " ]]; then
            echo "  🐳 $DOCKER_REPO:latest"
        fi
        
        echo ""
        log_info "Usage examples:"
        echo "  # Lite scanner (crypto only)"
        echo "  docker run --rm -v \$(pwd):/workspace $DOCKER_REPO:lite-$VERSION enhanced-scan ."
        echo ""
        echo "  # Standard scanner (crypto + dependencies)"
        echo "  docker run --rm -v \$(pwd):/workspace $DOCKER_REPO:standard-$VERSION enhanced-scan --include-deps ."
        echo ""
        echo "  # Full scanner (comprehensive)"
        echo "  docker run --rm -v \$(pwd):/workspace $DOCKER_REPO:full-$VERSION enhanced-scan --include-deps --external-tools ."
        
    else
        log_error "Some variants failed to build"
        exit 1
    fi
}

# Run main function
main 