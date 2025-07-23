#!/usr/bin/env bash
# systematic_scan_parallel.sh - Run systematic scans on all cloned repositories
# Optimized for ML training data collection with sophisticated detection strategy
# Usage: bash systematic_scan_parallel.sh

set -euo pipefail

SCANNER_PATH="../pqswitch"
REPOS_DIR="./repos"
RESULTS_DIR="./results"
MAX_PARALLEL=4
SCAN_TIMEOUT=1800  # 30 minutes timeout for large repositories

# ML Training Configuration
MIN_CONFIDENCE=0.3      # Capture lower confidence findings for ML training
TOP_FINDINGS=1000       # Sufficient findings for training data
ENABLE_BENCHMARKS=true  # Collect performance metrics for analysis

# Create results directory
mkdir -p "$RESULTS_DIR"

# Function to run command with timeout (Mac-compatible)
run_with_timeout() {
    local timeout_duration="$1"
    shift
    
    # Run command in background
    "$@" &
    local cmd_pid=$!
    
    # Start timeout in background
    (
        sleep "$timeout_duration"
        if kill -0 "$cmd_pid" 2>/dev/null; then
            echo "⏰ Timeout reached, killing process $cmd_pid"
            kill "$cmd_pid" 2>/dev/null
        fi
    ) &
    local timeout_pid=$!
    
    # Wait for command to complete
    if wait "$cmd_pid" 2>/dev/null; then
        # Command completed successfully, kill timeout
        kill "$timeout_pid" 2>/dev/null || true
        return 0
    else
        # Command failed or was killed
        kill "$timeout_pid" 2>/dev/null || true
        return 1
    fi
}

# Function to scan a single repository with ML-optimized settings
scan_repo() {
    local repo_name="$1"
    local repo_path="$2"
    local output_file="$3"
    
    # Calculate dynamic timeout based on repository size
    local repo_size_mb=$(du -sm "$repo_path" 2>/dev/null | cut -f1)
    local dynamic_timeout=$SCAN_TIMEOUT
    
    # Increase timeout for large repositories
    if [[ "$repo_size_mb" -gt 1000 ]]; then
        dynamic_timeout=$((SCAN_TIMEOUT * 2))  # 60 minutes for repos > 1GB
        echo "🔍 Scanning $repo_name (${repo_size_mb}MB - large repo, extended timeout: $((dynamic_timeout / 60)) min)..."
    elif [[ "$repo_size_mb" -gt 500 ]]; then
        dynamic_timeout=$((SCAN_TIMEOUT + 600))  # 40 minutes for repos > 500MB
        echo "🔍 Scanning $repo_name (${repo_size_mb}MB - medium repo, timeout: $((dynamic_timeout / 60)) min)..."
    else
        echo "🔍 Scanning $repo_name (${repo_size_mb}MB - standard timeout: $((dynamic_timeout / 60)) min)..."
    fi
    
    if [[ ! -d "$repo_path" ]]; then
        echo "⚠️  Repository $repo_name not found at $repo_path"
        return 1
    fi
    
    # Build scanner arguments for ML training
    local scan_args=(
        "$SCANNER_PATH" scan "$repo_path"
        --output json
        --output-file "$output_file"
        --enable-l1                    # AST-based analysis (sophisticated detection)
        --min-confidence "$MIN_CONFIDENCE"  # Capture lower confidence findings
        --top-findings "$TOP_FINDINGS"      # Sufficient data for training
        --verbose                           # Detailed output for analysis
    )
    
    # Add benchmarking if enabled
    if [[ "$ENABLE_BENCHMARKS" == "true" ]]; then
        scan_args+=(--show-benchmark)
    fi
    
    # Run scan with dynamic timeout
    if run_with_timeout "$dynamic_timeout" "${scan_args[@]}" 2>&1; then
        if [[ -f "$output_file" ]]; then
            echo "✅ Completed scan for $repo_name ($(wc -l < "$output_file" 2>/dev/null || echo "0") lines)"
            return 0
        else
            echo "⚠️  Scan completed but no output file created for $repo_name"
            return 1
        fi
    else
        echo "⚠️  Scan failed or timed out for $repo_name (${repo_size_mb}MB after $((dynamic_timeout / 60)) min)"
        # Check if it's a scanner issue
        if [[ ! -f "$SCANNER_PATH" ]]; then
            echo "❌ Scanner not found at $SCANNER_PATH"
        elif [[ ! -x "$SCANNER_PATH" ]]; then
            echo "❌ Scanner not executable at $SCANNER_PATH"
        fi
        return 1
    fi
}

# Get list of repositories
if [[ ! -d "$REPOS_DIR" ]]; then
    echo "❌ Repositories directory not found. Run clone_repos.sh first."
    exit 1
fi

# Find all repositories
repos=()
while IFS= read -r -d '' repo_path; do
    if [[ -d "$repo_path/.git" ]]; then
        repo_name=$(basename "$repo_path")
        repos+=("$repo_name:$repo_path")
    fi
done < <(find "$REPOS_DIR" -maxdepth 1 -type d -print0)

echo "📊 Found ${#repos[@]} repositories to scan"
echo "🧠 ML Training Configuration:"
echo "   - Min Confidence: $MIN_CONFIDENCE (captures lower confidence findings)"
echo "   - AST Analysis: Enabled (L1 sophisticated detection)"
echo "   - Max Findings: $TOP_FINDINGS per repository"
echo "   - Benchmarks: $ENABLE_BENCHMARKS"
echo "   - Parallel Jobs: $MAX_PARALLEL"
echo "   - Timeout: $SCAN_TIMEOUT seconds ($(($SCAN_TIMEOUT / 60)) minutes)"

# Check if scanner exists
if [[ ! -f "$SCANNER_PATH" ]]; then
    echo "❌ Scanner not found at $SCANNER_PATH. Run 'make build' first."
    exit 1
fi

# Process repositories in parallel
pids=()
scan_count=0
success_count=0
skipped_count=0

for repo_info in "${repos[@]}"; do
    repo_name="${repo_info%:*}"
    repo_path="${repo_info#*:}"
    output_file="$RESULTS_DIR/${repo_name}_scan_results.json"
    
    # Skip if already scanned
    if [[ -f "$output_file" ]]; then
        echo "⏭️  Skipping $repo_name (already scanned)"
        ((skipped_count++))
        continue
    fi
    
    # Limit parallel processes
    while [[ ${#pids[@]} -ge $MAX_PARALLEL ]]; do
        # Check which processes have finished
        new_pids=()
        if [[ ${#pids[@]} -gt 0 ]]; then
            for pid in "${pids[@]}"; do
                if kill -0 "$pid" 2>/dev/null; then
                    new_pids+=("$pid")
                fi
            done
        fi
        pids=("${new_pids[@]}")
        
        # If we still have too many processes, wait a bit
        if [[ ${#pids[@]} -ge $MAX_PARALLEL ]]; then
            sleep 1
        fi
    done
    
    # Start scan in background
    scan_repo "$repo_name" "$repo_path" "$output_file" &
    pids+=($!)
    ((scan_count++))
    
    # Progress update
    if (( scan_count % 10 == 0 )); then
        echo "📈 Progress: $scan_count/${#repos[@]} repositories queued"
    fi
done

# Wait for all background processes
echo "⏳ Waiting for all scans to complete..."
if [[ ${#pids[@]} -gt 0 ]]; then
    for pid in "${pids[@]}"; do
        if wait "$pid"; then
            ((success_count++))
        fi
    done
fi

echo "✅ All scans completed!"
echo "📊 Scan Statistics:"
echo "   - Total repositories: ${#repos[@]}"
echo "   - Previously scanned: $skipped_count"
echo "   - Newly queued: $scan_count"
echo "   - Successfully completed: $success_count"
echo "   - Failed scans: $((scan_count - success_count))"
echo "📁 Results saved in $RESULTS_DIR/"

# Generate comprehensive analysis for ML training
echo "📊 Generating ML training analysis..."
if ls "$RESULTS_DIR"/*_scan_results.json >/dev/null 2>&1; then
    echo "🧠 Creating ML training dataset summary..."
    python3 analyze_results.py "$RESULTS_DIR"/*_scan_results.json "ml_training_dataset.json"
    
    # Count total findings for ML training
    total_findings=$(find "$RESULTS_DIR" -name "*_scan_results.json" -exec jq '.crypto_findings | length' {} \; 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
    echo "🎯 ML Training Dataset Ready:"
    echo "   - Total findings: $total_findings"
    echo "   - Confidence range: $MIN_CONFIDENCE - 1.0"
    echo "   - Detection method: AST-based (L1) analysis"
    echo "   - Ready for AI-in-loop or human validation"
    
    # Create combined scan results for AI evaluation
    echo "🔗 Creating combined scan results for AI evaluation..."
    python3 -c "
import json
import glob
import os

# Get all scan result files
result_files = glob.glob('$RESULTS_DIR/*_scan_results.json')
print(f'📄 Found {len(result_files)} scan result files')

# Combine all findings
all_findings = []
successful_files = 0
total_repos = 0

for file in result_files:
    total_repos += 1
    try:
        with open(file, 'r') as f:
            data = json.load(f)
            repo_name = os.path.basename(file).replace('_scan_results.json', '')
            
            if isinstance(data, dict) and 'crypto_findings' in data:
                findings = data['crypto_findings']
                if findings:  # Only count non-empty findings
                    all_findings.extend(findings)
                    successful_files += 1
                    if len(findings) >= 100:  # Highlight repos with many findings
                        print(f'  🔥 {repo_name}: {len(findings)} findings')
                    elif len(findings) >= 10:
                        print(f'  📊 {repo_name}: {len(findings)} findings')
            elif isinstance(data, list):
                all_findings.extend(data)
                successful_files += 1
    except Exception as e:
        print(f'  ⚠️  Error reading {os.path.basename(file)}: {e}')

print(f'📈 Combined Results Summary:')
print(f'  - Total repositories processed: {total_repos}')
print(f'  - Repositories with findings: {successful_files}')
print(f'  - Total findings collected: {len(all_findings)}')

# Save combined results to project root for easy access
combined_file = '../combined_scan_results.json'
with open(combined_file, 'w') as f:
    json.dump(all_findings, f, indent=2)

print(f'✅ Combined results saved to: {combined_file}')
print(f'🚀 Ready for AI evaluation with: ./build/pqswitch ai-evaluate combined_scan_results.json')
"
else
    echo "⚠️  No scan results found to analyze"
fi 