#!/usr/bin/env bash
# monitor_ai_evaluation.sh - Monitor AI evaluation progress with real-time updates
# Usage: bash monitor_ai_evaluation.sh <scan-results.json> [additional-flags]

set -euo pipefail

# Configuration
SCAN_FILE="${1:-combined_scan_results_fixed.json}"
OUTPUT_DIR="${2:-ai_evaluation_monitored}"
PROGRESS_FILE="$OUTPUT_DIR/progress.log"
BATCH_SIZE=20  # Optimized for speed
MIN_CONFIDENCE=0.3

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to estimate total work
estimate_work() {
    local scan_file="$1"
    local min_conf="$2"
    
    echo "🔍 Analyzing scan file to estimate work..."
    
    # Get total findings
    local total_findings=$(jq '.findings | length' "$scan_file")
    
    # Estimate filtered findings (rough approximation)
    local estimated_filtered=$((total_findings * 55 / 100))  # ~55% typically pass confidence filter
    
    # Calculate batches
    local total_batches=$(((estimated_filtered + BATCH_SIZE - 1) / BATCH_SIZE))
    
    echo "📊 Work Estimation:"
    echo "   - Total findings: $total_findings"
    echo "   - Estimated filtered (conf ≥ $min_conf): $estimated_filtered"
    echo "   - Batch size: $BATCH_SIZE"
    echo "   - Total batches: $total_batches"
    echo "   - Estimated time: $((total_batches * 4 / 60)) minutes"
    echo ""
    
    # Store estimates for progress tracking
    echo "$total_batches" > "$OUTPUT_DIR/total_batches.txt"
    echo "$estimated_filtered" > "$OUTPUT_DIR/total_findings.txt"
}

# Function to monitor progress
monitor_progress() {
    local output_dir="$1"
    local total_batches=$(cat "$output_dir/total_batches.txt" 2>/dev/null || echo "0")
    local total_findings=$(cat "$output_dir/total_findings.txt" 2>/dev/null || echo "0")
    
    echo "📈 Starting progress monitoring..."
    echo "   Press Ctrl+C to stop monitoring (evaluation will continue)"
    echo ""
    
    local start_time=$(date +%s)
    local last_count=0
    
    while true; do
        sleep 5
        
        # Check if AI evaluation is still running
        if ! pgrep -f "pqswitch ai-evaluate" > /dev/null; then
            echo "✅ AI evaluation completed!"
            break
        fi
        
        # Count completed evaluations
        local current_count=0
        if [[ -f "$output_dir/ai_evaluations.json" ]]; then
            current_count=$(jq '.evaluations | length' "$output_dir/ai_evaluations.json" 2>/dev/null || echo "0")
        fi
        
        # Calculate progress
        local progress_pct=0
        if [[ "$total_findings" -gt 0 ]]; then
            progress_pct=$((current_count * 100 / total_findings))
        fi
        
        # Calculate rate
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        local rate=0
        if [[ "$elapsed" -gt 0 ]]; then
            rate=$((current_count * 60 / elapsed))  # findings per minute
        fi
        
        # Estimate time remaining
        local eta="unknown"
        if [[ "$rate" -gt 0 ]] && [[ "$total_findings" -gt "$current_count" ]]; then
            local remaining=$((total_findings - current_count))
            local eta_minutes=$((remaining / rate))
            eta="${eta_minutes}m"
        fi
        
        # Show progress
        if [[ "$current_count" -ne "$last_count" ]]; then
            printf "\r🤖 Progress: %d/%d (%d%%) | Rate: %d/min | ETA: %s | Elapsed: %dm" \
                "$current_count" "$total_findings" "$progress_pct" "$rate" "$eta" "$((elapsed / 60))"
            last_count=$current_count
        else
            printf "\r🔄 Working... %d/%d (%d%%) | Elapsed: %dm" \
                "$current_count" "$total_findings" "$progress_pct" "$((elapsed / 60))"
        fi
    done
    echo ""
}

# Function to run AI evaluation with optimized settings
run_ai_evaluation() {
    local scan_file="$1"
    local output_dir="$2"
    
    echo "🚀 Starting AI evaluation with optimized settings..."
    echo "   - Batch size: $BATCH_SIZE (faster processing)"
    echo "   - Min confidence: $MIN_CONFIDENCE"
    echo "   - Output directory: $output_dir"
    echo ""
    
    # Run AI evaluation in background
    ./build/pqswitch ai-evaluate "$scan_file" \
        --output-dir "$output_dir" \
        --batch-size "$BATCH_SIZE" \
        --min-confidence "$MIN_CONFIDENCE" \
        --max-findings 15000 \
        --api-key "$OPENAI_API_KEY" \
        > "$output_dir/evaluation.log" 2>&1 &
    
    local ai_pid=$!
    echo "🔄 AI evaluation started (PID: $ai_pid)"
    echo "📝 Logs: $output_dir/evaluation.log"
    
    # Monitor progress
    monitor_progress "$output_dir"
    
    # Wait for completion
    wait "$ai_pid"
    local exit_code=$?
    
    if [[ "$exit_code" -eq 0 ]]; then
        echo "✅ AI evaluation completed successfully!"
        echo "📁 Results saved in: $output_dir/"
        
        # Show summary
        if [[ -f "$output_dir/ai_evaluation_summary.json" ]]; then
            echo ""
            echo "📊 Summary:"
            jq -r '"   - Total evaluated: " + (.total_findings | tostring) + 
                     "\n   - Valid findings: " + (.valid_findings | tostring) + 
                     "\n   - False positives: " + (.false_positives | tostring) + 
                     "\n   - Total cost: $" + (.total_cost | tostring)' \
                "$output_dir/ai_evaluation_summary.json"
        fi
    else
        echo "❌ AI evaluation failed with exit code: $exit_code"
        echo "📝 Check logs: $output_dir/evaluation.log"
        return $exit_code
    fi
}

# Main execution
main() {
    echo "🤖 PQSwitch AI Evaluation with Progress Monitoring"
    echo "=================================================="
    
    # Validate inputs
    if [[ ! -f "$SCAN_FILE" ]]; then
        echo "❌ Scan file not found: $SCAN_FILE"
        echo "Usage: $0 <scan-results.json> [output-dir]"
        exit 1
    fi
    
    if [[ -z "${OPENAI_API_KEY:-}" ]]; then
        echo "❌ OPENAI_API_KEY environment variable not set"
        echo "Set it with: export OPENAI_API_KEY='sk-your-key-here'"
        exit 1
    fi
    
    # Estimate work
    estimate_work "$SCAN_FILE" "$MIN_CONFIDENCE"
    
    # Confirm before starting
    read -p "🚀 Start AI evaluation? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelled."
        exit 0
    fi
    
    # Run evaluation with monitoring
    run_ai_evaluation "$SCAN_FILE" "$OUTPUT_DIR"
}

# Handle interrupts gracefully
trap 'echo -e "\n🛑 Monitoring stopped. AI evaluation continues in background."; exit 0' INT

# Run main function
main "$@" 