#!/usr/bin/env bash
# run_ai_evaluation.sh - Smart AI evaluation with automatic batch size adjustment
# Usage: bash run_ai_evaluation.sh [results_file] [api_key] [max_findings] [confidence_threshold]

set -euo pipefail

# Default parameters
RESULTS_FILE="${1:-combined_scan_results.json}"
API_KEY="${2:-$OPENAI_API_KEY}"
MAX_FINDINGS="${3:-1000}"
MIN_CONFIDENCE="${4:-0.5}"
OUTPUT_DIR="ai_evaluation_$(date +%Y%m%d_%H%M%S)"

# Batch size strategy: start conservative, can increase if successful
INITIAL_BATCH_SIZE=10
MODEL="gpt-4o-mini"

echo "🤖 Smart AI Evaluation Pipeline"
echo "==============================="
echo "📄 Results file: $RESULTS_FILE"
echo "🎯 Max findings: $MAX_FINDINGS"
echo "📊 Min confidence: $MIN_CONFIDENCE"
echo "📦 Initial batch size: $INITIAL_BATCH_SIZE"
echo "🤖 Model: $MODEL"
echo "📁 Output directory: $OUTPUT_DIR"
echo ""

# Validate inputs
if [[ ! -f "$RESULTS_FILE" ]]; then
    echo "❌ Results file not found: $RESULTS_FILE"
    echo "💡 Try running: cd ml-training && bash systematic_scan_parallel.sh"
    exit 1
fi

if [[ -z "$API_KEY" ]]; then
    echo "❌ OpenAI API key required"
    echo "💡 Set OPENAI_API_KEY environment variable or pass as second argument"
    exit 1
fi

# Check if pqswitch binary exists
if [[ ! -f "./build/pqswitch" ]]; then
    echo "❌ PQSwitch binary not found at ./build/pqswitch"
    echo "💡 Run: go build -o build/pqswitch cmd/pqswitch/*.go"
    exit 1
fi

# Get cost estimate first
echo "💰 Getting cost estimate..."
ESTIMATE_OUTPUT=$(./build/pqswitch ai-evaluate "$RESULTS_FILE" \
    --api-key "$API_KEY" \
    --model "$MODEL" \
    --batch-size "$INITIAL_BATCH_SIZE" \
    --min-confidence "$MIN_CONFIDENCE" \
    --max-findings "$MAX_FINDINGS" \
    --estimate-cost-only 2>/dev/null)

echo "$ESTIMATE_OUTPUT"
echo ""

# Extract estimated cost for confirmation
ESTIMATED_COST=$(echo "$ESTIMATE_OUTPUT" | grep "Estimated Cost" | sed 's/.*\$\([0-9.]*\).*/\1/')

if [[ -n "$ESTIMATED_COST" ]]; then
    # Auto-approve for small costs, ask for larger ones
    if (( $(echo "$ESTIMATED_COST < 0.10" | bc -l) )); then
        echo "✅ Auto-approving low cost evaluation ($${ESTIMATED_COST})"
        PROCEED="y"
    else
        echo "⚠️  This will cost approximately \$$ESTIMATED_COST"
        read -p "Continue? (y/N): " PROCEED
    fi
else
    read -p "Continue with AI evaluation? (y/N): " PROCEED
fi

if [[ "${PROCEED,,}" != "y" ]]; then
    echo "❌ Evaluation cancelled"
    exit 0
fi

echo ""
echo "🚀 Starting AI evaluation with smart batch management..."

# Function to run evaluation with retry logic
run_evaluation() {
    local batch_size="$1"
    local attempt="$2"
    
    echo "📦 Attempt $attempt: Using batch size $batch_size"
    
    # Run with caffeinate to prevent sleep during long evaluations
    if caffeinate -i ./build/pqswitch ai-evaluate "$RESULTS_FILE" \
        --api-key "$API_KEY" \
        --model "$MODEL" \
        --batch-size "$batch_size" \
        --min-confidence "$MIN_CONFIDENCE" \
        --max-findings "$MAX_FINDINGS" \
        --output-dir "$OUTPUT_DIR" 2>&1; then
        return 0
    else
        return 1
    fi
}

# Smart retry logic with decreasing batch sizes
CURRENT_BATCH_SIZE="$INITIAL_BATCH_SIZE"
MAX_ATTEMPTS=4
ATTEMPT=1

while [[ $ATTEMPT -le $MAX_ATTEMPTS ]]; do
    echo "🔄 Evaluation attempt $ATTEMPT/$MAX_ATTEMPTS (batch size: $CURRENT_BATCH_SIZE)"
    
    if run_evaluation "$CURRENT_BATCH_SIZE" "$ATTEMPT"; then
        echo ""
        echo "✅ AI evaluation completed successfully!"
        echo "📁 Results saved in: $OUTPUT_DIR/"
        echo ""
        
        # Show quick summary if files exist
        if [[ -f "$OUTPUT_DIR/ai_evaluation_summary.json" ]]; then
            echo "📊 Quick Summary:"
            if command -v jq >/dev/null 2>&1; then
                jq -r '"Total Findings: " + (.total_findings | tostring) + 
                       "\nValid Findings: " + (.valid_findings | tostring) + 
                       "\nFalse Positives: " + (.false_positives | tostring) + 
                       "\nTotal Cost: $" + (.total_cost | tostring)' "$OUTPUT_DIR/ai_evaluation_summary.json"
            else
                echo "   (Install jq for detailed summary)"
                ls -la "$OUTPUT_DIR/"
            fi
        fi
        
        echo ""
        echo "🎯 Next Steps:"
        echo "   1. Review results: cat $OUTPUT_DIR/ai_evaluation_summary.json"
        echo "   2. Train ML models: cd ml-training && bash run_ai_enhanced_training.sh"
        echo "   3. Integrate findings: Use results for production deployment"
        
        exit 0
    else
        echo "⚠️  Evaluation attempt $ATTEMPT failed"
        
        if [[ $ATTEMPT -lt $MAX_ATTEMPTS ]]; then
            # Reduce batch size for next attempt
            CURRENT_BATCH_SIZE=$((CURRENT_BATCH_SIZE / 2))
            if [[ $CURRENT_BATCH_SIZE -lt 1 ]]; then
                CURRENT_BATCH_SIZE=1
            fi
            
            echo "🔧 Reducing batch size to $CURRENT_BATCH_SIZE for next attempt"
            ATTEMPT=$((ATTEMPT + 1))
            
            # Wait before retry
            echo "⏳ Waiting 5 seconds before retry..."
            sleep 5
        else
            echo "❌ All evaluation attempts failed"
            echo ""
            echo "🔍 Troubleshooting suggestions:"
            echo "   1. Check your OpenAI API key and quota"
            echo "   2. Try with smaller --max-findings (e.g., 100)"
            echo "   3. Increase --min-confidence (e.g., 0.7) to reduce findings"
            echo "   4. Check network connectivity"
            echo "   5. Try again later if OpenAI is experiencing issues"
            exit 1
        fi
    fi
done 