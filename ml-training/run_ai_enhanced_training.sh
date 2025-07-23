#!/usr/bin/env bash
# run_ai_enhanced_training.sh - Execute AI-enhanced ML training pipeline
# Incorporates AI evaluation feedback as ground truth for model training

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AI_EVALUATION_FILE="../ai_evaluation/ai_evaluations.json"
SCAN_RESULTS_FILE="../combined_scan_results.json"
TRAINING_SCRIPT="ai_enhanced_training.py"
MODELS_DIR="trained_models"

echo "🚀 AI-Enhanced ML Training Pipeline"
echo "=================================="

# Check prerequisites
echo "🔍 Checking prerequisites..."

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

# Check if required Python packages are installed
echo "📦 Checking Python packages..."
python3 -c "
import sys
required_packages = [
    'pandas', 'numpy', 'sklearn', 'joblib'
]
missing_packages = []
for package in required_packages:
    try:
        __import__(package)
    except ImportError:
        missing_packages.append(package)

if missing_packages:
    print(f'❌ Missing packages: {missing_packages}')
    print('📦 Install with: pip3 install pandas numpy scikit-learn joblib')
    sys.exit(1)
else:
    print('✅ All required packages are installed')
"

# Check if AI evaluation file exists
if [[ ! -f "$AI_EVALUATION_FILE" ]]; then
    echo "❌ AI evaluation file not found: $AI_EVALUATION_FILE"
    echo "💡 Run AI evaluation first: ../pqswitch ai-evaluate ../combined_scan_results.json"
    exit 1
fi

# Check if scan results file exists
if [[ ! -f "$SCAN_RESULTS_FILE" ]]; then
    echo "❌ Scan results file not found: $SCAN_RESULTS_FILE"
    echo "💡 Run scan first to generate combined results"
    exit 1
fi

# Check if training script exists
if [[ ! -f "$TRAINING_SCRIPT" ]]; then
    echo "❌ Training script not found: $TRAINING_SCRIPT"
    exit 1
fi

# Display data summary
echo "📊 Data Summary:"
if command -v jq &> /dev/null; then
    AI_EVAL_COUNT=$(jq '.evaluations | length' "$AI_EVALUATION_FILE" 2>/dev/null || echo "unknown")
    SCAN_COUNT=$(jq '.crypto_findings | length' "$SCAN_RESULTS_FILE" 2>/dev/null || echo "unknown")
    echo "   - AI Evaluations: $AI_EVAL_COUNT"
    echo "   - Scan Findings: $SCAN_COUNT"
    
    if [[ "$AI_EVAL_COUNT" != "unknown" ]] && [[ "$SCAN_COUNT" != "unknown" ]]; then
        COVERAGE=$(python3 -c "print(f'{int($AI_EVAL_COUNT) / int($SCAN_COUNT) * 100:.1f}%')" 2>/dev/null || echo "unknown")
        echo "   - AI Coverage: $COVERAGE"
    fi
else
    echo "   - Install jq for detailed statistics"
fi

# Create models directory
mkdir -p "$MODELS_DIR"

# Run training
echo ""
echo "🧠 Starting AI-Enhanced ML Training..."
echo "⏱️  This may take several minutes..."

# Execute training with error handling
if python3 "$TRAINING_SCRIPT"; then
    echo ""
    echo "✅ Training completed successfully!"
    
    # Display results
    echo ""
    echo "📊 Training Results:"
    
    # Check if models were created
    if ls "$MODELS_DIR"/*.joblib >/dev/null 2>&1; then
        echo "   📁 Models saved in $MODELS_DIR/:"
        ls -la "$MODELS_DIR"/*.joblib | while read -r line; do
            echo "      $(echo "$line" | awk '{print $9}') ($(echo "$line" | awk '{print $5}') bytes)"
        done
    fi
    
    # Check if training report was created
    if [[ -f "$MODELS_DIR/ai_enhanced_training_report.json" ]]; then
        echo "   📊 Training report: $MODELS_DIR/ai_enhanced_training_report.json"
        
        # Display key metrics if jq is available
        if command -v jq &> /dev/null; then
            echo ""
            echo "🎯 Key Metrics:"
            
            # False Positive Detection
            FP_AUC=$(jq -r '.model_results.false_positive_detector.auc_score // "N/A"' "$MODELS_DIR/ai_enhanced_training_report.json" 2>/dev/null)
            if [[ "$FP_AUC" != "N/A" ]]; then
                echo "   - False Positive Detection AUC: $FP_AUC"
            fi
            
            # Confidence Prediction
            CONF_ACC=$(jq -r '.model_results.confidence_predictor.accuracy // "N/A"' "$MODELS_DIR/ai_enhanced_training_report.json" 2>/dev/null)
            if [[ "$CONF_ACC" != "N/A" ]]; then
                echo "   - Confidence Prediction Accuracy: $CONF_ACC"
            fi
            
            # Severity Classification
            SEV_ACC=$(jq -r '.model_results.severity_classifier.accuracy // "N/A"' "$MODELS_DIR/ai_enhanced_training_report.json" 2>/dev/null)
            if [[ "$SEV_ACC" != "N/A" ]]; then
                echo "   - Severity Classification Accuracy: $SEV_ACC"
            fi
        fi
    fi
    
    echo ""
    echo "🎉 AI-Enhanced ML Training Complete!"
    echo "💡 Models are ready for integration with PQSwitch scanner"
    
else
    echo ""
    echo "❌ Training failed!"
    echo "💡 Check the error messages above for troubleshooting"
    exit 1
fi 