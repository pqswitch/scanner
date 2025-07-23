#!/usr/bin/env bash
# test_setup.sh - Test the ml-training setup

set -euo pipefail

echo "🧪 Testing ML Training Setup"
echo "============================"

# Test 1: Check directory structure
echo "📁 Checking directory structure..."
required_dirs=("repos" "results" "storage" "training" "logs" "trained_models")
for dir in "${required_dirs[@]}"; do
    if [[ -d "$dir" ]]; then
        echo "   ✅ $dir/ exists"
    else
        echo "   ❌ $dir/ missing"
        mkdir -p "$dir"
        echo "   ➕ Created $dir/"
    fi
done

# Test 2: Check essential scripts
echo ""
echo "📜 Checking essential scripts..."
required_scripts=("clone_repos.sh" "systematic_scan_parallel.sh" "analyze_results.py" "ai_enhanced_training.py" "run_ai_enhanced_training.sh")
for script in "${required_scripts[@]}"; do
    if [[ -f "$script" ]]; then
        echo "   ✅ $script exists"
    else
        echo "   ❌ $script missing"
    fi
done

# Test 3: Check repos.csv
echo ""
echo "📊 Checking repos.csv..."
if [[ -f "repos.csv" ]]; then
    repo_count=$(tail -n +2 repos.csv | wc -l)
    echo "   ✅ repos.csv exists with $repo_count repositories"
else
    echo "   ❌ repos.csv missing"
fi

# Test 4: Check Python environment
echo ""
echo "🐍 Checking Python environment..."
if command -v python3 &> /dev/null; then
    echo "   ✅ Python 3 available"
    python3 --version
else
    echo "   ❌ Python 3 not available"
fi

# Test 5: Check Python packages
echo ""
echo "📦 Checking Python packages..."
python3 -c "
import sys
required_packages = ['pandas', 'numpy', 'scikit-learn', 'joblib']
available_packages = []
missing_packages = []

for package in required_packages:
    try:
        __import__(package)
        available_packages.append(package)
    except ImportError:
        missing_packages.append(package)

print(f'   ✅ Available: {available_packages}')
if missing_packages:
    print(f'   ❌ Missing: {missing_packages}')
    print('   💡 Install with: pip3 install pandas numpy scikit-learn joblib')
else:
    print('   ✅ All required packages available')
"

# Test 6: Check parent directory files
echo ""
echo "📂 Checking parent directory files..."
parent_files=("../combined_scan_results.json" "../ai_evaluation/ai_evaluations.json" "../pqswitch")
for file in "${parent_files[@]}"; do
    if [[ -f "$file" ]]; then
        echo "   ✅ $file exists"
    else
        echo "   ⚠️  $file missing (needed for training)"
    fi
done

echo ""
echo "🎯 ML Training Setup Summary:"
echo "   - Directory structure: ✅ Complete"
echo "   - Essential scripts: $(ls -1 *.sh *.py 2>/dev/null | wc -l)/5 available"
echo "   - Repository list: $(if [[ -f repos.csv ]]; then echo "✅ Ready"; else echo "❌ Missing"; fi)"
echo "   - Python environment: $(if command -v python3 &> /dev/null; then echo "✅ Ready"; else echo "❌ Missing"; fi)"
echo ""
echo "💡 Next steps:"
echo "   1. Run: bash clone_repos.sh (to clone repositories)"
echo "   2. Run: bash systematic_scan_parallel.sh (to scan repositories)"
echo "   3. Run: bash run_ai_enhanced_training.sh (to train models)" 