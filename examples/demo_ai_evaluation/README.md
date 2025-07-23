# AI Evaluation Demo

This demo shows how to use PQSwitch's AI-in-the-loop evaluation feature to automatically assess scan results using OpenAI's API.

## Quick Start

1. **Get an OpenAI API key** from https://platform.openai.com/api-keys

2. **Set your API key**:
   ```bash
   export OPENAI_API_KEY="your-api-key-here"
   ```

3. **Run the demo**:
   ```bash
   cd examples/demo_ai_evaluation
   go run main.go
   ```

## What This Demo Does

The demo creates 3 sample findings representing common scenarios:

1. **MD5 Hash (Critical)**: Actual security vulnerability in production code
2. **RSA in Documentation (False Positive)**: Just mentioned in README, not actual crypto usage  
3. **AES Implementation (Medium)**: Modern crypto that needs review but isn't urgent

## Expected AI Assessment

The AI evaluator should identify:
- **Finding 1**: Valid critical security issue requiring immediate action
- **Finding 2**: False positive (documentation only)
- **Finding 3**: Valid medium priority finding for review

## Demo Output

```
🎯 AI Evaluation Demo
====================
Created sample findings in: demo_scan_results.json
Sample findings:
  1. MD5 in auth.go:42 (confidence: 0.95)
  2. RSA in README.md:15 (confidence: 0.60)  
  3. AES in crypto.go:128 (confidence: 0.80)

💡 To run AI evaluation on these findings:
1. Get an OpenAI API key from https://platform.openai.com/api-keys
2. Set your API key: export OPENAI_API_KEY="your-key-here"
3. Run evaluation:
   pqswitch ai-evaluate demo_scan_results.json --api-key $OPENAI_API_KEY

📊 Expected results:
- Finding 1 (MD5): Likely CRITICAL - genuine security issue
- Finding 2 (RSA in docs): Likely FALSE POSITIVE - just documentation
- Finding 3 (AES): Likely MEDIUM - review needed but not urgent

💰 Estimated cost: <$0.01 (using gpt-4o-mini)

🤖 OpenAI API key detected! Running live demo...
[Live evaluation results...]
```

## Using the CLI Command

After running the demo, you can use the generated `demo_scan_results.json` with the CLI:

```bash
# Basic evaluation
pqswitch ai-evaluate demo_scan_results.json --api-key $OPENAI_API_KEY

# Estimate costs first
pqswitch ai-evaluate demo_scan_results.json --api-key $OPENAI_API_KEY --estimate-cost-only

# Use different model
pqswitch ai-evaluate demo_scan_results.json --api-key $OPENAI_API_KEY --model gpt-4o
```

## Files Generated

- `demo_scan_results.json`: Sample findings for evaluation
- `demo_ai_evaluation/`: Directory with AI evaluation results
  - `ai_evaluations.json`: Detailed evaluation of each finding
  - `ai_evaluation_summary.json`: Summary statistics and recommendations 