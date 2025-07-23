package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/pqswitch/scanner/internal/ml"
	"github.com/pqswitch/scanner/internal/types"
)

func main() {
	// Example: Create some sample findings for demonstration
	sampleFindings := []types.Finding{
		{
			ID:         "demo-001",
			File:       "auth.go",
			Line:       42,
			Algorithm:  "MD5",
			Severity:   "critical",
			Confidence: 0.95,
			Message:    "MD5 hash function detected",
			Context:    "Used in password hashing function",
			CryptoType: "hash",
			Suggestion: "Replace with SHA-256 or bcrypt",
		},
		{
			ID:         "demo-002",
			File:       "README.md",
			Line:       15,
			Algorithm:  "RSA",
			Severity:   "high",
			Confidence: 0.6,
			Message:    "RSA mentioned in documentation",
			Context:    "Documentation comment about RSA encryption",
			CryptoType: "asymmetric",
			Suggestion: "Consider post-quantum alternatives",
		},
		{
			ID:         "demo-003",
			File:       "crypto.go",
			Line:       128,
			Algorithm:  "AES",
			Severity:   "medium",
			Confidence: 0.8,
			Message:    "AES encryption implementation",
			Context:    "Production encryption code",
			CryptoType: "symmetric",
			Suggestion: "Review key exchange mechanism",
		},
	}

	// Save sample findings to file for demo
	demoFile := "demo_scan_results.json"
	if err := saveSampleFindings(sampleFindings, demoFile); err != nil {
		log.Fatalf("Failed to save sample findings: %v", err)
	}

	fmt.Printf("🎯 AI Evaluation Demo\n")
	fmt.Printf("====================\n")
	fmt.Printf("Created sample findings in: %s\n", demoFile)
	fmt.Printf("Sample findings:\n")

	for i, finding := range sampleFindings {
		fmt.Printf("  %d. %s in %s:%d (confidence: %.2f)\n",
			i+1, finding.Algorithm, finding.File, finding.Line, finding.Confidence)
	}

	fmt.Printf("\n💡 To run AI evaluation on these findings:\n")
	fmt.Printf("1. Get an OpenAI API key from https://platform.openai.com/api-keys\n")
	fmt.Printf("2. Set your API key: export OPENAI_API_KEY=\"your-key-here\"\n")
	fmt.Printf("3. Run evaluation:\n")
	fmt.Printf("   pqswitch ai-evaluate %s --api-key $OPENAI_API_KEY\n", demoFile)
	fmt.Printf("\n📊 Expected results:\n")
	fmt.Printf("- Finding 1 (MD5): Likely CRITICAL - genuine security issue\n")
	fmt.Printf("- Finding 2 (RSA in docs): Likely FALSE POSITIVE - just documentation\n")
	fmt.Printf("- Finding 3 (AES): Likely MEDIUM - review needed but not urgent\n")
	fmt.Printf("\n💰 Estimated cost: <$0.01 (using gpt-4o-mini)\n")

	// Check if API key is available
	if apiKey := os.Getenv("OPENAI_API_KEY"); apiKey != "" {
		fmt.Printf("\n🤖 OpenAI API key detected! Running live demo...\n")
		runLiveDemo(sampleFindings, apiKey)
	} else {
		fmt.Printf("\n⚠️  Set OPENAI_API_KEY to run live demo\n")
	}
}

func saveSampleFindings(findings []types.Finding, filename string) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0600)
}

func runLiveDemo(findings []types.Finding, apiKey string) {
	fmt.Printf("Initializing AI client...\n")

	client := ml.NewOpenAIClient(apiKey)

	fmt.Printf("Running evaluation on %d findings...\n", len(findings))

	evaluations, summary, err := client.EvaluateFindings(findings, 3)
	if err != nil {
		fmt.Printf("❌ Demo failed: %v\n", err)
		return
	}

	fmt.Printf("\n✅ Demo Results:\n")
	fmt.Printf("Valid Findings: %d/%d\n", summary.ValidFindings, summary.TotalFindings)
	fmt.Printf("False Positives: %d/%d\n", summary.FalsePositives, summary.TotalFindings)
	fmt.Printf("Total Cost: $%.4f\n", summary.TotalCost)
	fmt.Printf("Processing Time: %s\n", summary.ProcessingTime)

	fmt.Printf("\n📋 Detailed Evaluations:\n")
	for i, eval := range evaluations {
		status := "✅ Valid"
		if !eval.IsValidFinding {
			status = "❌ False Positive"
		}

		fmt.Printf("  %d. %s (confidence: %.2f)\n", i+1, status, eval.Confidence)
		fmt.Printf("     Severity: %s | Priority: %s\n", eval.Severity, eval.Priority)
		fmt.Printf("     Reasoning: %s\n", eval.Reasoning)
		fmt.Printf("     Suggestion: %s\n", eval.MigrationSuggestion)
		fmt.Printf("\n")
	}

	// Save demo results
	demoDir := "demo_ai_evaluation"
	if err := os.MkdirAll(demoDir, 0750); err != nil {
		fmt.Printf("⚠️  Failed to create demo directory: %v\n", err)
		return
	}

	if err := ml.SaveEvaluationResults(evaluations, summary, demoDir); err != nil {
		fmt.Printf("⚠️  Failed to save demo results: %v\n", err)
		return
	}

	fmt.Printf("💾 Demo results saved to: %s/\n", demoDir)
}
