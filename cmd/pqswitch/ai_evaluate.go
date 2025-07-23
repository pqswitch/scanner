package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/pqswitch/scanner/internal/ml"
	"github.com/pqswitch/scanner/internal/types"
	"github.com/spf13/cobra"
)

// aiEvaluateCmd represents the ai-evaluate command
var aiEvaluateCmd = &cobra.Command{
	Use:   "ai-evaluate [scan-results.json]",
	Short: "Use AI to evaluate scan results (AI-in-the-loop)",
	Long: `Use OpenAI's API to automatically evaluate scan results, similar to human validation
but automated. This provides expert-level assessment of findings to reduce false positives
and prioritize real security issues.

The AI evaluator will:
- Assess whether each finding is a genuine security concern or false positive
- Provide appropriate severity levels and migration priorities  
- Give specific recommendations for fixing/migrating each finding
- Generate cost estimates and processing summaries

Example usage:
  # Evaluate scan results with OpenAI API
  pqswitch ai-evaluate scan_results.json --api-key your-openai-key
  
  # Use custom batch size and model
  pqswitch ai-evaluate results.json --api-key key --batch-size 5 --model gpt-4o-mini
  
  # Estimate costs without running
  pqswitch ai-evaluate results.json --estimate-cost-only`,
	Args: cobra.ExactArgs(1),
	RunE: runAIEvaluate,
}

var (
	aiAPIKey        string
	aiModel         string
	aiBatchSize     int
	aiOutputDir     string
	aiEstimateCost  bool
	aiMinConfidence float64
	aiMaxFindings   int
)

func init() {
	rootCmd.AddCommand(aiEvaluateCmd)

	aiEvaluateCmd.Flags().StringVar(&aiAPIKey, "api-key", "", "OpenAI API key (or set OPENAI_API_KEY env var)")
	aiEvaluateCmd.Flags().StringVar(&aiModel, "model", "gpt-4o-mini", "OpenAI model to use (gpt-4o-mini, gpt-4o, gpt-4)")
	aiEvaluateCmd.Flags().IntVar(&aiBatchSize, "batch-size", 5, "Number of findings to evaluate per API call")
	aiEvaluateCmd.Flags().StringVar(&aiOutputDir, "output-dir", "ai_evaluation", "Directory to save evaluation results")
	aiEvaluateCmd.Flags().BoolVar(&aiEstimateCost, "estimate-cost-only", false, "Only estimate costs, don't run evaluation")
	aiEvaluateCmd.Flags().Float64Var(&aiMinConfidence, "min-confidence", 0.3, "Minimum confidence threshold for findings to evaluate")
	aiEvaluateCmd.Flags().IntVar(&aiMaxFindings, "max-findings", 100, "Maximum number of findings to evaluate (cost control)")

	// Note: API key is only required when not doing cost estimation only
}

func runAIEvaluate(cmd *cobra.Command, args []string) error {
	scanResultsFile := args[0]

	// Get API key from flag or environment
	if aiAPIKey == "" {
		aiAPIKey = os.Getenv("OPENAI_API_KEY")
	}

	// API key is only required if not doing cost estimation only
	if aiAPIKey == "" && !aiEstimateCost {
		return fmt.Errorf("OpenAI API key required: use --api-key flag or set OPENAI_API_KEY environment variable")
	}

	// Load scan results
	findings, err := loadScanResults(scanResultsFile)
	if err != nil {
		return fmt.Errorf("failed to load scan results: %w", err)
	}

	// Filter findings by confidence and limit count
	filteredFindings := filterFindingsForAI(findings, aiMinConfidence, aiMaxFindings)

	fmt.Printf("🤖 AI-in-the-Loop Evaluation\n")
	fmt.Printf("============================\n")
	fmt.Printf("Scan Results: %s\n", scanResultsFile)
	fmt.Printf("Total Findings: %d\n", len(findings))
	fmt.Printf("Filtered Findings: %d (confidence ≥ %.1f)\n", len(filteredFindings), aiMinConfidence)
	fmt.Printf("Model: %s\n", aiModel)
	fmt.Printf("Batch Size: %d\n", aiBatchSize)
	fmt.Printf("\n")

	// Estimate costs
	estimatedCost, estimatedTokens := estimateEvaluationCost(filteredFindings, aiModel, aiBatchSize)
	fmt.Printf("💰 Cost Estimation:\n")
	fmt.Printf("Estimated Tokens: %s\n", formatNumber(estimatedTokens))
	fmt.Printf("Estimated Cost: $%.4f\n", estimatedCost)
	fmt.Printf("\n")

	if aiEstimateCost {
		fmt.Printf("✅ Cost estimation complete. Use --estimate-cost-only=false to run evaluation.\n")
		return nil
	}

	// Confirm before proceeding
	if !confirmProceed(estimatedCost) {
		fmt.Printf("❌ Evaluation cancelled by user.\n")
		return nil
	}

	// Create output directory
	if err := os.MkdirAll(aiOutputDir, 0750); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Initialize AI client
	client := ml.NewOpenAIClient(aiAPIKey)
	client.Model = aiModel

	fmt.Printf("🔄 Running AI evaluation...\n")
	fmt.Printf("Progress: 0/%d findings processed (0%%)\n", len(filteredFindings))

	// Run evaluation with progress callback
	progressCallback := func(processed, total int) {
		percent := int(float64(processed) / float64(total) * 100)
		fmt.Printf("\rProgress: %d/%d findings processed (%d%%)", processed, total, percent)
		if processed == total {
			fmt.Printf("\n")
		}
	}

	evaluations, summary, err := client.EvaluateFindingsWithProgress(filteredFindings, aiBatchSize, progressCallback)
	if err != nil {
		return fmt.Errorf("AI evaluation failed: %w", err)
	}

	// Save results
	if err := ml.SaveEvaluationResults(evaluations, summary, aiOutputDir); err != nil {
		return fmt.Errorf("failed to save results: %w", err)
	}

	// Print summary
	printEvaluationSummary(summary, evaluations)

	fmt.Printf("\n✅ AI evaluation complete!\n")
	fmt.Printf("Results saved to: %s/\n", aiOutputDir)
	fmt.Printf("- ai_evaluations.json (detailed findings)\n")
	fmt.Printf("- ai_evaluation_summary.json (summary statistics)\n")

	return nil
}

// loadScanResults loads findings from a JSON scan results file
func loadScanResults(filename string) ([]types.Finding, error) {
	data, err := os.ReadFile(filename) //nolint:gosec // Legitimate file reading
	if err != nil {
		return nil, err
	}

	// Try to parse as direct findings array first
	var findings []types.Finding
	if err := json.Unmarshal(data, &findings); err == nil {
		return findings, nil
	}

	// Try to parse as scan results object with findings field
	var scanResults struct {
		Findings []types.Finding `json:"findings"`
	}
	if err := json.Unmarshal(data, &scanResults); err == nil {
		return scanResults.Findings, nil
	}

	// Try to parse as scan results object with results field
	var scanResults2 struct {
		Results []types.Finding `json:"results"`
	}
	if err := json.Unmarshal(data, &scanResults2); err == nil {
		return scanResults2.Results, nil
	}

	return nil, fmt.Errorf("unable to parse scan results file format")
}

// filterFindingsForAI filters findings by confidence and limits count for AI evaluation with intelligent prioritization
func filterFindingsForAI(findings []types.Finding, minConfidence float64, maxCount int) []types.Finding {
	var filtered []types.Finding

	for _, finding := range findings {
		if finding.Confidence >= minConfidence {
			filtered = append(filtered, finding)
		}
	}

	// Apply intelligent prioritization for cost control
	if len(filtered) > maxCount {
		// Use the same prioritization logic as the main scanner
		filtered = prioritizeFindings(filtered, maxCount)
	}

	return filtered
}

// estimateEvaluationCost estimates the cost of AI evaluation
func estimateEvaluationCost(findings []types.Finding, model string, batchSize int) (float64, int) {
	// Estimate tokens per finding (prompt + response)
	avgTokensPerFinding := 300 // Conservative estimate
	totalTokens := len(findings) * avgTokensPerFinding

	// Model pricing (per 1M tokens)
	var inputPrice, outputPrice float64
	switch model {
	case "gpt-4o-mini":
		inputPrice = 0.15  // $0.15/1M input tokens
		outputPrice = 0.60 // $0.60/1M output tokens
	case "gpt-4o":
		inputPrice = 2.50   // $2.50/1M input tokens
		outputPrice = 10.00 // $10.00/1M output tokens
	case "gpt-4":
		inputPrice = 30.00  // $30.00/1M input tokens
		outputPrice = 60.00 // $60.00/1M output tokens
	default:
		// Default to gpt-4o-mini pricing
		inputPrice = 0.15
		outputPrice = 0.60
	}

	// Estimate input/output split (roughly 70% input, 30% output)
	inputTokens := int(float64(totalTokens) * 0.7)
	outputTokens := int(float64(totalTokens) * 0.3)

	inputCost := float64(inputTokens) * inputPrice / 1000000
	outputCost := float64(outputTokens) * outputPrice / 1000000
	totalCost := inputCost + outputCost

	return totalCost, totalTokens
}

// confirmProceed asks user to confirm before spending money
func confirmProceed(estimatedCost float64) bool {
	if estimatedCost < 0.01 {
		return true // Auto-proceed for very small costs
	}

	fmt.Printf("⚠️  This will cost approximately $%.4f. Continue? (y/N): ", estimatedCost)

	var response string
	if _, err := fmt.Scanln(&response); err != nil {
		// If we can't read input, default to no
		return false
	}

	return strings.ToLower(strings.TrimSpace(response)) == "y"
}

// formatNumber formats a number with thousand separators
func formatNumber(n int) string {
	str := strconv.Itoa(n)
	if len(str) <= 3 {
		return str
	}

	var result strings.Builder
	for i, digit := range str {
		if i > 0 && (len(str)-i)%3 == 0 {
			result.WriteString(",")
		}
		result.WriteRune(digit)
	}

	return result.String()
}

// titleCase converts a string to title case (replacement for deprecated strings.Title)
func titleCase(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + strings.ToLower(s[1:])
}

// printEvaluationSummary prints a summary of the evaluation results
func printEvaluationSummary(summary *ml.AIEvaluationSummary, evaluations []ml.AIEvaluation) {
	fmt.Printf("\n📊 AI Evaluation Summary\n")
	fmt.Printf("========================\n")
	fmt.Printf("Total Findings: %d\n", summary.TotalFindings)
	fmt.Printf("Valid Findings: %d (%.1f%%)\n", summary.ValidFindings,
		float64(summary.ValidFindings)/float64(summary.TotalFindings)*100)
	fmt.Printf("False Positives: %d (%.1f%%)\n", summary.FalsePositives,
		float64(summary.FalsePositives)/float64(summary.TotalFindings)*100)
	fmt.Printf("Average Confidence: %.2f\n", summary.AverageConfidence)
	fmt.Printf("Processing Time: %s\n", summary.ProcessingTime)
	fmt.Printf("Total Tokens Used: %s\n", formatNumber(summary.TotalTokensUsed))
	fmt.Printf("Total Cost: $%.4f\n", summary.TotalCost)

	// Show severity breakdown
	severityCounts := make(map[string]int)
	priorityCounts := make(map[string]int)

	for _, eval := range evaluations {
		if eval.IsValidFinding {
			severityCounts[eval.Severity]++
			priorityCounts[eval.Priority]++
		}
	}

	if len(severityCounts) > 0 {
		fmt.Printf("\n🎯 Valid Findings by Severity:\n")
		for severity, count := range severityCounts {
			fmt.Printf("  %s: %d\n", titleCase(severity), count)
		}
	}

	if len(priorityCounts) > 0 {
		fmt.Printf("\n⚡ Valid Findings by Priority:\n")
		for priority, count := range priorityCounts {
			fmt.Printf("  %s: %d\n", titleCase(priority), count)
		}
	}

	fmt.Printf("\n💡 Recommended Actions:\n")
	for i, action := range summary.RecommendedActions {
		fmt.Printf("  %d. %s\n", i+1, action)
	}
}
