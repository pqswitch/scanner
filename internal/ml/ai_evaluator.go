package ml

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pqswitch/scanner/internal/types"
)

// OpenAIClient handles communication with OpenAI API
type OpenAIClient struct {
	APIKey     string
	BaseURL    string
	Model      string
	HTTPClient *http.Client
}

// AIEvaluationRequest represents a request for AI evaluation
type AIEvaluationRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature"`
	MaxTokens   int       `json:"max_tokens"`
}

// Message represents a chat message
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// AIEvaluationResponse represents OpenAI API response
type AIEvaluationResponse struct {
	ID      string    `json:"id"`
	Object  string    `json:"object"`
	Created int64     `json:"created"`
	Model   string    `json:"model"`
	Choices []Choice  `json:"choices"`
	Usage   Usage     `json:"usage"`
	Error   *APIError `json:"error,omitempty"`
}

// Choice represents a response choice
type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

// Usage represents token usage information
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// APIError represents an API error
type APIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

// AIEvaluation represents the AI's evaluation of a finding
type AIEvaluation struct {
	FindingID           string  `json:"finding_id"`
	IsValidFinding      bool    `json:"is_valid_finding"`
	Confidence          float64 `json:"confidence"`
	Severity            string  `json:"severity"`
	Priority            string  `json:"priority"`
	Reasoning           string  `json:"reasoning"`
	MigrationSuggestion string  `json:"migration_suggestion"`
	FalsePositiveReason string  `json:"false_positive_reason,omitempty"`
	TokensUsed          int     `json:"tokens_used"`
	Cost                float64 `json:"cost"`
}

// AIEvaluationSummary represents summary statistics
type AIEvaluationSummary struct {
	TotalFindings      int      `json:"total_findings"`
	ValidFindings      int      `json:"valid_findings"`
	FalsePositives     int      `json:"false_positives"`
	TotalTokensUsed    int      `json:"total_tokens_used"`
	TotalCost          float64  `json:"total_cost"`
	AverageConfidence  float64  `json:"average_confidence"`
	ProcessingTime     string   `json:"processing_time"`
	RecommendedActions []string `json:"recommended_actions"`
}

// NewOpenAIClient creates a new OpenAI client
func NewOpenAIClient(apiKey string) *OpenAIClient {
	return &OpenAIClient{
		APIKey:  apiKey,
		BaseURL: "https://api.openai.com/v1/chat/completions",
		Model:   "gpt-4o-mini", // Cost-effective model
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// EvaluateFindings sends findings to AI for evaluation in batches
func (client *OpenAIClient) EvaluateFindings(findings []types.Finding, batchSize int) ([]AIEvaluation, *AIEvaluationSummary, error) {
	return client.EvaluateFindingsWithProgress(findings, batchSize, nil)
}

// EvaluateFindingsWithProgress sends findings to AI for evaluation in batches with progress callback
func (client *OpenAIClient) EvaluateFindingsWithProgress(findings []types.Finding, batchSize int, progressCallback func(int, int)) ([]AIEvaluation, *AIEvaluationSummary, error) {
	startTime := time.Now()
	var evaluations []AIEvaluation
	totalTokens := 0
	totalCost := 0.0

	// Process findings in batches
	for i := 0; i < len(findings); i += batchSize {
		end := i + batchSize
		if end > len(findings) {
			end = len(findings)
		}

		batch := findings[i:end]
		batchEvaluations, batchTokens, batchCost, err := client.evaluateBatch(batch)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to evaluate batch %d-%d: %w", i, end-1, err)
		}

		evaluations = append(evaluations, batchEvaluations...)
		totalTokens += batchTokens
		totalCost += batchCost

		// Call progress callback if provided
		if progressCallback != nil {
			progressCallback(len(evaluations), len(findings))
		}

		// Rate limiting: wait between batches
		if i+batchSize < len(findings) {
			time.Sleep(1 * time.Second)
		}
	}

	// Generate summary
	summary := client.generateSummary(evaluations, totalTokens, totalCost, time.Since(startTime))

	return evaluations, summary, nil
}

// evaluateBatch evaluates a batch of findings with automatic batch size reduction on failures
func (client *OpenAIClient) evaluateBatch(findings []types.Finding) ([]AIEvaluation, int, float64, error) {
	return client.evaluateBatchWithSize(findings, len(findings))
}

// evaluateBatchWithSize evaluates a batch of findings with specified batch size
func (client *OpenAIClient) evaluateBatchWithSize(findings []types.Finding, batchSize int) ([]AIEvaluation, int, float64, error) {
	// If batch size is larger than findings, use all findings
	if batchSize > len(findings) {
		batchSize = len(findings)
	}

	// If we need to split the batch, process recursively
	if batchSize < len(findings) {
		var allEvaluations []AIEvaluation
		var totalTokens int
		var totalCost float64

		for i := 0; i < len(findings); i += batchSize {
			end := i + batchSize
			if end > len(findings) {
				end = len(findings)
			}

			subBatch := findings[i:end]
			subEvaluations, subTokens, subCost, err := client.evaluateBatchWithSize(subBatch, batchSize)
			if err != nil {
				return nil, 0, 0, err
			}

			allEvaluations = append(allEvaluations, subEvaluations...)
			totalTokens += subTokens
			totalCost += subCost

			// Rate limiting between sub-batches
			if end < len(findings) {
				time.Sleep(1 * time.Second)
			}
		}

		return allEvaluations, totalTokens, totalCost, nil
	}

	// Process single batch
	prompt := client.buildEvaluationPrompt(findings)

	request := AIEvaluationRequest{
		Model: client.Model,
		Messages: []Message{
			{
				Role:    "system",
				Content: client.getSystemPrompt(),
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
		Temperature: 0.1,  // Low temperature for consistent results
		MaxTokens:   4000, // Sufficient for detailed evaluation
	}

	// Retry logic with progressively smaller batch sizes
	var response *AIEvaluationResponse
	var evaluations []AIEvaluation
	var err error

	maxRetries := 2
	currentBatchSize := len(findings)

	for attempt := 0; attempt <= maxRetries; attempt++ {
		response, err = client.makeRequest(request)
		if err != nil {
			if attempt == maxRetries {
				return nil, 0, 0, fmt.Errorf("API request failed after %d attempts: %w", maxRetries+1, err)
			}
			fmt.Fprintf(os.Stderr, "API request attempt %d failed, retrying: %v\n", attempt+1, err)
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}

		evaluations, err = client.parseEvaluationResponse(response.Choices[0].Message.Content, findings)
		if err != nil {
			// Check if this is an incomplete evaluation error
			if strings.Contains(err.Error(), "incomplete evaluations") && currentBatchSize > 1 {
				// Retry with smaller batch size
				newBatchSize := currentBatchSize / 2
				fmt.Fprintf(os.Stderr, "Incomplete evaluations detected, retrying with smaller batch size: %d -> %d\n", currentBatchSize, newBatchSize)
				return client.evaluateBatchWithSize(findings, newBatchSize)
			}

			if attempt == maxRetries {
				return nil, 0, 0, fmt.Errorf("response parsing failed after %d attempts: %w", maxRetries+1, err)
			}
			fmt.Fprintf(os.Stderr, "Response parsing attempt %d failed, retrying: %v\n", attempt+1, err)
			// For parsing failures, adjust the request slightly
			request.Temperature = 0.05 // Even lower temperature for more consistency
			time.Sleep(time.Duration(attempt+1) * time.Second)
			continue
		}

		// Success!
		break
	}

	// Calculate cost (GPT-4o-mini pricing: $0.15/1M input tokens, $0.60/1M output tokens)
	inputCost := float64(response.Usage.PromptTokens) * 0.15 / 1000000
	outputCost := float64(response.Usage.CompletionTokens) * 0.60 / 1000000
	totalCost := inputCost + outputCost

	// Add token usage and cost to each evaluation
	for i := range evaluations {
		evaluations[i].TokensUsed = response.Usage.TotalTokens / len(evaluations)
		evaluations[i].Cost = totalCost / float64(len(evaluations))
	}

	return evaluations, response.Usage.TotalTokens, totalCost, nil
}

// getSystemPrompt returns the system prompt for AI evaluation
func (client *OpenAIClient) getSystemPrompt() string {
	return `You are an expert cybersecurity analyst specializing in post-quantum cryptography migration. Your task is to evaluate cryptographic findings from a code scanner and determine:

1. Whether each finding represents a genuine security concern or a false positive
2. The appropriate severity level (critical, high, medium, low, info)
3. Migration priority and specific recommendations

Consider these factors:
- Context: Is this production code, test code, documentation, or library implementation?
- Algorithm: Is it cryptographically broken (MD5, SHA-1, DES) or quantum-vulnerable (RSA, ECDSA, ECDH)?
- Usage: Is it actually being used for security purposes or just mentioned/referenced?
- Risk: What's the real-world impact if this isn't fixed?

CRITICAL: You must respond with a JSON array containing exactly one evaluation object per finding, in the same order as presented. Do not add, skip, or reorder any findings.

Each evaluation object must contain:
- is_valid_finding: boolean
- confidence: 0.0-1.0 (how confident you are in your assessment)
- severity: "critical"|"high"|"medium"|"low"|"info"
- priority: "immediate"|"high"|"medium"|"low"|"info"
- reasoning: brief explanation of your assessment
- migration_suggestion: specific recommendation for fixing/migrating
- false_positive_reason: if false positive, explain why

Be practical and focus on real security risks, not theoretical concerns. Ensure your response contains exactly the same number of evaluations as findings provided.`
}

// buildEvaluationPrompt creates the evaluation prompt for a batch of findings
func (client *OpenAIClient) buildEvaluationPrompt(findings []types.Finding) string {
	var prompt strings.Builder

	prompt.WriteString("Please evaluate the following cryptographic findings:\n\n")

	for i, finding := range findings {
		prompt.WriteString(fmt.Sprintf("Finding %d:\n", i+1))
		prompt.WriteString(fmt.Sprintf("ID: %s\n", finding.ID))
		prompt.WriteString(fmt.Sprintf("File: %s (line %d)\n", finding.File, finding.Line))
		prompt.WriteString(fmt.Sprintf("Algorithm: %s\n", finding.Algorithm))
		prompt.WriteString(fmt.Sprintf("Severity: %s\n", finding.Severity))
		prompt.WriteString(fmt.Sprintf("Confidence: %.2f\n", finding.Confidence))
		prompt.WriteString(fmt.Sprintf("Message: %s\n", finding.Message))
		prompt.WriteString(fmt.Sprintf("Context: %s\n", finding.Context))
		prompt.WriteString(fmt.Sprintf("Crypto Type: %s\n", finding.CryptoType))
		prompt.WriteString(fmt.Sprintf("Suggestion: %s\n", finding.Suggestion))
		prompt.WriteString("\n")
	}

	prompt.WriteString("Respond with a JSON array containing one evaluation object per finding, in the same order.")

	return prompt.String()
}

// makeRequest makes an HTTP request to OpenAI API
func (client *OpenAIClient) makeRequest(request AIEvaluationRequest) (*AIEvaluationResponse, error) {
	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", client.BaseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+client.APIKey)

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// Log the error but don't fail the request
			fmt.Fprintf(os.Stderr, "Warning: failed to close response body: %v\n", closeErr)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	var response AIEvaluationResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	if response.Error != nil {
		return nil, fmt.Errorf("API error: %s", response.Error.Message)
	}

	return &response, nil
}

// parseEvaluationResponse parses the AI's evaluation response
func (client *OpenAIClient) parseEvaluationResponse(content string, findings []types.Finding) ([]AIEvaluation, error) {
	// Try to extract JSON from the response
	start := strings.Index(content, "[")
	end := strings.LastIndex(content, "]")

	if start == -1 || end == -1 {
		return nil, fmt.Errorf("no JSON array found in response")
	}

	jsonStr := content[start : end+1]

	var evaluations []AIEvaluation
	if err := json.Unmarshal([]byte(jsonStr), &evaluations); err != nil {
		return nil, fmt.Errorf("failed to parse evaluation JSON: %w", err)
	}

	// Handle mismatched evaluation counts more gracefully
	expectedCount := len(findings)
	actualCount := len(evaluations)

	if actualCount == 0 {
		return nil, fmt.Errorf("no evaluations found in response")
	}

	// If we have too many evaluations, truncate to match findings
	if actualCount > expectedCount {
		fmt.Fprintf(os.Stderr, "Warning: AI returned %d evaluations, expected %d. Truncating to match findings.\n", actualCount, expectedCount)
		evaluations = evaluations[:expectedCount]
	}

	// If we have too few evaluations, this is an error that should trigger a retry
	if actualCount < expectedCount {
		return nil, fmt.Errorf("AI returned incomplete evaluations: got %d, expected %d. This will trigger a retry with smaller batch size", actualCount, expectedCount)
	}

	// Add finding IDs
	for i, finding := range findings {
		if i < len(evaluations) {
			evaluations[i].FindingID = finding.ID
		}
	}

	return evaluations, nil
}

// generateSummary creates a summary of the evaluation results
func (client *OpenAIClient) generateSummary(evaluations []AIEvaluation, totalTokens int, totalCost float64, processingTime time.Duration) *AIEvaluationSummary {
	summary := &AIEvaluationSummary{
		TotalFindings:   len(evaluations),
		TotalTokensUsed: totalTokens,
		TotalCost:       totalCost,
		ProcessingTime:  processingTime.String(),
	}

	var confidenceSum float64

	for _, eval := range evaluations {
		if eval.IsValidFinding {
			summary.ValidFindings++
		} else {
			summary.FalsePositives++
		}
		confidenceSum += eval.Confidence
	}

	if len(evaluations) > 0 {
		summary.AverageConfidence = confidenceSum / float64(len(evaluations))
	}

	// Generate recommended actions
	summary.RecommendedActions = []string{
		fmt.Sprintf("Review %d critical/high priority findings immediately", summary.ValidFindings),
		fmt.Sprintf("Consider filtering out %d false positives", summary.FalsePositives),
		"Focus on quantum-vulnerable algorithms (RSA, ECDSA, ECDH) for migration planning",
		"Replace cryptographically broken algorithms (MD5, SHA-1, DES) immediately",
	}

	return summary
}

// SaveEvaluationResults saves the evaluation results to JSON files
func SaveEvaluationResults(evaluations []AIEvaluation, summary *AIEvaluationSummary, outputDir string) error {
	// Save detailed evaluations
	evalFile := fmt.Sprintf("%s/ai_evaluations.json", outputDir)
	evalData, err := json.MarshalIndent(evaluations, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal evaluations: %w", err)
	}

	if err := writeFile(evalFile, evalData); err != nil {
		return fmt.Errorf("failed to write evaluations: %w", err)
	}

	// Save summary
	summaryFile := fmt.Sprintf("%s/ai_evaluation_summary.json", outputDir)
	summaryData, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal summary: %w", err)
	}

	if err := writeFile(summaryFile, summaryData); err != nil {
		return fmt.Errorf("failed to write summary: %w", err)
	}

	return nil
}

// writeFile is a helper function to write data to a file
func writeFile(filename string, data []byte) error {
	return os.WriteFile(filename, data, 0600)
}
