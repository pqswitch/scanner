package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pqswitch/scanner/internal/config"
	"github.com/pqswitch/scanner/internal/scanner"
	"github.com/pqswitch/scanner/internal/types"
)

// Client provides a programmatic interface to the PQSwitch scanner
type Client struct {
	config   *config.Config
	detector *scanner.Detector
}

// ScanRequest represents a scan request
type ScanRequest struct {
	Path         string            `json:"path"`
	OutputFormat string            `json:"output_format,omitempty"`
	RulesPath    string            `json:"rules_path,omitempty"`
	Options      map[string]string `json:"options,omitempty"`
}

// ScanResponse represents a scan response
type ScanResponse struct {
	Success   bool              `json:"success"`
	Result    *types.ScanResult `json:"result,omitempty"`
	Error     string            `json:"error,omitempty"`
	RequestID string            `json:"request_id"`
	Timestamp time.Time         `json:"timestamp"`
}

// HealthResponse represents a health check response
type HealthResponse struct {
	Status    string            `json:"status"`
	Version   string            `json:"version"`
	Timestamp time.Time         `json:"timestamp"`
	Details   map[string]string `json:"details"`
}

// RulesResponse represents a rules information response
type RulesResponse struct {
	TotalRules  int                    `json:"total_rules"`
	RulesByType map[string]int         `json:"rules_by_type"`
	Statistics  map[string]interface{} `json:"statistics"`
	LastUpdated time.Time              `json:"last_updated"`
}

// NewClient creates a new API client
func NewClient(cfg *config.Config) *Client {
	if cfg == nil {
		cfg = config.Load()
	}

	return &Client{
		config:   cfg,
		detector: scanner.NewDetector(cfg),
	}
}

// NewDefaultClient creates a new client with default configuration
func NewDefaultClient() *Client {
	return NewClient(nil)
}

// Scan performs a cryptographic scan
func (c *Client) Scan(ctx context.Context, request ScanRequest) (*ScanResponse, error) {
	requestID := generateRequestID()

	response := &ScanResponse{
		RequestID: requestID,
		Timestamp: time.Now(),
	}

	// Validate request
	if request.Path == "" {
		response.Error = "path is required"
		return response, nil
	}

	// Create scan configuration
	scanConfig := &scanner.Config{
		Path:         request.Path,
		OutputFormat: request.OutputFormat,
		RulesPath:    request.RulesPath,
		Verbose:      false,
	}

	if scanConfig.OutputFormat == "" {
		scanConfig.OutputFormat = "json"
	}

	// Perform scan with context
	done := make(chan error, 1)
	var result *types.ScanResult

	go func() {
		// Create a temporary detector for this scan
		detector := scanner.NewDetector(c.config)

		// Load rules
		if err := detector.LoadRules(scanConfig.RulesPath); err != nil {
			done <- fmt.Errorf("failed to load rules: %w", err)
			return
		}

		// Collect files
		files, err := detector.CollectFiles(scanConfig.Path)
		if err != nil {
			done <- fmt.Errorf("failed to collect files: %w", err)
			return
		}

		// Scan files
		findings, errors := detector.ScanFiles(files, false)

		// Enhanced classification and risk scoring
		for i := range findings {
			result := detector.GetEnhancedClassifier().ClassifyFinding(&findings[i])
			findings[i].Confidence = result.Confidence
			findings[i].Algorithm = result.Algorithm
			findings[i].CryptoType = result.CryptoType
			findings[i].Severity = result.Severity
			findings[i].KeySize = result.KeySize

			// Add enhanced metadata
			if findings[i].Metadata == nil {
				findings[i].Metadata = make(map[string]string)
			}
			findings[i].Metadata["quantum_vulnerable"] = fmt.Sprintf("%t", result.QuantumVulnerable)
			findings[i].Metadata["deprecated"] = fmt.Sprintf("%t", result.Deprecated)
		}

		// Generate result
		result = &types.ScanResult{
			Summary:  detector.GenerateSummary(files, findings, time.Since(response.Timestamp)),
			Findings: findings,
			Errors:   errors,
			Metadata: types.ScanMetadata{
				Version:     "v1.0.0",
				ScanPath:    scanConfig.Path,
				StartTime:   response.Timestamp,
				EndTime:     time.Now(),
				RulesLoaded: detector.GetRulesCount(),
			},
		}

		done <- nil
	}()

	// Wait for completion or context cancellation
	select {
	case err := <-done:
		if err != nil {
			response.Error = err.Error()
			return response, nil
		}
		response.Success = true
		response.Result = result
		return response, nil
	case <-ctx.Done():
		response.Error = "scan cancelled due to context timeout"
		return response, ctx.Err()
	}
}

// Health returns the health status of the scanner
func (c *Client) Health(ctx context.Context) (*HealthResponse, error) {
	response := &HealthResponse{
		Status:    "healthy",
		Version:   "v1.0.0",
		Timestamp: time.Now(),
		Details:   make(map[string]string),
	}

	// Check if rules can be loaded
	tempDetector := scanner.NewDetector(c.config)
	if err := tempDetector.LoadRules(""); err != nil {
		response.Status = "unhealthy"
		response.Details["rules_error"] = err.Error()
	} else {
		response.Details["rules_loaded"] = fmt.Sprintf("%d", tempDetector.GetRulesCount())
	}

	// Check configuration
	if c.config != nil {
		response.Details["config_loaded"] = "true"
		response.Details["default_rules_path"] = c.config.Rules.DefaultRulesPath
	} else {
		response.Details["config_loaded"] = "false"
	}

	return response, nil
}

// GetRulesInfo returns information about loaded rules
func (c *Client) GetRulesInfo(ctx context.Context) (*RulesResponse, error) {
	tempDetector := scanner.NewDetector(c.config)
	if err := tempDetector.LoadRules(""); err != nil {
		return nil, fmt.Errorf("failed to load rules: %w", err)
	}

	stats := tempDetector.GetRuleStatistics()

	response := &RulesResponse{
		TotalRules:  tempDetector.GetRulesCount(),
		Statistics:  stats,
		LastUpdated: time.Now(),
	}

	// Extract rules by type from statistics
	if rulesByType, ok := stats["rules_by_crypto_type"].(map[string]int); ok {
		response.RulesByType = rulesByType
	} else {
		response.RulesByType = make(map[string]int)
	}

	return response, nil
}

// ValidateConfig validates the client configuration
func (c *Client) ValidateConfig() error {
	if c.config == nil {
		return fmt.Errorf("configuration is nil")
	}

	// Test rule loading
	tempDetector := scanner.NewDetector(c.config)
	if err := tempDetector.LoadRules(""); err != nil {
		return fmt.Errorf("failed to validate rules: %w", err)
	}

	return nil
}

// GetVersion returns the client version
func (c *Client) GetVersion() string {
	return "v1.0.0"
}

// Close cleans up client resources
func (c *Client) Close() error {
	// Clean up any resources if needed
	return nil
}

// generateRequestID generates a unique request ID
func generateRequestID() string {
	return fmt.Sprintf("pq-%d", time.Now().UnixNano())
}

// JSONResponse converts a response to JSON
func (r *ScanResponse) JSONResponse() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// JSONResponse converts a health response to JSON
func (r *HealthResponse) JSONResponse() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// JSONResponse converts a rules response to JSON
func (r *RulesResponse) JSONResponse() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
