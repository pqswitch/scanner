package scanner

import (
	"context"
	"fmt"

	"github.com/pqswitch/scanner/internal/ml"
	"github.com/pqswitch/scanner/internal/types"
)

// MLEnhancedDetector wraps a LayeredDetector with ML enhancements
type MLEnhancedDetector struct {
	baseDetector *LayeredDetector
	mlModels     *ml.MLModels
	enabled      bool
}

// NewMLEnhancedDetector creates a new ML-enhanced detector
func NewMLEnhancedDetector(baseDetector *LayeredDetector) *MLEnhancedDetector {
	return &MLEnhancedDetector{
		baseDetector: baseDetector,
		mlModels:     ml.NewMLModels(),
		enabled:      true,
	}
}

// EnableML enables or disables ML enhancements
func (d *MLEnhancedDetector) EnableML(enabled bool) {
	d.enabled = enabled
}

// LoadRules loads detection rules (delegates to base detector)
func (d *MLEnhancedDetector) LoadRules(rulesPath string) error {
	return d.baseDetector.LoadRules(rulesPath)
}

// CollectFiles collects files to scan (delegates to base detector)
func (d *MLEnhancedDetector) CollectFiles(scanPath string) ([]string, error) {
	// LayeredDetector doesn't have CollectFiles method, so we need to create a basic detector for this
	// This is a limitation of the current architecture
	return nil, fmt.Errorf("CollectFiles not supported by MLEnhancedDetector, use base detector directly")
}

// AnalyzeFile analyzes a file and enhances findings with ML predictions
func (d *MLEnhancedDetector) AnalyzeFile(ctx context.Context, fileCtx *FileContext) (*LayeredResult, error) {
	// Get base analysis results
	result, err := d.baseDetector.AnalyzeFile(ctx, fileCtx)
	if err != nil {
		return result, err
	}

	// Enhance findings with ML predictions if enabled
	if d.enabled && d.mlModels != nil {
		for i := range result.Findings {
			enhanced := d.enhanceFindingWithML(&result.Findings[i])
			result.Findings[i] = *enhanced
		}
	}

	return result, nil
}

// enhanceFindingWithML enhances a single finding with ML predictions
func (d *MLEnhancedDetector) enhanceFindingWithML(finding *types.Finding) *types.Finding {
	// Convert finding to map for ML processing
	findingMap := d.findingToMap(finding)

	// Apply ML enhancements
	enhanced := ml.EnhanceFindingWithML(findingMap, d.mlModels)

	// Update finding with ML predictions
	if fpScore, ok := enhanced["ml_false_positive_score"].(float64); ok {
		finding.Metadata["ml_false_positive_score"] = fmt.Sprintf("%.3f", fpScore)

		// Adjust confidence based on ML prediction
		if fpScore < 0.3 {
			// High likelihood of false positive - reduce confidence
			finding.Confidence *= 0.5
			finding.Metadata["ml_adjustment"] = "confidence_reduced_likely_fp"
		} else if fpScore > 0.8 {
			// High likelihood of valid finding - boost confidence
			finding.Confidence = min(1.0, finding.Confidence*1.2)
			finding.Metadata["ml_adjustment"] = "confidence_boosted_likely_valid"
		}
	}

	if confClass, ok := enhanced["ml_confidence_class"].(string); ok {
		finding.Metadata["ml_confidence_class"] = confClass
	}

	if sevClass, ok := enhanced["ml_predicted_severity"].(string); ok {
		finding.Metadata["ml_predicted_severity"] = sevClass

		// Optionally adjust severity based on ML prediction
		if sevClass == "critical" && finding.Severity != "critical" {
			finding.Metadata["ml_severity_suggestion"] = "consider_upgrading_to_critical"
		} else if sevClass == "info" && finding.Severity == "high" {
			finding.Metadata["ml_severity_suggestion"] = "consider_downgrading_from_high"
		}
	}

	// Add ML enhancement marker
	finding.Metadata["ml_enhanced"] = "true"

	return finding
}

// findingToMap converts a Finding to a map for ML processing
func (d *MLEnhancedDetector) findingToMap(finding *types.Finding) map[string]interface{} {
	return map[string]interface{}{
		"algorithm":   finding.Algorithm,
		"severity":    finding.Severity,
		"confidence":  finding.Confidence,
		"crypto_type": finding.CryptoType,
		"language":    getLanguageFromFile(finding.File),
		"rule_id":     finding.RuleID,
		"line":        float64(finding.Line),
		"file":        finding.File,
		"pattern":     getPatternFromMetadata(finding.Metadata),
		"message":     finding.Message,
		"context":     finding.Context,
	}
}

// Helper functions

func getLanguageFromFile(filename string) string {
	// Extract language from file extension
	if len(filename) == 0 {
		return "unknown"
	}

	ext := ""
	for i := len(filename) - 1; i >= 0; i-- {
		if filename[i] == '.' {
			ext = filename[i+1:]
			break
		}
	}

	switch ext {
	case "go":
		return "go"
	case "js", "mjs", "jsx":
		return "javascript"
	case "ts", "tsx":
		return "typescript"
	case "py":
		return "python"
	case "java":
		return "java"
	case "kt":
		return "kotlin"
	case "rs":
		return "rust"
	case "c", "h":
		return "c"
	case "cpp", "cc", "cxx", "hpp":
		return "cpp"
	case "cs":
		return "csharp"
	case "rb":
		return "ruby"
	case "php":
		return "php"
	default:
		return "unknown"
	}
}

func getPatternFromMetadata(metadata map[string]string) string {
	if pattern, exists := metadata["pattern"]; exists {
		return pattern
	}
	if matchText, exists := metadata["match_text"]; exists {
		return matchText
	}
	return ""
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// MLEnhancedDetectorConfig holds configuration for ML enhancements
type MLEnhancedDetectorConfig struct {
	EnableML               bool    `yaml:"enable_ml"`
	FalsePositiveThreshold float64 `yaml:"false_positive_threshold"`
	ConfidenceBoostFactor  float64 `yaml:"confidence_boost_factor"`
	ConfidenceReduceFactor float64 `yaml:"confidence_reduce_factor"`
	AdjustSeverity         bool    `yaml:"adjust_severity"`
}

// DefaultMLEnhancedDetectorConfig returns default configuration
func DefaultMLEnhancedDetectorConfig() MLEnhancedDetectorConfig {
	return MLEnhancedDetectorConfig{
		EnableML:               true,
		FalsePositiveThreshold: 0.3,
		ConfidenceBoostFactor:  1.2,
		ConfidenceReduceFactor: 0.5,
		AdjustSeverity:         false, // Conservative default
	}
}
