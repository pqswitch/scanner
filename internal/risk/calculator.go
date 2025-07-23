package risk

import (
	"math"
	"strings"

	"github.com/pqswitch/scanner/internal/types"
)

// Calculator calculates risk scores for findings
type Calculator struct {
	severityWeights map[string]float64
	typeWeights     map[string]float64
}

// NewCalculator creates a new risk calculator
func NewCalculator() *Calculator {
	return &Calculator{
		severityWeights: map[string]float64{
			"critical": 1.0,
			"high":     0.8,
			"medium":   0.5,
			"low":      0.2,
			"info":     0.1,
		},
		typeWeights: map[string]float64{
			"asymmetric": 1.0,
			"symmetric":  0.8,
			"hash":       0.6,
			"random":     0.4,
		},
	}
}

// CalculateRiskScore calculates the overall risk score for a scan result
func (c *Calculator) CalculateRiskScore(result *types.ScanResult) float64 {
	if result.Summary.TotalFindings == 0 {
		return 0.0
	}

	// Calculate weighted sum of findings
	var totalWeight float64
	var weightedSum float64

	for _, finding := range result.Findings {
		severityWeight := c.severityWeights[strings.ToLower(finding.Severity)]
		typeWeight := c.typeWeights[strings.ToLower(finding.CryptoType)]
		weight := severityWeight * typeWeight

		totalWeight += weight
		weightedSum += weight
	}

	// Normalize to 0-1 range
	if totalWeight > 0 {
		return weightedSum / totalWeight
	}
	return 0.0
}

// CalculateConfidence calculates the confidence score for a finding
func (c *Calculator) CalculateConfidence(finding *types.Finding) float64 {
	// Base confidence on severity and type
	severityWeight := c.severityWeights[strings.ToLower(finding.Severity)]
	typeWeight := c.typeWeights[strings.ToLower(finding.CryptoType)]

	// Additional factors
	contextFactor := c.calculateContextFactor(finding)
	algorithmFactor := c.calculateAlgorithmFactor(finding)

	// Combine factors with weights
	confidence := (severityWeight * 0.3) +
		(typeWeight * 0.3) +
		(contextFactor * 0.2) +
		(algorithmFactor * 0.2)

	// Normalize to 0-1 range
	return math.Min(1.0, math.Max(0.0, confidence))
}

// calculateContextFactor calculates how much context is available
func (c *Calculator) calculateContextFactor(finding *types.Finding) float64 {
	if finding.Context == "" {
		return 0.5
	}

	// More context generally means higher confidence
	contextLength := float64(len(finding.Context))
	switch {
	case contextLength > 200:
		return 1.0
	case contextLength > 100:
		return 0.8
	case contextLength > 50:
		return 0.6
	default:
		return 0.4
	}
}

// calculateAlgorithmFactor calculates confidence based on algorithm details
func (c *Calculator) calculateAlgorithmFactor(finding *types.Finding) float64 {
	if finding.Algorithm == "" {
		return 0.5
	}

	// More specific algorithm information means higher confidence
	if finding.KeySize > 0 {
		return 1.0
	}

	// Check if algorithm name is specific
	algorithm := strings.ToLower(finding.Algorithm)
	if strings.Contains(algorithm, "aes") ||
		strings.Contains(algorithm, "rsa") ||
		strings.Contains(algorithm, "ecdsa") ||
		strings.Contains(algorithm, "sha") {
		return 0.9
	}

	return 0.7
}
