package risk

import (
	"math"
	"strings"
	"time"

	"github.com/pqswitch/scanner/internal/types"
)

// RiskScore represents a calculated risk score
type RiskScore struct {
	Overall     float64            `json:"overall"`
	Categories  map[string]float64 `json:"categories"`
	Factors     map[string]float64 `json:"factors"`
	Explanation string             `json:"explanation"`
}

// RiskFactor represents a factor that contributes to risk
type RiskFactor struct {
	Name        string  `json:"name"`
	Weight      float64 `json:"weight"`
	Value       float64 `json:"value"`
	Description string  `json:"description"`
}

// HeatMapEntry represents an entry in the risk heat map
type HeatMapEntry struct {
	File        string  `json:"file"`
	Line        int     `json:"line"`
	RiskScore   float64 `json:"risk_score"`
	CryptoType  string  `json:"crypto_type"`
	Algorithm   string  `json:"algorithm"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
}

// CalculateOverallRisk calculates the overall risk score for a set of findings
func CalculateOverallRisk(findings []types.Finding) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	var totalRisk float64
	var weights float64

	for _, finding := range findings {
		riskScore := CalculateFindingRisk(finding)
		weight := getSeverityWeight(finding.Severity)

		totalRisk += riskScore * weight
		weights += weight
	}

	if weights == 0 {
		return 0.0
	}

	// Normalize to 0-100 scale
	overallRisk := (totalRisk / weights) * 100

	// Apply diminishing returns for multiple findings
	findingCount := float64(len(findings))
	diminishingFactor := 1.0 - math.Exp(-findingCount/10.0)

	return math.Min(100.0, overallRisk*diminishingFactor)
}

// CalculateFindingRisk calculates the risk score for a single finding
func CalculateFindingRisk(finding types.Finding) float64 {
	factors := []RiskFactor{
		{
			Name:        "Algorithm Vulnerability",
			Weight:      0.3,
			Value:       getAlgorithmRisk(finding.Algorithm),
			Description: "Risk based on the cryptographic algorithm used",
		},
		{
			Name:        "Severity Level",
			Weight:      0.25,
			Value:       getSeverityRisk(finding.Severity),
			Description: "Risk based on the severity classification",
		},
		{
			Name:        "Confidence Score",
			Weight:      0.2,
			Value:       finding.Confidence,
			Description: "Confidence in the finding accuracy",
		},
		{
			Name:        "Context Risk",
			Weight:      0.15,
			Value:       getContextRisk(finding),
			Description: "Risk based on the code context",
		},
		{
			Name:        "Temporal Risk",
			Weight:      0.1,
			Value:       getTemporalRisk(finding),
			Description: "Risk based on time-sensitive factors",
		},
	}

	var weightedSum float64
	var totalWeight float64

	for _, factor := range factors {
		weightedSum += factor.Value * factor.Weight
		totalWeight += factor.Weight
	}

	if totalWeight == 0 {
		return 0.0
	}

	return weightedSum / totalWeight
}

// getAlgorithmRisk returns risk score based on the algorithm
func getAlgorithmRisk(algorithm string) float64 {
	algorithmUpper := strings.ToUpper(algorithm)

	// Risk scores for different algorithms (0.0 = low risk, 1.0 = high risk)
	algorithmRisks := map[string]float64{
		// Asymmetric algorithms - high risk due to quantum vulnerability
		"RSA":     1.0,
		"ECDSA":   1.0,
		"ECDH":    1.0,
		"DSA":     0.9,
		"DH":      0.8,
		"ELGAMAL": 0.9,

		// Symmetric algorithms - lower risk but still concerning
		"DES":  0.9,
		"3DES": 0.7,
		"RC4":  0.9,
		"RC2":  0.8,

		// Hash algorithms
		"MD5":    0.8,
		"SHA1":   0.7,
		"SHA224": 0.3,
		"SHA256": 0.2,
		"SHA384": 0.1,
		"SHA512": 0.1,

		// Modern algorithms - lower risk
		"AES":      0.2,
		"CHACHA20": 0.1,
		"POLY1305": 0.1,

		// Post-quantum algorithms - very low risk
		"ML-KEM":    0.0,
		"ML-DSA":    0.0,
		"SLH-DSA":   0.0,
		"KYBER":     0.0,
		"DILITHIUM": 0.0,
		"FALCON":    0.0,
		"SPHINCS+":  0.0,
	}

	if risk, exists := algorithmRisks[algorithmUpper]; exists {
		return risk
	}

	// Check for partial matches
	for alg, risk := range algorithmRisks {
		if strings.Contains(algorithmUpper, alg) {
			return risk
		}
	}

	// Default risk for unknown algorithms
	return 0.5
}

// getSeverityRisk returns risk score based on severity
func getSeverityRisk(severity string) float64 {
	severityLower := strings.ToLower(severity)

	severityRisks := map[string]float64{
		"critical": 1.0,
		"high":     0.8,
		"medium":   0.6,
		"low":      0.4,
		"info":     0.2,
	}

	if risk, exists := severityRisks[severityLower]; exists {
		return risk
	}

	return 0.5 // Default for unknown severity
}

// getSeverityWeight returns weight for severity in overall calculations
func getSeverityWeight(severity string) float64 {
	severityLower := strings.ToLower(severity)

	weights := map[string]float64{
		"critical": 1.0,
		"high":     0.8,
		"medium":   0.6,
		"low":      0.4,
		"info":     0.2,
	}

	if weight, exists := weights[severityLower]; exists {
		return weight
	}

	return 0.5
}

// getContextRisk calculates risk based on code context
func getContextRisk(finding types.Finding) float64 {
	context := strings.ToLower(finding.Context)
	risk := 0.5 // Base risk

	// Increase risk for production-like contexts
	productionIndicators := []string{
		"production", "prod", "live", "main", "master",
		"server", "service", "api", "endpoint",
	}

	for _, indicator := range productionIndicators {
		if strings.Contains(context, indicator) {
			risk += 0.2
			break
		}
	}

	// Decrease risk for test/development contexts
	testIndicators := []string{
		"test", "spec", "mock", "stub", "fake",
		"example", "demo", "sample", "debug",
	}

	for _, indicator := range testIndicators {
		if strings.Contains(context, indicator) {
			risk -= 0.3
			break
		}
	}

	// Increase risk for key generation/management
	keyIndicators := []string{
		"generatekey", "newkey", "createkey", "keygen",
		"privatekey", "publickey", "secretkey",
	}

	for _, indicator := range keyIndicators {
		if strings.Contains(context, indicator) {
			risk += 0.3
			break
		}
	}

	// Ensure risk stays within bounds
	return math.Max(0.0, math.Min(1.0, risk))
}

// getTemporalRisk calculates risk based on time-sensitive factors
func getTemporalRisk(finding types.Finding) float64 {
	// Base temporal risk
	risk := 0.5

	// Increase risk based on how recently the code was written
	// (assuming newer code is more likely to be in active use)
	now := time.Now()
	timeSinceFound := now.Sub(finding.Timestamp)

	if timeSinceFound < 24*time.Hour {
		risk += 0.2 // Recently found
	} else if timeSinceFound < 7*24*time.Hour {
		risk += 0.1 // Found this week
	}

	// Increase risk for certain crypto types that are more urgent
	urgentTypes := []string{"asymmetric", "signature", "key_exchange"}
	for _, urgentType := range urgentTypes {
		if strings.ToLower(finding.CryptoType) == urgentType {
			risk += 0.3
			break
		}
	}

	return math.Max(0.0, math.Min(1.0, risk))
}

// GenerateHeatMap generates a risk heat map from findings
func GenerateHeatMap(findings []types.Finding) []HeatMapEntry {
	var heatMap []HeatMapEntry

	for _, finding := range findings {
		riskScore := CalculateFindingRisk(finding)

		entry := HeatMapEntry{
			File:        finding.File,
			Line:        finding.Line,
			RiskScore:   riskScore * 100, // Convert to 0-100 scale
			CryptoType:  finding.CryptoType,
			Algorithm:   finding.Algorithm,
			Severity:    finding.Severity,
			Description: finding.Message,
		}

		heatMap = append(heatMap, entry)
	}

	return heatMap
}

// CalculateRiskTrend calculates risk trend over time
func CalculateRiskTrend(historicalFindings [][]types.Finding) []float64 {
	var trend []float64

	for _, findings := range historicalFindings {
		overallRisk := CalculateOverallRisk(findings)
		trend = append(trend, overallRisk)
	}

	return trend
}

// GetRiskRecommendations provides recommendations based on risk analysis
func GetRiskRecommendations(findings []types.Finding) []string {
	var recommendations []string

	// Count findings by algorithm
	algorithmCounts := make(map[string]int)
	for _, finding := range findings {
		algorithmCounts[finding.Algorithm]++
	}

	// Generate algorithm-specific recommendations
	if count := algorithmCounts["RSA"]; count > 0 {
		recommendations = append(recommendations,
			"Consider migrating RSA implementations to ML-KEM for key encapsulation or hybrid approaches")
	}

	if count := algorithmCounts["ECDSA"]; count > 0 {
		recommendations = append(recommendations,
			"Replace ECDSA signatures with ML-DSA (FIPS 204) for quantum resistance")
	}

	if count := algorithmCounts["MD5"]; count > 0 {
		recommendations = append(recommendations,
			"Immediately replace MD5 hash usage with SHA-256 or SHA-3")
	}

	if count := algorithmCounts["SHA1"]; count > 0 {
		recommendations = append(recommendations,
			"Migrate from SHA-1 to SHA-256 or newer hash algorithms")
	}

	// General recommendations based on overall risk
	overallRisk := CalculateOverallRisk(findings)

	switch {
	case overallRisk > 80:
		recommendations = append(recommendations,
			"High risk detected: Prioritize immediate migration planning and implement hybrid solutions")
	case overallRisk > 60:
		recommendations = append(recommendations,
			"Medium-high risk: Develop migration timeline and begin testing post-quantum alternatives")
	case overallRisk > 40:
		recommendations = append(recommendations,
			"Medium risk: Start evaluating post-quantum cryptography options for future migration")
	}

	if len(recommendations) == 0 {
		recommendations = append(recommendations,
			"Low risk detected: Continue monitoring for new cryptographic vulnerabilities")
	}

	return recommendations
}

// CalculateRiskByCategory calculates risk scores by category
func CalculateRiskByCategory(findings []types.Finding) map[string]float64 {
	categories := map[string][]types.Finding{
		"asymmetric": {},
		"symmetric":  {},
		"hash":       {},
		"signature":  {},
		"protocol":   {},
		"library":    {},
	}

	// Categorize findings
	for _, finding := range findings {
		cryptoType := strings.ToLower(finding.CryptoType)
		if _, exists := categories[cryptoType]; exists {
			categories[cryptoType] = append(categories[cryptoType], finding)
		} else {
			categories["library"] = append(categories["library"], finding)
		}
	}

	// Calculate risk for each category
	categoryRisks := make(map[string]float64)
	for category, categoryFindings := range categories {
		if len(categoryFindings) > 0 {
			categoryRisks[category] = CalculateOverallRisk(categoryFindings)
		} else {
			categoryRisks[category] = 0.0
		}
	}

	return categoryRisks
}
