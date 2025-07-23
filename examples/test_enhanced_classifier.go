package main

import (
	"fmt"
	"time"

	"github.com/pqswitch/scanner/internal/classifier"
	"github.com/pqswitch/scanner/internal/types"
)

func main() {
	// Create enhanced classifier
	ec := classifier.NewEnhancedClassifier()

	// Test findings
	testFindings := []types.Finding{
		{
			ID:        "test-1",
			File:      "crypto/rsa.go",
			Line:      42,
			Message:   "RSA key generation detected",
			Context:   "key, err := rsa.GenerateKey(rand.Reader, 2048)",
			Algorithm: "RSA",
			Timestamp: time.Now(),
		},
		{
			ID:        "test-2",
			File:      "auth/jwt.go",
			Line:      25,
			Message:   "ECDSA signature detected",
			Context:   "token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)",
			Algorithm: "ECDSA",
			Timestamp: time.Now(),
		},
		{
			ID:        "test-3",
			File:      "utils/hash.go",
			Line:      15,
			Message:   "MD5 hash usage detected",
			Context:   "hash := md5.Sum(data)",
			Algorithm: "MD5",
			Timestamp: time.Now(),
		},
	}

	fmt.Println("=== Enhanced Crypto Classification Test ===")

	for i, finding := range testFindings {
		fmt.Printf("Test %d: %s\n", i+1, finding.File)
		fmt.Printf("Context: %s\n", finding.Context)

		// Classify finding
		result := ec.ClassifyFinding(&finding)

		fmt.Printf("Results:\n")
		fmt.Printf("  Algorithm: %s\n", result.Algorithm)
		fmt.Printf("  Crypto Type: %s\n", result.CryptoType)
		fmt.Printf("  Severity: %s\n", result.Severity)
		fmt.Printf("  Confidence: %.2f\n", result.Confidence)
		fmt.Printf("  Quantum Vulnerable: %t\n", result.QuantumVulnerable)
		fmt.Printf("  Deprecated: %t\n", result.Deprecated)

		if result.KeySize > 0 {
			fmt.Printf("  Key Size: %d bits\n", result.KeySize)
		}

		if len(result.MigrationPath.Recommended) > 0 {
			fmt.Printf("  Recommended Migration: %v\n", result.MigrationPath.Recommended)
			fmt.Printf("  Migration Timeline: %s\n", result.MigrationPath.Timeline)
			fmt.Printf("  Effort Level: %s\n", result.MigrationPath.EffortLevel)
		}

		if len(result.VulnerabilityInfo.CVEs) > 0 {
			fmt.Printf("  CVEs: %v\n", result.VulnerabilityInfo.CVEs)
		}

		fmt.Println()
	}

	// Generate comprehensive report
	fmt.Println("=== Comprehensive Report ===")
	report, err := ec.GenerateReport(testFindings)
	if err != nil {
		fmt.Printf("Error generating report: %v\n", err)
		return
	}

	fmt.Println(report)
}
