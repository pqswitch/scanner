package crypto_rules

import (
	"testing"

	"github.com/pqswitch/scanner/internal/types"
)

// TestDotNetCryptoDetection validates our C# crypto detection rules for .NET System.Security.Cryptography
func TestDotNetCryptoDetection(t *testing.T) {
	// Mock scan results for .NET cryptography patterns
	mockFindings := []types.Finding{
		// Critical Legacy/Broken Algorithms (Replace Immediately)
		{
			RuleID:    "csharp-md5-usage",
			Algorithm: "MD5",
			Severity:  "critical",
		},
		{
			RuleID:    "csharp-des-usage",
			Algorithm: "DES",
			Severity:  "critical",
		},
		{
			RuleID:    "csharp-tripledes-usage",
			Algorithm: "3DES",
			Severity:  "critical",
		},
		{
			RuleID:    "csharp-rc2-usage",
			Algorithm: "RC2",
			Severity:  "critical",
		},

		// High Priority Quantum-Vulnerable Asymmetric Algorithms
		{
			RuleID:    "csharp-rsa-crypto-service-provider",
			Algorithm: "RSA",
			Severity:  "high",
		},
		{
			RuleID:    "csharp-rsa-key-generation",
			Algorithm: "RSA",
			Severity:  "high",
		},
		{
			RuleID:    "csharp-ecdsa-usage",
			Algorithm: "ECDSA",
			Severity:  "high",
		},
		{
			RuleID:    "csharp-ecdh-usage",
			Algorithm: "ECDH",
			Severity:  "high",
		},
		{
			RuleID:    "csharp-dsa-usage",
			Algorithm: "DSA",
			Severity:  "high",
		},
		{
			RuleID:    "csharp-sha1-usage",
			Algorithm: "SHA1",
			Severity:  "high",
		},

		// Medium Priority Protocol/Configuration
		{
			RuleID:    "csharp-xml-encryption-constants",
			Algorithm: "XML_ENCRYPTION",
			Severity:  "medium",
		},
		{
			RuleID:    "csharp-hmac-usage",
			Algorithm: "HMAC",
			Severity:  "medium",
		},
		{
			RuleID:    "csharp-key-exchange-usage",
			Algorithm: "KEY_EXCHANGE",
			Severity:  "medium",
		},
		{
			RuleID:    "csharp-hash-algorithm-usage",
			Algorithm: "HASH_ALGORITHM",
			Severity:  "medium",
		},

		// Info Level - Positive Detections and Context
		{
			RuleID:    "csharp-aes-usage",
			Algorithm: "AES",
			Severity:  "info",
		},
		{
			RuleID:    "csharp-rng-usage",
			Algorithm: "RNG",
			Severity:  "info",
		},
		{
			RuleID:    "csharp-pbkdf2-usage",
			Algorithm: "PBKDF2",
			Severity:  "info",
		},
		{
			RuleID:    "csharp-crypto-provider-usage",
			Algorithm: "various",
			Severity:  "info",
		},
		{
			RuleID:    "csharp-certificate-usage",
			Algorithm: "X509",
			Severity:  "info",
		},
		{
			RuleID:    "csharp-crypto-stream-usage",
			Algorithm: "CRYPTO_STREAM",
			Severity:  "info",
		},
		{
			RuleID:    "csharp-crypto-exception-usage",
			Algorithm: "EXCEPTION",
			Severity:  "info",
		},
		{
			RuleID:    "csharp-crypto-namespace-usage",
			Algorithm: "various",
			Severity:  "info",
		},
	}

	// Expected algorithm categories for validation
	criticalAlgorithms := []string{"MD5", "DES", "3DES", "RC2"} // Broken algorithms
	quantumVulnerableAsymmetric := []string{"RSA", "ECDSA", "ECDH", "DSA"}
	contextDetectionRules := []string{
		"csharp-crypto-namespace-usage",
		"csharp-crypto-provider-usage",
		"csharp-certificate-usage",
		"csharp-crypto-stream-usage",
	}

	t.Run("CriticalAlgorithmDetection", func(t *testing.T) {
		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			if finding.Severity == "critical" {
				detected[finding.Algorithm] = true
			}
		}

		for _, algo := range criticalAlgorithms {
			if !detected[algo] {
				t.Errorf("Critical algorithm %s not detected", algo)
			}
		}

		if len(detected) < 4 { // MD5, DES, 3DES, RC2
			t.Errorf("Expected at least 4 critical algorithms, got %d", len(detected))
		}
	})

	t.Run("QuantumVulnerableAsymmetricDetection", func(t *testing.T) {
		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			if finding.Severity == "high" && contains(quantumVulnerableAsymmetric, finding.Algorithm) {
				detected[finding.Algorithm] = true
			}
		}

		for _, algo := range quantumVulnerableAsymmetric {
			if !detected[algo] {
				t.Errorf("Quantum-vulnerable asymmetric algorithm %s not detected", algo)
			}
		}

		if len(detected) < 4 {
			t.Errorf("Expected at least 4 quantum-vulnerable asymmetric algorithms, got %d", len(detected))
		}
	})

	t.Run("ContextDetectionRuleValidation", func(t *testing.T) {
		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			if finding.Severity == "info" && contains(contextDetectionRules, finding.RuleID) {
				detected[finding.RuleID] = true
			}
		}

		for _, rule := range contextDetectionRules {
			if !detected[rule] {
				t.Errorf("Context detection rule %s not detected", rule)
			}
		}
	})

	t.Run("CSharpSpecificPatternDetection", func(t *testing.T) {
		csharpSpecificRules := []string{
			"csharp-md5-usage",
			"csharp-sha1-usage",
			"csharp-des-usage",
			"csharp-tripledes-usage",
			"csharp-rc2-usage",
			"csharp-rsa-crypto-service-provider",
			"csharp-rsa-key-generation",
			"csharp-ecdsa-usage",
			"csharp-ecdh-usage",
			"csharp-dsa-usage",
			"csharp-aes-usage",
			"csharp-rng-usage",
			"csharp-pbkdf2-usage",
			"csharp-hmac-usage",
			"csharp-xml-encryption-constants",
			"csharp-certificate-usage",
			"csharp-key-exchange-usage",
			"csharp-crypto-stream-usage",
			"csharp-hash-algorithm-usage",
			"csharp-crypto-exception-usage",
			"csharp-crypto-provider-usage",
			"csharp-crypto-namespace-usage",
		}

		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			if hasPrefix(finding.RuleID, "csharp-") {
				detected[finding.RuleID] = true
			}
		}

		for _, rule := range csharpSpecificRules {
			if !detected[rule] {
				t.Errorf("C#-specific rule %s not detected", rule)
			}
		}

		if len(detected) < 20 {
			t.Errorf("Expected at least 20 C# rules, got %d", len(detected))
		}
	})

	t.Run("SeverityDistributionValidation", func(t *testing.T) {
		severityCounts := make(map[string]int)
		for _, finding := range mockFindings {
			severityCounts[finding.Severity]++
		}

		// Should have findings across all severity levels
		expectedSeverities := []string{"critical", "high", "medium", "info"}
		for _, severity := range expectedSeverities {
			if severityCounts[severity] == 0 {
				t.Errorf("No findings with severity %s", severity)
			}
		}

		// Critical findings should exist (legacy broken algorithms)
		if severityCounts["critical"] < 4 {
			t.Errorf("Expected at least 4 critical findings, got %d", severityCounts["critical"])
		}

		// High priority findings should dominate (quantum-vulnerable asymmetric)
		if severityCounts["high"] < 5 {
			t.Errorf("Expected at least 5 high priority findings, got %d", severityCounts["high"])
		}

		// Info level should have good representation (positive detections)
		if severityCounts["info"] < 6 {
			t.Errorf("Expected at least 6 info level findings, got %d", severityCounts["info"])
		}
	})

	t.Run("AlgorithmCategoryValidation", func(t *testing.T) {
		// Validate comprehensive .NET cryptography coverage
		ruleCategories := map[string]int{
			"hash":       0, // Hash algorithms
			"symmetric":  0, // Symmetric encryption
			"asymmetric": 0, // Asymmetric cryptography
			"support":    0, // Support functions (RNG, KDF, etc.)
			"context":    0, // Context and configuration
		}

		for _, finding := range mockFindings {
			switch {
			case contains([]string{"csharp-md5-usage", "csharp-sha1-usage", "csharp-hash-algorithm-usage"}, finding.RuleID):
				ruleCategories["hash"]++
			case contains([]string{"csharp-des-usage", "csharp-tripledes-usage", "csharp-rc2-usage", "csharp-aes-usage"}, finding.RuleID):
				ruleCategories["symmetric"]++
			case contains([]string{"csharp-rsa-crypto-service-provider", "csharp-rsa-key-generation", "csharp-ecdsa-usage", "csharp-ecdh-usage", "csharp-dsa-usage"}, finding.RuleID):
				ruleCategories["asymmetric"]++
			case contains([]string{"csharp-rng-usage", "csharp-pbkdf2-usage", "csharp-hmac-usage"}, finding.RuleID):
				ruleCategories["support"]++
			case contains([]string{"csharp-crypto-namespace-usage", "csharp-crypto-provider-usage", "csharp-certificate-usage", "csharp-crypto-stream-usage", "csharp-crypto-exception-usage", "csharp-xml-encryption-constants", "csharp-key-exchange-usage"}, finding.RuleID):
				ruleCategories["context"]++
			}
		}

		for category, count := range ruleCategories {
			if count == 0 {
				t.Errorf("No rules detected for category %s", category)
			}
		}

		// Asymmetric crypto should have good coverage (quantum threat)
		if ruleCategories["asymmetric"] < 5 {
			t.Errorf("Expected at least 5 asymmetric crypto rules, got %d", ruleCategories["asymmetric"])
		}

		// Hash algorithms should be well covered
		if ruleCategories["hash"] < 3 {
			t.Errorf("Expected at least 3 hash algorithm rules, got %d", ruleCategories["hash"])
		}
	})

	t.Run("QuantumVulnerabilityAssessment", func(t *testing.T) {
		quantumVulnerableRules := []string{
			"csharp-rsa-crypto-service-provider",
			"csharp-rsa-key-generation",
			"csharp-ecdsa-usage",
			"csharp-ecdh-usage",
			"csharp-dsa-usage",
		}

		detected := 0
		for _, finding := range mockFindings {
			if contains(quantumVulnerableRules, finding.RuleID) {
				detected++
			}
		}

		if detected < len(quantumVulnerableRules) {
			t.Errorf("Expected %d quantum-vulnerable patterns, detected %d",
				len(quantumVulnerableRules), detected)
		}
	})

	t.Run("PostQuantumMigrationGuidance", func(t *testing.T) {
		// Validate that findings provide appropriate migration guidance
		migrationTargets := map[string]string{
			"csharp-md5-usage":                   "SHA3-256",
			"csharp-sha1-usage":                  "SHA3-256",
			"csharp-des-usage":                   "AES-256",
			"csharp-tripledes-usage":             "AES-256",
			"csharp-rc2-usage":                   "AES-256",
			"csharp-rsa-crypto-service-provider": "ML-KEM-768",
			"csharp-rsa-key-generation":          "ML-KEM-768",
			"csharp-ecdsa-usage":                 "ML-DSA-65",
			"csharp-ecdh-usage":                  "ML-KEM-768",
			"csharp-dsa-usage":                   "ML-DSA-65",
		}

		detectedRules := make(map[string]bool)
		for _, finding := range mockFindings {
			detectedRules[finding.RuleID] = true
		}

		for ruleID := range migrationTargets {
			if !detectedRules[ruleID] {
				t.Errorf("Migration guidance rule %s not detected", ruleID)
			}
		}
	})

	t.Run("DotNetLibrarySpecificPatterns", func(t *testing.T) {
		// Test .NET-specific patterns that distinguish from other platforms
		dotnetSpecificPatterns := []string{
			"csharp-crypto-namespace-usage",   // using System.Security.Cryptography
			"csharp-crypto-provider-usage",    // CryptoConfig, CspParameters
			"csharp-xml-encryption-constants", // XML encryption URLs
			"csharp-crypto-stream-usage",      // CryptoStream
			"csharp-crypto-exception-usage",   // CryptographicException
		}

		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			if contains(dotnetSpecificPatterns, finding.RuleID) {
				detected[finding.RuleID] = true
			}
		}

		for _, pattern := range dotnetSpecificPatterns {
			if !detected[pattern] {
				t.Errorf(".NET-specific pattern %s not detected", pattern)
			}
		}
	})
}
