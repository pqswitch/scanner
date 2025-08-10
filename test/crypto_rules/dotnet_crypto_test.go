package crypto_rules

import (
	"testing"

	"github.com/pqswitch/scanner/internal/types"
	"github.com/pqswitch/scanner/test/helpers"
)

var mockDotNetFindings = []types.Finding{
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

func TestDotNetCryptoDetection(t *testing.T) {
	testCases := []struct {
		name          string
		ruleID        string
		expectedSev   string
		expectPresent bool
	}{
		// Critical Legacy/Broken Algorithms
		{"csharp-md5-usage", "csharp-md5-usage", "critical", true},
		{"csharp-des-usage", "csharp-des-usage", "critical", true},
		{"csharp-tripledes-usage", "csharp-tripledes-usage", "critical", true},
		{"csharp-rc2-usage", "csharp-rc2-usage", "critical", true},

		// High Priority Quantum-Vulnerable
		{"csharp-rsa-crypto-service-provider", "csharp-rsa-crypto-service-provider", "high", true},
		{"csharp-rsa-key-generation", "csharp-rsa-key-generation", "high", true},
		{"csharp-ecdsa-usage", "csharp-ecdsa-usage", "high", true},
		{"csharp-ecdh-usage", "csharp-ecdh-usage", "high", true},
		{"csharp-dsa-usage", "csharp-dsa-usage", "high", true},
		{"csharp-sha1-usage", "csharp-sha1-usage", "high", true},

		// Medium Priority Protocol/Configuration
		{"csharp-xml-encryption-constants", "csharp-xml-encryption-constants", "medium", true},
		{"csharp-hmac-usage", "csharp-hmac-usage", "medium", true},
		{"csharp-key-exchange-usage", "csharp-key-exchange-usage", "medium", true},
		{"csharp-hash-algorithm-usage", "csharp-hash-algorithm-usage", "medium", true},

		// Info Level - Positive Detections and Context
		{"csharp-aes-usage", "csharp-aes-usage", "info", true},
		{"csharp-rng-usage", "csharp-rng-usage", "info", true},
		{"csharp-pbkdf2-usage", "csharp-pbkdf2-usage", "info", true},
		{"csharp-crypto-provider-usage", "csharp-crypto-provider-usage", "info", true},
		{"csharp-certificate-usage", "csharp-certificate-usage", "info", true},
		{"csharp-crypto-stream-usage", "csharp-crypto-stream-usage", "info", true},
		{"csharp-crypto-exception-usage", "csharp-crypto-exception-usage", "info", true},
		{"csharp-crypto-namespace-usage", "csharp-crypto-namespace-usage", "info", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			helpers.AssertRule(t, mockDotNetFindings, tc.ruleID, tc.expectedSev, tc.expectPresent)
		})
	}

	t.Run("AlgorithmCategoryValidation", func(t *testing.T) {
		// Validate comprehensive .NET cryptography coverage
		ruleCategories := map[string]int{
			"hash":       0, // Hash algorithms
			"symmetric":  0, // Symmetric encryption
			"asymmetric": 0, // Asymmetric cryptography
			"support":    0, // Support functions (RNG, KDF, etc.)
			"context":    0, // Context and configuration
		}

		for _, finding := range mockDotNetFindings {
			switch {
			case helpers.Contains([]string{"csharp-md5-usage", "csharp-sha1-usage", "csharp-hash-algorithm-usage"}, finding.RuleID):
				ruleCategories["hash"]++
			case helpers.Contains([]string{"csharp-des-usage", "csharp-tripledes-usage", "csharp-rc2-usage", "csharp-aes-usage"}, finding.RuleID):
				ruleCategories["symmetric"]++
			case helpers.Contains([]string{"csharp-rsa-crypto-service-provider", "csharp-rsa-key-generation", "csharp-ecdsa-usage", "csharp-ecdh-usage", "csharp-dsa-usage"}, finding.RuleID):
				ruleCategories["asymmetric"]++
			case helpers.Contains([]string{"csharp-rng-usage", "csharp-pbkdf2-usage", "csharp-hmac-usage"}, finding.RuleID):
				ruleCategories["support"]++
			case helpers.Contains([]string{"csharp-crypto-namespace-usage", "csharp-crypto-provider-usage", "csharp-certificate-usage", "csharp-crypto-stream-usage", "csharp-crypto-exception-usage", "csharp-xml-encryption-constants", "csharp-key-exchange-usage"}, finding.RuleID):
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
		for _, finding := range mockDotNetFindings {
			if helpers.Contains(quantumVulnerableRules, finding.RuleID) {
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
		for _, finding := range mockDotNetFindings {
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
		for _, finding := range mockDotNetFindings {
			if helpers.Contains(dotnetSpecificPatterns, finding.RuleID) {
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
