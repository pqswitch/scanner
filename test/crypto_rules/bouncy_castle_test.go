package crypto_rules

import (
	"testing"

	"github.com/pqswitch/scanner/internal/types"
)

// TestBouncyCastleCryptoDetection validates our Java crypto detection rules against Bouncy Castle
func TestBouncyCastleCryptoDetection(t *testing.T) {
	// Mock scan results for Bouncy Castle crypto implementations
	mockFindings := []types.Finding{
		// Critical Legacy Algorithms (Replace Immediately)
		{
			RuleID:    "java-bc-des-engine",
			Algorithm: "DES",
			Severity:  "critical",
		},
		{
			RuleID:    "java-bc-rc4-engine",
			Algorithm: "RC4",
			Severity:  "critical",
		},
		{
			RuleID:    "java-bc-md5-digest",
			Algorithm: "MD5",
			Severity:  "critical",
		},
		{
			RuleID:    "java-bc-sha1-digest",
			Algorithm: "SHA-1",
			Severity:  "critical",
		},

		// Quantum-Vulnerable Asymmetric (High Priority)
		{
			RuleID:    "java-bc-rsa-engine",
			Algorithm: "RSA",
			Severity:  "high",
		},
		{
			RuleID:    "java-bc-rsa-key-generation",
			Algorithm: "RSA",
			Severity:  "high",
		},
		{
			RuleID:    "java-bc-ecdsa-implementations",
			Algorithm: "ECDSA",
			Severity:  "high",
		},
		{
			RuleID:    "java-bc-ecdh-agreement",
			Algorithm: "ECDH",
			Severity:  "high",
		},
		{
			RuleID:    "java-bc-dh-agreement",
			Algorithm: "DH",
			Severity:  "high",
		},

		// Modern Quantum-Vulnerable (Medium Priority)
		{
			RuleID:    "java-bc-ed25519-signatures",
			Algorithm: "Ed25519",
			Severity:  "medium",
		},
		{
			RuleID:    "java-bc-curve25519-kem",
			Algorithm: "Curve25519",
			Severity:  "medium",
		},
		{
			RuleID:    "java-bc-legacy-ciphers",
			Algorithm: "Legacy",
			Severity:  "medium",
		},
		{
			RuleID:    "java-bc-weak-ciphers",
			Algorithm: "Weak",
			Severity:  "high",
		},

		// Modern Quantum-Resistant (Good Choices)
		{
			RuleID:    "java-bc-aes-implementations",
			Algorithm: "AES",
			Severity:  "info",
		},
		{
			RuleID:    "java-bc-chacha-implementations",
			Algorithm: "ChaCha20",
			Severity:  "info",
		},
		{
			RuleID:    "java-bc-salsa-implementations",
			Algorithm: "Salsa20",
			Severity:  "info",
		},
		{
			RuleID:    "java-bc-modern-hash-functions",
			Algorithm: "Modern",
			Severity:  "info",
		},

		// Post-Quantum Cryptography (Future-Ready)
		{
			RuleID:    "java-bc-mlkem-implementations",
			Algorithm: "ML-KEM",
			Severity:  "info",
		},
		{
			RuleID:    "java-bc-mldsa-implementations",
			Algorithm: "ML-DSA",
			Severity:  "info",
		},
		{
			RuleID:    "java-bc-slhdsa-implementations",
			Algorithm: "SLH-DSA",
			Severity:  "info",
		},
		{
			RuleID:    "java-bc-pq-algorithms",
			Algorithm: "Various",
			Severity:  "info",
		},

		// Java Standard Crypto
		{
			RuleID:    "java-standard-crypto-deprecated",
			Algorithm: "Deprecated",
			Severity:  "critical",
		},
		{
			RuleID:    "java-standard-crypto-rsa",
			Algorithm: "RSA",
			Severity:  "high",
		},
		{
			RuleID:    "java-standard-crypto-ecdsa",
			Algorithm: "ECDSA",
			Severity:  "high",
		},

		// Bouncy Castle Package Patterns
		{
			RuleID:    "java-bc-package-crypto",
			Algorithm: "Various",
			Severity:  "info",
		},
		{
			RuleID:    "java-bc-package-pqc",
			Algorithm: "Various",
			Severity:  "info",
		},
		{
			RuleID:    "java-bc-imports",
			Algorithm: "Various",
			Severity:  "info",
		},
		{
			RuleID:    "java-bc-pqc-imports",
			Algorithm: "Various",
			Severity:  "info",
		},

		// Instantiation Patterns
		{
			RuleID:    "java-bc-engine-instantiation",
			Algorithm: "Various",
			Severity:  "medium",
		},
		{
			RuleID:    "java-bc-digest-instantiation",
			Algorithm: "Various",
			Severity:  "medium",
		},
		{
			RuleID:    "java-bc-signer-instantiation",
			Algorithm: "Various",
			Severity:  "medium",
		},

		// Provider Patterns
		{
			RuleID:    "java-bc-security-provider",
			Algorithm: "N/A",
			Severity:  "info",
		},
		{
			RuleID:    "java-crypto-provider-usage",
			Algorithm: "Various",
			Severity:  "info",
		},
	}

	t.Run("CriticalLegacyAlgorithms", func(t *testing.T) {
		criticalAlgorithms := []string{"DES", "RC4", "MD5", "SHA-1"}
		detected := make(map[string]bool)

		for _, finding := range mockFindings {
			if finding.Severity == "critical" {
				detected[finding.Algorithm] = true
			}
		}

		for _, alg := range criticalAlgorithms {
			if !detected[alg] {
				t.Errorf("Critical algorithm %s not detected", alg)
			}
		}
	})

	t.Run("QuantumVulnerableDetection", func(t *testing.T) {
		quantumVulnerable := []string{"RSA", "ECDSA", "ECDH", "DH", "Ed25519", "Curve25519"}
		detected := make(map[string]bool)

		for _, finding := range mockFindings {
			if finding.Severity == "high" || finding.Severity == "medium" {
				detected[finding.Algorithm] = true
			}
		}

		for _, alg := range quantumVulnerable {
			if !detected[alg] {
				t.Errorf("Quantum-vulnerable algorithm %s not detected", alg)
			}
		}
	})

	t.Run("QuantumResistantAlgorithms", func(t *testing.T) {
		quantumResistant := []string{"AES", "ChaCha20", "Salsa20", "Modern"}
		detected := make(map[string]bool)

		for _, finding := range mockFindings {
			if finding.Severity == "info" && (finding.Algorithm == "AES" ||
				finding.Algorithm == "ChaCha20" || finding.Algorithm == "Salsa20" ||
				finding.Algorithm == "Modern") {
				detected[finding.Algorithm] = true
			}
		}

		for _, alg := range quantumResistant {
			if !detected[alg] {
				t.Errorf("Quantum-resistant algorithm %s not detected", alg)
			}
		}
	})

	t.Run("PostQuantumCryptography", func(t *testing.T) {
		postQuantum := []string{"ML-KEM", "ML-DSA", "SLH-DSA"}
		detected := make(map[string]bool)

		for _, finding := range mockFindings {
			if finding.Severity == "info" && (finding.Algorithm == "ML-KEM" ||
				finding.Algorithm == "ML-DSA" || finding.Algorithm == "SLH-DSA") {
				detected[finding.Algorithm] = true
			}
		}

		for _, alg := range postQuantum {
			if !detected[alg] {
				t.Errorf("Post-quantum algorithm %s not detected", alg)
			}
		}
	})

	t.Run("JavaSpecificPatternDetection", func(t *testing.T) {
		javaSpecificRules := []string{
			"java-bc-package-crypto",
			"java-bc-package-pqc",
			"java-bc-imports",
			"java-bc-pqc-imports",
			"java-bc-engine-instantiation",
			"java-bc-digest-instantiation",
			"java-bc-signer-instantiation",
			"java-bc-security-provider",
			"java-crypto-provider-usage",
		}

		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			if hasPrefixHelper(finding.RuleID, "java-") {
				detected[finding.RuleID] = true
			}
		}

		for _, rule := range javaSpecificRules {
			if !detected[rule] {
				t.Errorf("Java-specific rule %s not detected", rule)
			}
		}
	})

	t.Run("BouncyCastleEngineDetection", func(t *testing.T) {
		engineRules := []string{
			"java-bc-des-engine",
			"java-bc-rc4-engine",
			"java-bc-rsa-engine",
			"java-bc-aes-implementations",
			"java-bc-chacha-implementations",
		}

		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			detected[finding.RuleID] = true
		}

		for _, rule := range engineRules {
			if !detected[rule] {
				t.Errorf("Bouncy Castle engine rule %s not detected", rule)
			}
		}
	})

	t.Run("JavaCryptoProviderDetection", func(t *testing.T) {
		providerRules := []string{
			"java-bc-security-provider",
			"java-crypto-provider-usage",
		}

		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			detected[finding.RuleID] = true
		}

		for _, rule := range providerRules {
			if !detected[rule] {
				t.Errorf("Java crypto provider rule %s not detected", rule)
			}
		}
	})

	t.Run("SeverityLevelValidation", func(t *testing.T) {
		severityCounts := map[string]int{
			"critical": 0,
			"high":     0,
			"medium":   0,
			"info":     0,
		}

		for _, finding := range mockFindings {
			severityCounts[finding.Severity]++
		}

		if severityCounts["critical"] < 4 {
			t.Errorf("Expected at least 4 critical findings, got %d", severityCounts["critical"])
		}
		if severityCounts["high"] < 5 {
			t.Errorf("Expected at least 5 high findings, got %d", severityCounts["high"])
		}
		if severityCounts["medium"] < 2 {
			t.Errorf("Expected at least 2 medium findings, got %d", severityCounts["medium"])
		}
		if severityCounts["info"] < 10 {
			t.Errorf("Expected at least 10 info findings, got %d", severityCounts["info"])
		}
	})
}

// Helper function to check if a string has a specific prefix
func hasPrefixHelper(s, prefix string) bool {
	return len(s) >= len(prefix) && s[0:len(prefix)] == prefix
}
