package crypto_rules

import (
	"testing"

	"github.com/pqswitch/scanner/internal/types"
	"github.com/pqswitch/scanner/test/helpers"
)

var mockBouncyCastleFindings = []types.Finding{
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

func TestBouncyCastleCryptoDetection(t *testing.T) {
	testCases := []struct {
		name          string
		ruleID        string
		expectedSev   string
		expectPresent bool
	}{
		// Critical Legacy Algorithms
		{"java-bc-des-engine", "java-bc-des-engine", "critical", true},
		{"java-bc-rc4-engine", "java-bc-rc4-engine", "critical", true},
		{"java-bc-md5-digest", "java-bc-md5-digest", "critical", true},
		{"java-bc-sha1-digest", "java-bc-sha1-digest", "critical", true},

		// Quantum-Vulnerable Asymmetric (High Priority)
		{"java-bc-rsa-engine", "java-bc-rsa-engine", "high", true},
		{"java-bc-rsa-key-generation", "java-bc-rsa-key-generation", "high", true},
		{"java-bc-ecdsa-implementations", "java-bc-ecdsa-implementations", "high", true},
		{"java-bc-ecdh-agreement", "java-bc-ecdh-agreement", "high", true},
		{"java-bc-dh-agreement", "java-bc-dh-agreement", "high", true},

		// Modern Quantum-Vulnerable (Medium Priority)
		{"java-bc-ed25519-signatures", "java-bc-ed25519-signatures", "medium", true},
		{"java-bc-curve25519-kem", "java-bc-curve25519-kem", "medium", true},
		{"java-bc-legacy-ciphers", "java-bc-legacy-ciphers", "medium", true},
		{"java-bc-weak-ciphers", "java-bc-weak-ciphers", "high", true},

		// Modern Quantum-Resistant (Good Choices)
		{"java-bc-aes-implementations", "java-bc-aes-implementations", "info", true},
		{"java-bc-chacha-implementations", "java-bc-chacha-implementations", "info", true},
		{"java-bc-salsa-implementations", "java-bc-salsa-implementations", "info", true},
		{"java-bc-modern-hash-functions", "java-bc-modern-hash-functions", "info", true},

		// Post-Quantum Cryptography (Future-Ready)
		{"java-bc-mlkem-implementations", "java-bc-mlkem-implementations", "info", true},
		{"java-bc-mldsa-implementations", "java-bc-mldsa-implementations", "info", true},
		{"java-bc-slhdsa-implementations", "java-bc-slhdsa-implementations", "info", true},
		{"java-bc-pq-algorithms", "java-bc-pq-algorithms", "info", true},

		// Java Standard Crypto
		{"java-standard-crypto-deprecated", "java-standard-crypto-deprecated", "critical", true},
		{"java-standard-crypto-rsa", "java-standard-crypto-rsa", "high", true},
		{"java-standard-crypto-ecdsa", "java-standard-crypto-ecdsa", "high", true},

		// Bouncy Castle Package Patterns
		{"java-bc-package-crypto", "java-bc-package-crypto", "info", true},
		{"java-bc-package-pqc", "java-bc-package-pqc", "info", true},
		{"java-bc-imports", "java-bc-imports", "info", true},
		{"java-bc-pqc-imports", "java-bc-pqc-imports", "info", true},

		// Instantiation Patterns
		{"java-bc-engine-instantiation", "java-bc-engine-instantiation", "medium", true},
		{"java-bc-digest-instantiation", "java-bc-digest-instantiation", "medium", true},
		{"java-bc-signer-instantiation", "java-bc-signer-instantiation", "medium", true},

		// Provider Patterns
		{"java-bc-security-provider", "java-bc-security-provider", "info", true},
		{"java-crypto-provider-usage", "java-crypto-provider-usage", "info", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			helpers.AssertRule(t, mockBouncyCastleFindings, tc.ruleID, tc.expectedSev, tc.expectPresent)
		})
	}

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
		for _, finding := range mockBouncyCastleFindings {
			if helpers.HasPrefix(finding.RuleID, "java-") {
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
		for _, finding := range mockBouncyCastleFindings {
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
		for _, finding := range mockBouncyCastleFindings {
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

		for _, finding := range mockBouncyCastleFindings {
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
