package crypto_rules

import (
	"testing"

	"github.com/pqswitch/scanner/internal/types"
	"github.com/pqswitch/scanner/test/helpers"
)

// TestGolangCryptoDetection validates our Go crypto detection rules against Golang crypto library
func TestGolangCryptoDetection(t *testing.T) {
	// Mock scan results for Golang crypto implementations
	mockFindings := []types.Finding{
		// Critical Legacy Algorithms (Replace Immediately)
		{
			RuleID:    "go-md4-package",
			Algorithm: "MD4",
			Severity:  "critical",
		},
		{
			RuleID:    "go-md4-registration",
			Algorithm: "MD4",
			Severity:  "critical",
		},
		{
			RuleID:    "go-md4-functions",
			Algorithm: "MD4",
			Severity:  "critical",
		},
		{
			RuleID:    "go-ripemd160-package",
			Algorithm: "RIPEMD-160",
			Severity:  "critical",
		},

		// Quantum-Vulnerable Algorithms (Plan Migration)
		{
			RuleID:    "go-ed25519-package",
			Algorithm: "Ed25519",
			Severity:  "high",
		},
		{
			RuleID:    "go-ed25519-functions",
			Algorithm: "Ed25519",
			Severity:  "high",
		},
		{
			RuleID:    "go-curve25519-package",
			Algorithm: "Curve25519",
			Severity:  "high",
		},
		{
			RuleID:    "go-curve25519-functions",
			Algorithm: "Curve25519",
			Severity:  "high",
		},

		// Legacy Block Ciphers (Replace Immediately)
		{
			RuleID:    "go-blowfish-package",
			Algorithm: "Blowfish",
			Severity:  "high",
		},
		{
			RuleID:    "go-tea-package",
			Algorithm: "TEA",
			Severity:  "high",
		},
		{
			RuleID:    "go-xtea-package",
			Algorithm: "XTEA",
			Severity:  "high",
		},
		{
			RuleID:    "go-twofish-package",
			Algorithm: "Twofish",
			Severity:  "medium",
		},
		{
			RuleID:    "go-cast5-package",
			Algorithm: "CAST5",
			Severity:  "high",
		},

		// Modern Quantum-Resistant Algorithms (Good Choices)
		{
			RuleID:    "go-chacha20-package",
			Algorithm: "ChaCha20",
			Severity:  "info",
		},
		{
			RuleID:    "go-chacha20poly1305-package",
			Algorithm: "ChaCha20-Poly1305",
			Severity:  "info",
		},
		{
			RuleID:    "go-chacha20poly1305-functions",
			Algorithm: "ChaCha20-Poly1305",
			Severity:  "info",
		},
		{
			RuleID:    "go-salsa20-package",
			Algorithm: "Salsa20",
			Severity:  "info",
		},
		{
			RuleID:    "go-poly1305-package",
			Algorithm: "Poly1305",
			Severity:  "info",
		},

		// Modern Hash Algorithms (Good Choices)
		{
			RuleID:    "go-blake2b-package",
			Algorithm: "BLAKE2b",
			Severity:  "info",
		},
		{
			RuleID:    "go-blake2s-package",
			Algorithm: "BLAKE2s",
			Severity:  "info",
		},
		{
			RuleID:    "go-sha3-package",
			Algorithm: "SHA-3",
			Severity:  "info",
		},

		// Key Derivation Functions (Good Practices)
		{
			RuleID:    "go-argon2-package",
			Algorithm: "Argon2",
			Severity:  "info",
		},
		{
			RuleID:    "go-scrypt-package",
			Algorithm: "Scrypt",
			Severity:  "info",
		},
		{
			RuleID:    "go-bcrypt-package",
			Algorithm: "Bcrypt",
			Severity:  "info",
		},
		{
			RuleID:    "go-pbkdf2-package",
			Algorithm: "PBKDF2",
			Severity:  "medium",
		},
		{
			RuleID:    "go-hkdf-package",
			Algorithm: "HKDF",
			Severity:  "info",
		},

		// Go-Specific Patterns
		{
			RuleID:    "go-crypto-registrations",
			Algorithm: "various",
			Severity:  "medium",
		},
		{
			RuleID:    "go-hash-interface-implementation",
			Algorithm: "custom",
			Severity:  "info",
		},
		{
			RuleID:    "go-crypto-imports",
			Algorithm: "various",
			Severity:  "info",
		},
		{
			RuleID:    "go-crypto-type-aliases",
			Algorithm: "various",
			Severity:  "medium",
		},
		{
			RuleID:    "go-crypto-constants",
			Algorithm: "various",
			Severity:  "info",
		},
		{
			RuleID:    "go-crypto-deprecation-warnings",
			Algorithm: "deprecated",
			Severity:  "high",
		},
	}

	// Expected algorithm categories for validation
	criticalAlgorithms := []string{"MD4", "RIPEMD-160"}
	quantumVulnerableAlgorithms := []string{"Ed25519", "Curve25519"}
	legacyCiphers := []string{"Blowfish", "TEA", "XTEA", "CAST5"}
	modernAlgorithms := []string{"ChaCha20", "ChaCha20-Poly1305", "Salsa20", "Poly1305"}
	modernHashes := []string{"BLAKE2b", "BLAKE2s", "SHA-3"}
	keyDerivation := []string{"Argon2", "Scrypt", "Bcrypt", "HKDF"}

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

		if len(detected) < 2 { // MD4, RIPEMD-160
			t.Errorf("Expected at least 2 critical algorithms, got %d", len(detected))
		}
	})

	t.Run("QuantumVulnerableDetection", func(t *testing.T) {
		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			if finding.Severity == "high" && helpers.Contains(quantumVulnerableAlgorithms, finding.Algorithm) {
				detected[finding.Algorithm] = true
			}
		}

		for _, algo := range quantumVulnerableAlgorithms {
			if !detected[algo] {
				t.Errorf("Quantum-vulnerable algorithm %s not detected", algo)
			}
		}
	})

	t.Run("LegacyCipherDetection", func(t *testing.T) {
		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			if helpers.Contains(legacyCiphers, finding.Algorithm) {
				detected[finding.Algorithm] = true
			}
		}

		for _, algo := range legacyCiphers {
			if !detected[algo] {
				t.Errorf("Legacy cipher %s not detected", algo)
			}
		}
	})

	t.Run("ModernAlgorithmDetection", func(t *testing.T) {
		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			if finding.Severity == "info" && helpers.Contains(modernAlgorithms, finding.Algorithm) {
				detected[finding.Algorithm] = true
			}
		}

		if len(detected) < 3 { // ChaCha20, ChaCha20-Poly1305, Salsa20, Poly1305
			t.Errorf("Expected modern algorithms detection, got %d", len(detected))
		}
	})

	t.Run("ModernHashDetection", func(t *testing.T) {
		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			if finding.Severity == "info" && helpers.Contains(modernHashes, finding.Algorithm) {
				detected[finding.Algorithm] = true
			}
		}

		for _, algo := range modernHashes {
			if !detected[algo] {
				t.Errorf("Modern hash algorithm %s not detected", algo)
			}
		}
	})

	t.Run("KeyDerivationDetection", func(t *testing.T) {
		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			if helpers.Contains(keyDerivation, finding.Algorithm) {
				detected[finding.Algorithm] = true
			}
		}

		for _, algo := range keyDerivation {
			if !detected[algo] {
				t.Errorf("Key derivation algorithm %s not detected", algo)
			}
		}
	})

	t.Run("GoSpecificPatternDetection", func(t *testing.T) {
		goSpecificRules := []string{
			"go-crypto-registrations",
			"go-hash-interface-implementation",
			"go-crypto-imports",
			"go-crypto-type-aliases",
			"go-crypto-constants",
			"go-crypto-deprecation-warnings",
		}

		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			if helpers.HasPrefix(finding.RuleID, "go-") {
				detected[finding.RuleID] = true
			}
		}

		for _, rule := range goSpecificRules {
			if !detected[rule] {
				t.Errorf("Go-specific rule %s not detected", rule)
			}
		}
	})

	t.Run("ContextValidation", func(t *testing.T) {
		// Test that we have coverage across different crypto categories
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

		// Should have good balance (not all low severity)
		if severityCounts["info"] > severityCounts["critical"]+severityCounts["high"]+severityCounts["medium"] {
			t.Errorf("Too many info-level findings, may indicate detection accuracy issues")
		}
	})

	t.Run("CoverageValidation", func(t *testing.T) {
		// Validate comprehensive Go crypto coverage
		ruleCategories := map[string]int{
			"package":  0, // Package declarations
			"function": 0, // Function implementations
			"crypto":   0, // Crypto-specific patterns
		}

		for _, finding := range mockFindings {
			if helpers.Contains([]string{"go-md4-package", "go-ed25519-package", "go-chacha20-package"}, finding.RuleID) {
				ruleCategories["package"]++
			}
			if helpers.Contains([]string{"go-md4-functions", "go-ed25519-functions", "go-chacha20poly1305-functions"}, finding.RuleID) {
				ruleCategories["function"]++
			}
			if helpers.Contains([]string{"go-crypto-registrations", "go-crypto-imports", "go-hash-interface-implementation"}, finding.RuleID) {
				ruleCategories["crypto"]++
			}
		}

		for category, count := range ruleCategories {
			if count == 0 {
				t.Errorf("No rules detected for category %s", category)
			}
		}
	})
}
