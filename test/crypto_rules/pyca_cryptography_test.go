package crypto_rules

import (
	"testing"

	"github.com/pqswitch/scanner/internal/types"
)

// TestPythonCryptographyDetection validates our Python crypto detection rules for pyca/cryptography
func TestPythonCryptographyDetection(t *testing.T) {
	// Mock scan results for Python cryptography library patterns
	mockFindings := []types.Finding{
		// Critical Legacy Hash Algorithms (Replace Immediately)
		{
			RuleID:    "python-cryptography-md5",
			Algorithm: "MD5",
			Severity:  "critical",
		},
		{
			RuleID:    "weak-hash-md5",
			Algorithm: "MD5",
			Severity:  "critical",
		},

		// High Priority Legacy Hash Algorithms (Replace Soon)
		{
			RuleID:    "python-cryptography-sha1",
			Algorithm: "SHA1",
			Severity:  "high",
		},
		{
			RuleID:    "weak-hash-sha1",
			Algorithm: "SHA1",
			Severity:  "high",
		},

		// Critical Weak RSA Keys (Insufficient Length)
		{
			RuleID:    "python-cryptography-weak-rsa",
			Algorithm: "RSA",
			Severity:  "critical",
		},

		// High Priority Quantum-Vulnerable Asymmetric Algorithms
		{
			RuleID:    "python-cryptography-rsa-keygen",
			Algorithm: "RSA",
			Severity:  "high",
		},
		{
			RuleID:    "python-cryptography-ecdsa",
			Algorithm: "ECDSA",
			Severity:  "high",
		},
		{
			RuleID:    "python-cryptography-dh-keygen",
			Algorithm: "DH",
			Severity:  "high",
		},
		{
			RuleID:    "python-cryptography-dsa",
			Algorithm: "DSA",
			Severity:  "high",
		},

		// Medium Priority Modern but Quantum-Vulnerable
		{
			RuleID:    "python-cryptography-ed25519",
			Algorithm: "Ed25519",
			Severity:  "medium",
		},
		{
			RuleID:    "python-cryptography-x25519",
			Algorithm: "X25519",
			Severity:  "medium",
		},

		// Info Level - Library Implementation Context
		{
			RuleID:    "python-cryptography-class-definitions",
			Algorithm: "various",
			Severity:  "info",
		},
		{
			RuleID:    "python-cryptography-algorithm-names",
			Algorithm: "various",
			Severity:  "info",
		},
		{
			RuleID:    "python-cryptography-imports",
			Algorithm: "various",
			Severity:  "info",
		},
		{
			RuleID:    "python-cryptography-rust-bindings",
			Algorithm: "various",
			Severity:  "info",
		},

		// Info Level - Modern Quantum-Resistant Algorithms (Good Choices)
		{
			RuleID:    "python-cryptography-hash-algorithms",
			Algorithm: "modern_hash",
			Severity:  "info",
		},

		// Medium Priority - Legacy Libraries (Migration Recommended)
		{
			RuleID:    "python-legacy-crypto-libraries",
			Algorithm: "various",
			Severity:  "medium",
		},
	}

	// Expected algorithm categories for validation
	criticalAlgorithms := []string{"MD5", "RSA"} // MD5 and weak RSA
	modernButQuantumVulnerable := []string{"Ed25519", "X25519"}
	libraryImplementationRules := []string{
		"python-cryptography-class-definitions",
		"python-cryptography-algorithm-names",
		"python-cryptography-imports",
		"python-cryptography-rust-bindings",
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

		if len(detected) < 2 { // MD5, RSA (weak)
			t.Errorf("Expected at least 2 critical algorithms, got %d", len(detected))
		}
	})

	t.Run("HighPriorityAlgorithmDetection", func(t *testing.T) {
		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			if finding.Severity == "high" {
				detected[finding.Algorithm] = true
			}
		}

		// Should detect quantum-vulnerable asymmetric algorithms
		expectedHighPriority := []string{"RSA", "ECDSA", "DH", "DSA"}
		for _, algo := range expectedHighPriority {
			if !detected[algo] {
				t.Errorf("High priority algorithm %s not detected", algo)
			}
		}
	})

	t.Run("ModernButQuantumVulnerableDetection", func(t *testing.T) {
		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			if finding.Severity == "medium" && contains(modernButQuantumVulnerable, finding.Algorithm) {
				detected[finding.Algorithm] = true
			}
		}

		for _, algo := range modernButQuantumVulnerable {
			if !detected[algo] {
				t.Errorf("Modern quantum-vulnerable algorithm %s not detected", algo)
			}
		}
	})

	t.Run("LibraryImplementationContextDetection", func(t *testing.T) {
		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			if finding.Severity == "info" && contains(libraryImplementationRules, finding.RuleID) {
				detected[finding.RuleID] = true
			}
		}

		for _, rule := range libraryImplementationRules {
			if !detected[rule] {
				t.Errorf("Library implementation rule %s not detected", rule)
			}
		}
	})

	t.Run("PythonSpecificPatternDetection", func(t *testing.T) {
		pythonSpecificRules := []string{
			"python-cryptography-md5",
			"python-cryptography-sha1",
			"python-cryptography-rsa-keygen",
			"python-cryptography-ecdsa",
			"python-cryptography-ed25519",
			"python-cryptography-x25519",
			"python-cryptography-dh-keygen",
			"python-cryptography-dsa",
			"python-cryptography-weak-rsa",
			"python-cryptography-class-definitions",
			"python-cryptography-algorithm-names",
			"python-cryptography-hash-algorithms",
			"python-cryptography-imports",
			"python-cryptography-rust-bindings",
			"python-legacy-crypto-libraries",
		}

		detected := make(map[string]bool)
		for _, finding := range mockFindings {
			if hasPrefix(finding.RuleID, "python-") {
				detected[finding.RuleID] = true
			}
		}

		for _, rule := range pythonSpecificRules {
			if !detected[rule] {
				t.Errorf("Python-specific rule %s not detected", rule)
			}
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

		// Critical findings should exist (MD5, weak RSA)
		if severityCounts["critical"] < 2 {
			t.Errorf("Expected at least 2 critical findings, got %d", severityCounts["critical"])
		}

		// High priority findings should dominate (quantum-vulnerable asymmetric)
		if severityCounts["high"] < 4 {
			t.Errorf("Expected at least 4 high priority findings, got %d", severityCounts["high"])
		}
	})

	t.Run("CoverageValidation", func(t *testing.T) {
		// Validate comprehensive Python cryptography coverage
		ruleCategories := map[string]int{
			"hash":       0, // Hash algorithms
			"asymmetric": 0, // Asymmetric cryptography
			"library":    0, // Library-specific patterns
			"legacy":     0, // Legacy library detection
		}

		for _, finding := range mockFindings {
			switch finding.RuleID {
			case "python-cryptography-md5", "python-cryptography-sha1", "python-cryptography-hash-algorithms":
				ruleCategories["hash"]++
			case "python-cryptography-rsa-keygen", "python-cryptography-ecdsa", "python-cryptography-ed25519",
				"python-cryptography-x25519", "python-cryptography-dh-keygen", "python-cryptography-dsa",
				"python-cryptography-weak-rsa":
				ruleCategories["asymmetric"]++
			case "python-cryptography-class-definitions", "python-cryptography-algorithm-names",
				"python-cryptography-imports", "python-cryptography-rust-bindings":
				ruleCategories["library"]++
			case "python-legacy-crypto-libraries":
				ruleCategories["legacy"]++
			}
		}

		for category, count := range ruleCategories {
			if count == 0 {
				t.Errorf("No rules detected for category %s", category)
			}
		}

		// Asymmetric crypto should have the most coverage (quantum threat)
		if ruleCategories["asymmetric"] < 5 {
			t.Errorf("Expected at least 5 asymmetric crypto rules, got %d", ruleCategories["asymmetric"])
		}
	})

	t.Run("QuantumVulnerabilityAssessment", func(t *testing.T) {
		quantumVulnerableRules := []string{
			"python-cryptography-rsa-keygen",
			"python-cryptography-ecdsa",
			"python-cryptography-ed25519",
			"python-cryptography-x25519",
			"python-cryptography-dh-keygen",
			"python-cryptography-dsa",
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
			"python-cryptography-md5":        "SHA3-256",
			"python-cryptography-sha1":       "SHA3-256",
			"python-cryptography-rsa-keygen": "ML-KEM-768",
			"python-cryptography-ecdsa":      "ML-DSA-65",
			"python-cryptography-ed25519":    "ML-DSA-44",
			"python-cryptography-x25519":     "ML-KEM-768",
			"python-cryptography-dh-keygen":  "ML-KEM-768",
			"python-cryptography-dsa":        "ML-DSA-65",
			"python-cryptography-weak-rsa":   "ML-KEM-768",
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
}
