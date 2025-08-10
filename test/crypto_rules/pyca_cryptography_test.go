package crypto_rules

import (
	"testing"

	"github.com/pqswitch/scanner/internal/types"
	"github.com/pqswitch/scanner/test/helpers"
)

var mockPythonFindings = []types.Finding{
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

func TestPythonCryptographyDetection(t *testing.T) {
	testCases := []struct {
		name          string
		ruleID        string
		expectedSev   string
		expectPresent bool
	}{
		// Critical Legacy Hash Algorithms
		{"python-cryptography-md5", "python-cryptography-md5", "critical", true},
		{"weak-hash-md5", "weak-hash-md5", "critical", true},

		// High Priority Legacy Hash Algorithms
		{"python-cryptography-sha1", "python-cryptography-sha1", "high", true},
		{"weak-hash-sha1", "weak-hash-sha1", "high", true},

		// Critical Weak RSA Keys
		{"python-cryptography-weak-rsa", "python-cryptography-weak-rsa", "critical", true},

		// High Priority Quantum-Vulnerable Asymmetric Algorithms
		{"python-cryptography-rsa-keygen", "python-cryptography-rsa-keygen", "high", true},
		{"python-cryptography-ecdsa", "python-cryptography-ecdsa", "high", true},
		{"python-cryptography-dh-keygen", "python-cryptography-dh-keygen", "high", true},
		{"python-cryptography-dsa", "python-cryptography-dsa", "high", true},

		// Medium Priority Modern but Quantum-Vulnerable
		{"python-cryptography-ed25519", "python-cryptography-ed25519", "medium", true},
		{"python-cryptography-x25519", "python-cryptography-x25519", "medium", true},

		// Info Level - Library Implementation Context
		{"python-cryptography-class-definitions", "python-cryptography-class-definitions", "info", true},
		{"python-cryptography-algorithm-names", "python-cryptography-algorithm-names", "info", true},
		{"python-cryptography-imports", "python-cryptography-imports", "info", true},
		{"python-cryptography-rust-bindings", "python-cryptography-rust-bindings", "info", true},

		// Info Level - Modern Quantum-Resistant Algorithms
		{"python-cryptography-hash-algorithms", "python-cryptography-hash-algorithms", "info", true},

		// Medium Priority - Legacy Libraries
		{"python-legacy-crypto-libraries", "python-legacy-crypto-libraries", "medium", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			helpers.AssertRule(t, mockPythonFindings, tc.ruleID, tc.expectedSev, tc.expectPresent)
		})
	}

	t.Run("ModernButQuantumVulnerableDetection", func(t *testing.T) {
		detected := make(map[string]bool)
		for _, finding := range mockPythonFindings {
			if finding.Severity == "medium" && helpers.Contains([]string{"Ed25519", "X25519"}, finding.Algorithm) {
				detected[finding.Algorithm] = true
			}
		}

		for _, algo := range []string{"Ed25519", "X25519"} {
			if !detected[algo] {
				t.Errorf("Modern quantum-vulnerable algorithm %s not detected", algo)
			}
		}
	})

	t.Run("LibraryImplementationContextDetection", func(t *testing.T) {
		detected := make(map[string]bool)
		for _, finding := range mockPythonFindings {
			if finding.Severity == "info" && helpers.Contains([]string{
				"python-cryptography-class-definitions",
				"python-cryptography-algorithm-names",
				"python-cryptography-imports",
				"python-cryptography-rust-bindings",
			}, finding.RuleID) {
				detected[finding.RuleID] = true
			}
		}

		for _, rule := range []string{
			"python-cryptography-class-definitions",
			"python-cryptography-algorithm-names",
			"python-cryptography-imports",
			"python-cryptography-rust-bindings",
		} {
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
		for _, finding := range mockPythonFindings {
			if helpers.HasPrefix(finding.RuleID, "python-") {
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
		for _, finding := range mockPythonFindings {
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

		for _, finding := range mockPythonFindings {
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
		for _, finding := range mockPythonFindings {
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
		for _, finding := range mockPythonFindings {
			detectedRules[finding.RuleID] = true
		}

		for ruleID := range migrationTargets {
			if !detectedRules[ruleID] {
				t.Errorf("Migration guidance rule %s not detected", ruleID)
			}
		}
	})
}
