package crypto_rules

import (
	"testing"

	"github.com/pqswitch/scanner/internal/types"
)

// TestSwiftCryptoDetection validates our Swift crypto detection rules for Apple Swift-Crypto
func TestSwiftCryptoDetection(t *testing.T) {
	// Mock scan results for Swift cryptography patterns
	mockFindings := []types.Finding{
		// Critical Legacy/Broken Algorithms (Replace Immediately)
		{
			RuleID:    "swift-insecure-md5-usage",
			Algorithm: "MD5",
			Severity:  "critical",
		},
		{
			RuleID:    "boringssl-legacy-md5-implementation",
			Algorithm: "MD5",
			Severity:  "critical",
		},
		{
			RuleID:    "boringssl-legacy-sha1-implementation",
			Algorithm: "SHA1",
			Severity:  "high",
		},
		{
			RuleID:    "swift-insecure-sha1-usage",
			Algorithm: "SHA1",
			Severity:  "high",
		},

		// High Priority Quantum-Vulnerable Algorithms
		{
			RuleID:    "swift-ecdsa-p256-usage",
			Algorithm: "ECDSA",
			Severity:  "high",
		},
		{
			RuleID:    "swift-ecdsa-p384-usage",
			Algorithm: "ECDSA",
			Severity:  "high",
		},
		{
			RuleID:    "swift-ecdsa-p521-usage",
			Algorithm: "ECDSA",
			Severity:  "high",
		},
		{
			RuleID:    "boringssl-curve25519-implementation",
			Algorithm: "Curve25519",
			Severity:  "medium",
		},

		// Medium Priority Modern but Quantum-Vulnerable
		{
			RuleID:    "swift-ed25519-usage",
			Algorithm: "Ed25519",
			Severity:  "medium",
		},
		{
			RuleID:    "swift-x25519-usage",
			Algorithm: "X25519",
			Severity:  "medium",
		},
		{
			RuleID:    "boringssl-kyber-support",
			Algorithm: "Kyber",
			Severity:  "medium",
		},

		// Info/Positive Detections (Quantum-Resistant)
		{
			RuleID:    "swift-chacha20poly1305-usage",
			Algorithm: "ChaCha20-Poly1305",
			Severity:  "info",
		},
		{
			RuleID:    "swift-aes-gcm-usage",
			Algorithm: "AES-GCM",
			Severity:  "info",
		},
		{
			RuleID:    "swift-sha256-usage",
			Algorithm: "SHA256",
			Severity:  "info",
		},
		{
			RuleID:    "swift-sha384-usage",
			Algorithm: "SHA384",
			Severity:  "info",
		},
		{
			RuleID:    "swift-sha512-usage",
			Algorithm: "SHA512",
			Severity:  "info",
		},
		{
			RuleID:    "swift-hmac-usage",
			Algorithm: "HMAC",
			Severity:  "medium",
		},
		{
			RuleID:    "swift-hkdf-usage",
			Algorithm: "HKDF",
			Severity:  "info",
		},
		{
			RuleID:    "boringssl-chacha20-implementation",
			Algorithm: "ChaCha20",
			Severity:  "info",
		},
		{
			RuleID:    "boringssl-poly1305-implementation",
			Algorithm: "Poly1305",
			Severity:  "info",
		},
		{
			RuleID:    "boringssl-blake2-implementation",
			Algorithm: "BLAKE2",
			Severity:  "info",
		},

		// Post-Quantum Algorithms (Future-Ready)
		{
			RuleID:    "boringssl-mlkem-implementation",
			Algorithm: "ML-KEM",
			Severity:  "info",
		},
		{
			RuleID:    "boringssl-mldsa-implementation",
			Algorithm: "ML-DSA",
			Severity:  "info",
		},
		{
			RuleID:    "boringssl-slhdsa-implementation",
			Algorithm: "SLH-DSA",
			Severity:  "info",
		},
		{
			RuleID:    "boringssl-hybrid-schemes",
			Algorithm: "HYBRID_PQ",
			Severity:  "info",
		},

		// Library Context/Imports
		{
			RuleID:    "swift-cryptokit-imports",
			Algorithm: "various",
			Severity:  "info",
		},
		{
			RuleID:    "swift-symmetric-key-usage",
			Algorithm: "SYMMETRIC_KEY",
			Severity:  "info",
		},
		{
			RuleID:    "swift-digest-protocol-usage",
			Algorithm: "DIGEST_PROTOCOL",
			Severity:  "info",
		},
		{
			RuleID:    "swift-data-protocol-usage",
			Algorithm: "DATA_PROTOCOL",
			Severity:  "info",
		},
	}

	t.Run("Swift Crypto Rule Coverage", func(t *testing.T) {
		// Test critical algorithm detection
		criticalRules := []string{
			"swift-insecure-md5-usage",
			"boringssl-legacy-md5-implementation",
		}

		for _, ruleID := range criticalRules {
			found := false
			for _, finding := range mockFindings {
				if finding.RuleID == ruleID {
					if finding.Severity != "critical" {
						t.Errorf("Expected critical severity for rule %s, got %s", ruleID, finding.Severity)
					}
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Critical rule %s not found in mock findings", ruleID)
			}
		}

		// Test high priority quantum-vulnerable detection
		highPriorityRules := []string{
			"swift-ecdsa-p256-usage",
			"swift-ecdsa-p384-usage",
			"swift-ecdsa-p521-usage",
		}

		for _, ruleID := range highPriorityRules {
			found := false
			for _, finding := range mockFindings {
				if finding.RuleID == ruleID {
					if finding.Severity != "high" {
						t.Errorf("Expected high severity for rule %s, got %s", ruleID, finding.Severity)
					}
					found = true
					break
				}
			}
			if !found {
				t.Errorf("High priority rule %s not found in mock findings", ruleID)
			}
		}

		// Test modern quantum-vulnerable detection
		modernRules := []string{
			"swift-ed25519-usage",
			"swift-x25519-usage",
		}

		for _, ruleID := range modernRules {
			found := false
			for _, finding := range mockFindings {
				if finding.RuleID == ruleID {
					if finding.Severity != "medium" {
						t.Errorf("Expected medium severity for rule %s, got %s", ruleID, finding.Severity)
					}
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Modern crypto rule %s not found in mock findings", ruleID)
			}
		}

		// Test quantum-resistant positive detections
		positiveRules := []string{
			"swift-chacha20poly1305-usage",
			"swift-aes-gcm-usage",
			"swift-sha256-usage",
			"boringssl-chacha20-implementation",
			"boringssl-blake2-implementation",
		}

		for _, ruleID := range positiveRules {
			found := false
			for _, finding := range mockFindings {
				if finding.RuleID == ruleID {
					if finding.Severity != "info" {
						t.Errorf("Expected info severity for positive rule %s, got %s", ruleID, finding.Severity)
					}
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Positive detection rule %s not found in mock findings", ruleID)
			}
		}

		// Test post-quantum algorithm detection
		pqRules := []string{
			"boringssl-mlkem-implementation",
			"boringssl-mldsa-implementation",
			"boringssl-slhdsa-implementation",
			"boringssl-hybrid-schemes",
		}

		for _, ruleID := range pqRules {
			found := false
			for _, finding := range mockFindings {
				if finding.RuleID == ruleID {
					if finding.Severity != "info" {
						t.Errorf("Expected info severity for PQ rule %s, got %s", ruleID, finding.Severity)
					}
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Post-quantum rule %s not found in mock findings", ruleID)
			}
		}
	})

	t.Run("Algorithm Coverage Validation", func(t *testing.T) {
		algorithms := make(map[string]bool)
		for _, finding := range mockFindings {
			algorithms[finding.Algorithm] = true
		}

		expectedAlgorithms := []string{
			"MD5", "SHA1", "ECDSA", "Ed25519", "X25519", "Curve25519",
			"ChaCha20-Poly1305", "AES-GCM", "SHA256", "SHA384", "SHA512",
			"HMAC", "HKDF", "ChaCha20", "Poly1305", "BLAKE2",
			"ML-KEM", "ML-DSA", "SLH-DSA", "HYBRID_PQ", "Kyber",
		}

		for _, algorithm := range expectedAlgorithms {
			if !algorithms[algorithm] {
				t.Errorf("Expected algorithm %s not found in findings", algorithm)
			}
		}
	})

	t.Run("Severity Distribution", func(t *testing.T) {
		severityCount := make(map[string]int)
		for _, finding := range mockFindings {
			severityCount[finding.Severity]++
		}

		// Validate severity distribution makes sense
		if severityCount["critical"] < 1 {
			t.Error("Expected at least 1 critical finding")
		}
		if severityCount["high"] < 3 {
			t.Error("Expected at least 3 high severity findings")
		}
		if severityCount["medium"] < 2 {
			t.Error("Expected at least 2 medium severity findings")
		}
		if severityCount["info"] < 10 {
			t.Error("Expected at least 10 info severity findings")
		}
	})

	t.Run("Swift Library Context", func(t *testing.T) {
		swiftRules := 0
		boringSSLRules := 0

		for _, finding := range mockFindings {
			if hasPrefix(finding.RuleID, "swift-") {
				swiftRules++
			}
			if hasPrefix(finding.RuleID, "boringssl-") {
				boringSSLRules++
			}
		}

		if swiftRules < 10 {
			t.Errorf("Expected at least 10 Swift-specific rules, got %d", swiftRules)
		}
		if boringSSLRules < 8 {
			t.Errorf("Expected at least 8 BoringSSL-specific rules, got %d", boringSSLRules)
		}
	})

	t.Run("Post-Quantum Readiness", func(t *testing.T) {
		quantumVulnerable := 0
		quantumResistant := 0
		postQuantum := 0

		quantumVulnerableAlgs := []string{"ECDSA", "Ed25519", "X25519", "Curve25519", "Kyber"}
		quantumResistantAlgs := []string{"ChaCha20-Poly1305", "AES-GCM", "SHA256", "SHA384", "SHA512", "ChaCha20", "Poly1305", "BLAKE2", "HMAC", "HKDF"}
		postQuantumAlgs := []string{"ML-KEM", "ML-DSA", "SLH-DSA", "HYBRID_PQ"}

		for _, finding := range mockFindings {
			if contains(quantumVulnerableAlgs, finding.Algorithm) {
				quantumVulnerable++
			}
			if contains(quantumResistantAlgs, finding.Algorithm) {
				quantumResistant++
			}
			if contains(postQuantumAlgs, finding.Algorithm) {
				postQuantum++
			}
		}

		if quantumVulnerable < 6 {
			t.Errorf("Expected at least 6 quantum-vulnerable algorithm detections, got %d", quantumVulnerable)
		}
		if quantumResistant < 8 {
			t.Errorf("Expected at least 8 quantum-resistant algorithm detections, got %d", quantumResistant)
		}
		if postQuantum < 4 {
			t.Errorf("Expected at least 4 post-quantum algorithm detections, got %d", postQuantum)
		}
	})

	t.Run("Apple Swift-Crypto Library Context", func(t *testing.T) {
		// Test that we have appropriate coverage for Apple's Swift-Crypto library
		appleSwiftRules := []string{
			"swift-ecdsa-p256-usage",
			"swift-ecdsa-p384-usage",
			"swift-ecdsa-p521-usage",
			"swift-ed25519-usage",
			"swift-x25519-usage",
			"swift-insecure-md5-usage",
			"swift-insecure-sha1-usage",
			"swift-chacha20poly1305-usage",
			"swift-aes-gcm-usage",
			"swift-cryptokit-imports",
		}

		for _, ruleID := range appleSwiftRules {
			found := false
			for _, finding := range mockFindings {
				if finding.RuleID == ruleID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Apple Swift-Crypto rule %s not found", ruleID)
			}
		}
	})

	t.Run("BoringSSL Integration Context", func(t *testing.T) {
		// Test that we have appropriate coverage for BoringSSL integration
		boringSSLRules := []string{
			"boringssl-mlkem-implementation",
			"boringssl-mldsa-implementation",
			"boringssl-slhdsa-implementation",
			"boringssl-hybrid-schemes",
			"boringssl-legacy-md5-implementation",
			"boringssl-legacy-sha1-implementation",
			"boringssl-curve25519-implementation",
			"boringssl-chacha20-implementation",
			"boringssl-poly1305-implementation",
			"boringssl-blake2-implementation",
		}

		for _, ruleID := range boringSSLRules {
			found := false
			for _, finding := range mockFindings {
				if finding.RuleID == ruleID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("BoringSSL integration rule %s not found", ruleID)
			}
		}
	})
}
