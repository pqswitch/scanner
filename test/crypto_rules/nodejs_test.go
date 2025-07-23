package crypto_rules

import (
	"context"
	"strings"
	"testing"

	"github.com/pqswitch/scanner/internal/config"
	"github.com/pqswitch/scanner/internal/scanner"
)

// TestNodeJSCryptoDetection tests JavaScript/Node.js crypto pattern detection
func TestNodeJSCryptoDetection(t *testing.T) {
	cfg := &config.Config{
		Scanner: config.ScannerConfig{
			MaxFileSize: 10485760,
			Parallel:    1,
		},
		Rules: config.RulesConfig{
			DefaultRulesPath: "../../internal/scanner/rules/crypto_rules.yaml",
		},
	}

	detector := scanner.NewLayeredDetector(cfg)
	err := detector.LoadRules(cfg.Rules.DefaultRulesPath)
	if err != nil {
		t.Fatalf("Failed to load rules: %v", err)
	}

	testCases := []struct {
		name          string
		content       string
		language      string
		expectedRules []string
		expectedAlgos []string
		minFindings   int
	}{
		// JavaScript Crypto Module Import Tests
		{
			name:          "Node.js crypto module require",
			content:       `const crypto = require('crypto');`,
			language:      "javascript",
			expectedRules: []string{"js-crypto-module-import"},
			expectedAlgos: []string{"UNKNOWN"},
			minFindings:   1,
		},
		{
			name:          "Node.js crypto module ES6 import",
			content:       `import crypto from 'crypto';`,
			language:      "javascript",
			expectedRules: []string{"js-crypto-module-import"},
			expectedAlgos: []string{"UNKNOWN"},
			minFindings:   1,
		},

		// JavaScript Internal Crypto Imports Tests
		{
			name:          "Node.js internal crypto hash import",
			content:       `const { Hash, Hmac } = require('internal/crypto/hash');`,
			language:      "javascript",
			expectedRules: []string{"js-internal-crypto-imports"},
			expectedAlgos: []string{"UNKNOWN"},
			minFindings:   1,
		},

		// JavaScript RSA Key Generation Tests
		{
			name:          "Node.js RSA key generation",
			content:       `crypto.generateKeyPair('rsa', { modulusLength: 2048 }, callback);`,
			language:      "javascript",
			expectedRules: []string{"js-rsa-key-generation"},
			expectedAlgos: []string{"RSA"},
			minFindings:   1,
		},

		// JavaScript RSA Cipher Usage Tests
		{
			name:          "Node.js RSA public encrypt",
			content:       `const encrypted = crypto.publicEncrypt(publicKey, buffer);`,
			language:      "javascript",
			expectedRules: []string{"js-rsa-cipher-usage"},
			expectedAlgos: []string{"RSA"},
			minFindings:   1,
		},

		// JavaScript Legacy Hash Usage Tests
		{
			name:          "Node.js MD5 hash creation",
			content:       `const hash = crypto.createHash('md5');`,
			language:      "javascript",
			expectedRules: []string{"js-legacy-hash-usage"},
			expectedAlgos: []string{"MD5"},
			minFindings:   1,
		},

		// JavaScript AES Cipher Usage Tests
		{
			name:          "Node.js AES cipher creation",
			content:       `const cipher = crypto.createCipher('aes192', password);`,
			language:      "javascript",
			expectedRules: []string{"js-aes-cipher-usage"},
			expectedAlgos: []string{"AES"},
			minFindings:   1,
		},

		// JavaScript WebCrypto API Usage Tests
		{
			name:          "WebCrypto subtle digest",
			content:       `const digest = await crypto.subtle.digest('SHA-256', data);`,
			language:      "javascript",
			expectedRules: []string{"js-webcrypto-usage"},
			expectedAlgos: []string{"UNKNOWN"},
			minFindings:   1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create file context
			fileCtx := &scanner.FileContext{
				FilePath: "test.js",
				Content:  []byte(tc.content),
				Language: tc.language,
			}

			// Analyze with layered detector
			result, err := detector.AnalyzeFile(context.TODO(), fileCtx)
			if err != nil {
				t.Fatalf("Analysis failed: %v", err)
			}

			if len(result.Findings) < tc.minFindings {
				t.Errorf("Expected at least %d findings, got %d", tc.minFindings, len(result.Findings))
				for i, finding := range result.Findings {
					t.Logf("Finding %d: %s - %s (%s)", i+1, finding.RuleID, finding.Message, finding.Algorithm)
				}
				return
			}

			// Check for expected rules
			foundRules := make(map[string]bool)
			foundAlgos := make(map[string]bool)

			for _, finding := range result.Findings {
				foundRules[finding.RuleID] = true
				if finding.Algorithm != "" && finding.Algorithm != "UNKNOWN" {
					foundAlgos[finding.Algorithm] = true
				}
			}

			for _, expectedRule := range tc.expectedRules {
				if !foundRules[expectedRule] {
					t.Errorf("Expected rule %s not found. Found rules: %v", expectedRule, getKeys(foundRules))
				}
			}

			for _, expectedAlgo := range tc.expectedAlgos {
				if expectedAlgo != "UNKNOWN" && !foundAlgos[expectedAlgo] {
					t.Errorf("Expected algorithm %s not found. Found algorithms: %v", expectedAlgo, getKeys(foundAlgos))
				}
			}

			// Log findings for debugging
			t.Logf("Test %s: Found %d findings", tc.name, len(result.Findings))
			for _, finding := range result.Findings {
				t.Logf("  - %s: %s (%s) [%s]", finding.RuleID, finding.Algorithm, finding.Severity, finding.CryptoType)
			}
		})
	}
}

// TestNodeJSCryptoAlgorithmCoverage tests coverage of major crypto algorithms in Node.js
func TestNodeJSCryptoAlgorithmCoverage(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		pattern   string
		code      string
		severity  string
	}{
		// Legacy algorithms (should be CRITICAL)
		{
			name:      "MD5 detection",
			algorithm: "MD5",
			pattern:   "js-legacy-hash-usage",
			code:      `const hash = crypto.createHash('md5');`,
			severity:  "critical",
		},

		// Quantum-vulnerable algorithms (should be HIGH)
		{
			name:      "RSA key generation",
			algorithm: "RSA",
			pattern:   "js-rsa-key-generation",
			code:      `crypto.generateKeyPair('rsa', { modulusLength: 2048 }, callback);`,
			severity:  "high",
		},

		// Modern but quantum-vulnerable (should be MEDIUM)
		{
			name:      "AES cipher usage",
			algorithm: "AES",
			pattern:   "js-aes-cipher-usage",
			code:      `const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);`,
			severity:  "medium",
		},
	}

	// Setup detector for algorithm coverage tests
	cfg2 := &config.Config{
		Scanner: config.ScannerConfig{
			MaxFileSize: 10485760,
			Parallel:    1,
		},
		Rules: config.RulesConfig{
			DefaultRulesPath: "../../internal/scanner/rules/crypto_rules.yaml",
		},
	}

	detector2 := scanner.NewLayeredDetector(cfg2)
	err2 := detector2.LoadRules(cfg2.Rules.DefaultRulesPath)
	if err2 != nil {
		t.Fatalf("Failed to load rules: %v", err2)
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create file context
			fileCtx := &scanner.FileContext{
				FilePath: "test.js",
				Content:  []byte(test.code),
				Language: "javascript",
			}

			// Analyze with layered detector
			result, err := detector2.AnalyzeFile(context.TODO(), fileCtx)
			if err != nil {
				t.Fatalf("Analysis failed: %v", err)
			}

			findings := result.Findings

			found := false
			for _, finding := range findings {
				if strings.Contains(finding.RuleID, test.pattern) {
					found = true
					if finding.Algorithm != test.algorithm {
						t.Errorf("Expected algorithm %s, got %s", test.algorithm, finding.Algorithm)
					}
					if finding.Severity != test.severity {
						t.Errorf("Expected severity %s, got %s for algorithm %s",
							test.severity, finding.Severity, test.algorithm)
					}
					break
				}
			}

			if !found {
				t.Errorf("Expected to find pattern %s for algorithm %s", test.pattern, test.algorithm)
			}
		})
	}
}
