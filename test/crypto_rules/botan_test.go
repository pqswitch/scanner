package crypto_rules

import (
	"context"
	"testing"

	"github.com/pqswitch/scanner/internal/config"
	"github.com/pqswitch/scanner/internal/scanner"
)

func TestBotanCppCryptoDetection(t *testing.T) {
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
		{
			name:     "Botan MD5 Class Definition",
			content:  "class MD5 final : public HashFunction {\npublic:\n    std::string name() const override { return \"MD5\"; }\n};",
			language: "cpp",
			expectedRules: []string{
				"cpp-md5-class",
				"cpp-hash-return-strings",
			},
			expectedAlgos: []string{"MD5"},
			minFindings:   2,
		},
		{
			name:     "Botan RSA Classes",
			content:  "class RSA_PublicKey : public virtual Public_Key {\npublic:\n    std::string algo_name() const override { return \"RSA\"; }\n};\n\nclass RSA_PrivateKey final : public Private_Key, public RSA_PublicKey {",
			language: "cpp",
			expectedRules: []string{
				"cpp-rsa-class",
				"cpp-legacy-algo-returns",
			},
			expectedAlgos: []string{"RSA"},
			minFindings:   2,
		},
		{
			name:     "Botan AES Implementation",
			content:  "class AES_128 final : public Block_Cipher_Fixed_Params<16, 16> {\npublic:\n    std::string name() const override { return \"AES-128\"; }\n};",
			language: "cpp",
			expectedRules: []string{
				"cpp-aes-class",
				"cpp-cipher-return-strings",
			},
			expectedAlgos: []string{"AES"},
			minFindings:   2,
		},
		{
			name:     "Botan ECDSA Implementation",
			content:  "class ECDSA_PublicKey : public virtual EC_PublicKey {\npublic:\n    std::string algo_name() const override { return \"ECDSA\"; }\n};",
			language: "cpp",
			expectedRules: []string{
				"cpp-ecdsa-class",
				"cpp-legacy-algo-returns",
			},
			expectedAlgos: []string{"ECDSA"},
			minFindings:   2,
		},
		{
			name:     "Botan Post-Quantum Dilithium",
			content:  "class Dilithium_PublicKey final : public virtual Public_Key {\npublic:\n    std::string algo_name() const override { return \"Dilithium\"; }\n};",
			language: "cpp",
			expectedRules: []string{
				"cpp-dilithium-class",
				"cpp-post-quantum-returns",
			},
			expectedAlgos: []string{"Dilithium"},
			minFindings:   2,
		},
		{
			name:     "Botan Modern Curves",
			content:  "class Ed25519_PublicKey final : public virtual Public_Key {\npublic:\n    std::string name() const override { return \"Ed25519\"; }\n};",
			language: "cpp",
			expectedRules: []string{
				"cpp-ed25519-class",
				"cpp-modern-curve-returns",
			},
			expectedAlgos: []string{"Ed25519"},
			minFindings:   2,
		},
		{
			name:     "Botan Header Guards",
			content:  "#ifndef BOTAN_AES_H_\n#define BOTAN_AES_H_\n\nnamespace Botan {\n\nclass AES_128 {\n};\n\n} // namespace Botan\n\n#endif",
			language: "cpp",
			expectedRules: []string{
				"cpp-crypto-header-guards",
				"cpp-crypto-namespaces",
			},
			expectedAlgos: []string{"AES"},
			minFindings:   2,
		},
		{
			name:     "Modern Stream Ciphers",
			content:  "class ChaCha20 final : public StreamCipher {\npublic:\n    std::string name() const override { return \"ChaCha20\"; }\n};\n\nclass Salsa20 final : public StreamCipher {",
			language: "cpp",
			expectedRules: []string{
				"cpp-chacha-class",
				"cpp-salsa-class",
			},
			expectedAlgos: []string{"ChaCha20", "Salsa20"},
			minFindings:   2,
		},
		{
			name:     "Broken Stream Cipher",
			content:  "class RC4 final : public StreamCipher {\npublic:\n    std::string name() const override { return \"RC4\"; }\n};",
			language: "cpp",
			expectedRules: []string{
				"cpp-rc4-class",
				"cpp-cipher-return-strings",
			},
			expectedAlgos: []string{"RC4"},
			minFindings:   2,
		},
		{
			name:     "Crypto Method Implementations",
			content:  "void AES::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {\n}\n\nvoid RSA::decrypt_n(const uint8_t in[], uint8_t out[]) const {\n}",
			language: "cpp",
			expectedRules: []string{
				"cpp-encrypt-decrypt-methods",
			},
			expectedAlgos: []string{"various"},
			minFindings:   1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create file context
			fileCtx := &scanner.FileContext{
				FilePath: "test.cpp",
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
				if !foundAlgos[expectedAlgo] {
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

func TestBotanContextDetection(t *testing.T) {
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

	// Test that Botan context is properly detected
	content := `
#ifndef BOTAN_MD5_H_
#define BOTAN_MD5_H_

namespace Botan {

/**
 * MD5 hash function - Legacy algorithm
 */
class MD5 final : public HashFunction {
public:
    std::string name() const override { return "MD5"; }
    
    void hash_final(uint8_t output[]) {
        // Botan implementation details
    }
};

} // namespace Botan

#endif
`

	fileCtx := &scanner.FileContext{
		FilePath: "botan/src/lib/hash/md5/md5.h",
		Content:  []byte(content),
		Language: "cpp",
	}

	result, err := detector.AnalyzeFile(context.TODO(), fileCtx)
	if err != nil {
		t.Fatalf("Analysis failed: %v", err)
	}

	if len(result.Findings) == 0 {
		t.Fatal("Expected findings but got none")
	}

	// Should detect multiple patterns
	expectedPatterns := map[string]bool{
		"cpp-crypto-header-guards": false,
		"cpp-crypto-namespaces":    false,
		"cpp-md5-class":            false,
		"cpp-hash-return-strings":  false,
	}

	for _, finding := range result.Findings {
		if _, exists := expectedPatterns[finding.RuleID]; exists {
			expectedPatterns[finding.RuleID] = true
		}
		t.Logf("Found: %s - %s (%s)", finding.RuleID, finding.Algorithm, finding.Severity)
	}

	for pattern, found := range expectedPatterns {
		if !found {
			t.Errorf("Expected pattern %s not found", pattern)
		}
	}
}

// Helper function to get keys from a map
func getKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
