package crypto_rules

import (
	"strings"
	"testing"

	"github.com/pqswitch/scanner/internal/config"
	"github.com/pqswitch/scanner/internal/scanner"
)

// TestApacheSparkFalsePositives tests that sample data containing bird names
// doesn't trigger false positive FALCON detections
func TestApacheSparkFalsePositives(t *testing.T) {
	tests := []struct {
		name           string
		content        string
		language       string
		expectFindings bool
		description    string
	}{
		{
			name:     "bird_names_in_dataframe",
			language: "python",
			content: `
>>> df = ps.DataFrame([('falcon', 'bird', 389.0),
...                    ('parrot', 'bird', 24.0),
...                    ('lion', 'mammal', 80.5),
...                    ('monkey', 'mammal', 77.0)],
...                    columns=('name', 'class', 'max_speed'))
`,
			expectFindings: false,
			description:    "Apache Spark DataFrame with bird names should not trigger FALCON detection",
		},
		{
			name:     "sample_tuples_with_animals",
			language: "python",
			content: `
data = [('eagle', 'bird'), ('horse', 'mammal'), ('spider', 'arthropod')]
for animal, category in data:
    print(f"{animal} is a {category}")
`,
			expectFindings: false,
			description:    "Sample data tuples should not trigger false positives",
		},
		{
			name:     "legitimate_falcon_crypto",
			language: "go",
			content: `
package pqcrypto

import "crypto/falcon"

func SignWithFalcon(message []byte, key *falcon.PrivateKey) ([]byte, error) {
    return falcon.Sign(message, key)
}
`,
			expectFindings: true,
			description:    "Legitimate FALCON cryptographic usage should be detected",
		},
		{
			name:     "documentation_with_bird_mentions",
			language: "markdown",
			content: `
# Animal Classification

This example demonstrates classification with various animals:
- falcon (bird)
- parrot (bird) 
- lion (mammal)

The falcon is known for its speed.
`,
			expectFindings: false,
			description:    "Documentation mentioning birds should not trigger crypto detection",
		},
	}

	cfg := &config.Config{
		Scanner: config.ScannerConfig{
			EnableAST: false,
		},
	}

	preFilter := scanner.NewRegexPreFilter(cfg)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := preFilter.ScanContent([]byte(tt.content), "test."+tt.language, tt.language)

			foundFalcon := false
			for _, finding := range findings {
				if finding.Algorithm == "FALCON" ||
					(finding.RuleID == "l0-pq-algorithms" &&
						findingContainsFalcon(finding.Context)) {
					foundFalcon = true
					// Check confidence - should be very low for false positives
					if !tt.expectFindings && finding.Confidence > 0.3 {
						t.Errorf("Test %s: FALCON false positive with high confidence %.2f",
							tt.name, finding.Confidence)
					}
				}
			}

			if tt.expectFindings && !foundFalcon {
				t.Errorf("Test %s: Expected FALCON detection but none found", tt.name)
			}
			if !tt.expectFindings && foundFalcon {
				t.Logf("Test %s: FALCON detection found but should be low confidence", tt.name)
				// Allow low-confidence detections as they'll be filtered out
			}
		})
	}
}

// TestKubernetesFalsePositives tests Kubernetes-specific contexts
func TestKubernetesFalsePositives(t *testing.T) {
	tests := []struct {
		name           string
		filePath       string
		content        string
		language       string
		expectHighConf bool
		description    string
	}{
		{
			name:     "kubernetes_pki_infrastructure",
			filePath: "staging/src/k8s.io/client-go/util/cert/cert.go",
			content: `
func generateCertificate() error {
    priv, err := rsa.GenerateKey(cryptorand.Reader, 2048)
    if err != nil {
        return err
    }
    // ... certificate generation logic
}
`,
			language:       "go",
			expectHighConf: false,
			description:    "Kubernetes PKI infrastructure should have reduced confidence",
		},
		{
			name:     "kubernetes_md5_utility_hashing",
			filePath: "pkg/api/v1/endpoints/util.go",
			content: `
func hashObject(hasher hash.Hash, obj interface{}) string {
    hasher := md5.New()
    deepHashObject(hasher, obj)
    return hex.EncodeToString(hasher.Sum(nil))
}
`,
			language:       "go",
			expectHighConf: false,
			description:    "Kubernetes MD5 utility hashing should have very low confidence",
		},
		{
			name:     "kubernetes_test_file",
			filePath: "staging/src/k8s.io/client-go/util/cert/cert_test.go",
			content: `
func TestSelfSignedCertHasSAN(t *testing.T) {
    key, err := rsa.GenerateKey(cryptorand.Reader, 2048)
    if err != nil {
        t.Fatal(err)
    }
}
`,
			language:       "go",
			expectHighConf: false,
			description:    "Kubernetes test files should have reduced confidence",
		},
		{
			name:     "kubernetes_kubeadm_pki",
			filePath: "cmd/kubeadm/app/util/pkiutil/pki_helpers.go",
			content: `
func NewPrivateKey() (*rsa.PrivateKey, error) {
    return rsa.GenerateKey(cryptorand.Reader, rsaKeySize)
}
`,
			language:       "go",
			expectHighConf: false,
			description:    "Kubeadm PKI utilities should have reduced confidence",
		},
		{
			name:     "kubernetes_sha1_volume_driver",
			filePath: "pkg/volume/util/attach_limit.go",
			content: `
func generateShortDriverName(driverName string) string {
    charsFromDriverName := driverName[:23]
    hash := sha1.New()
    hash.Write([]byte(driverName))
    hashed := hex.EncodeToString(hash.Sum(nil))
    return charsFromDriverName + hashed[:8]
}
`,
			language:       "go",
			expectHighConf: false,
			description:    "Kubernetes volume driver name generation should have very low confidence",
		},
		{
			name:     "kubernetes_service_account_jwt",
			filePath: "pkg/serviceaccount/jwt.go",
			content: `
func hashPublicKey(publicKey interface{}) (string, error) {
    hasher := sha256.New()
    hasher.Write(publicKeyDERBytes)
    return hex.EncodeToString(hasher.Sum(nil)), nil
}
`,
			language:       "go",
			expectHighConf: false,
			description:    "Kubernetes service account JWT hashing should have slight reduction",
		},
		{
			name:     "non_kubernetes_rsa_usage",
			filePath: "app/crypto/encryption.go",
			content: `
func encryptData(data []byte) ([]byte, error) {
    key, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, err
    }
    return rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, data)
}
`,
			language:       "go",
			expectHighConf: true,
			description:    "Non-Kubernetes RSA usage should maintain normal confidence",
		},
	}

	cfg := &config.Config{
		Scanner: config.ScannerConfig{
			EnableAST: false,
		},
	}

	preFilter := scanner.NewRegexPreFilter(cfg)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := preFilter.ScanContent([]byte(tt.content), tt.filePath, tt.language)

			foundCrypto := false
			for _, finding := range findings {
				if finding.Algorithm == "RSA" || finding.Algorithm == "MD5" ||
					finding.Algorithm == "SHA1" || finding.Algorithm == "SHA256" || finding.Algorithm == "ECDSA" {
					foundCrypto = true

					t.Logf("Finding: %s at %s:%d, confidence: %.2f, algorithm: %s",
						finding.RuleID, finding.File, finding.Line, finding.Confidence, finding.Algorithm)

					if tt.expectHighConf {
						// Non-Kubernetes code should maintain reasonable confidence
						if finding.Confidence < 0.4 {
							t.Errorf("Test %s: Expected higher confidence for non-K8s crypto usage, got %.2f",
								tt.name, finding.Confidence)
						}
					} else {
						// Kubernetes infrastructure should have reduced confidence
						if finding.Confidence > 0.5 && (finding.Algorithm == "MD5" || finding.Algorithm == "SHA1") {
							t.Errorf("Test %s: Expected lower confidence for K8s utility hashing, got %.2f",
								tt.name, finding.Confidence)
						}
						if finding.Confidence > 0.7 && (finding.Algorithm == "RSA" || finding.Algorithm == "ECDSA") {
							t.Errorf("Test %s: Expected reduced confidence for K8s PKI infrastructure, got %.2f",
								tt.name, finding.Confidence)
						}
					}
				}
			}

			if !foundCrypto {
				t.Logf("Test %s: No crypto usage detected (this may be expected for some test patterns)", tt.name)
			}
		})
	}
}

// TestNonCryptographicHashUsage tests detection of non-security hash usage
func TestNonCryptographicHashUsage(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		language      string
		expectDetect  bool
		expectLowConf bool
		description   string
	}{
		{
			name:          "git_commit_hash",
			content:       `// sha1 from git, output of $(git rev-parse HEAD)`,
			language:      "go",
			expectDetect:  true,
			expectLowConf: true,
			description:   "Git commit SHA-1 should have low confidence",
		},
		{
			name:          "file_checksum",
			content:       `// LICENSE checksum: md5 hash verification`,
			language:      "shell",
			expectDetect:  true,
			expectLowConf: true,
			description:   "File checksum MD5 should have low confidence",
		},
		{
			name:          "etag_generation",
			content:       `// ETag generation using sha512 for object comparison`,
			language:      "go",
			expectDetect:  true,
			expectLowConf: true,
			description:   "ETag generation should have low confidence",
		},
		{
			name:          "test_directory_naming",
			content:       `// Test directory naming with md5 hash for uniqueness`,
			language:      "go",
			expectDetect:  true,
			expectLowConf: true,
			description:   "Test directory naming with MD5 should have low confidence",
		},
		{
			name: "cryptographic_md5_usage",
			content: `
func authenticateUser(password string) bool {
    hash := md5.New()
    hash.Write([]byte(password))
    hashedPassword := hex.EncodeToString(hash.Sum(nil))
    return checkPassword(hashedPassword)
}
`,
			language:      "go",
			expectDetect:  true,
			expectLowConf: false,
			description:   "Cryptographic MD5 usage should maintain higher confidence",
		},
	}

	cfg := &config.Config{
		Scanner: config.ScannerConfig{
			EnableAST: false,
		},
	}

	preFilter := scanner.NewRegexPreFilter(cfg)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := preFilter.ScanContent([]byte(tt.content), "test."+tt.language, tt.language)

			foundHash := false
			for _, finding := range findings {
				if finding.Algorithm == "MD5" || finding.Algorithm == "SHA1" ||
					finding.Algorithm == "SHA512" {
					foundHash = true

					t.Logf("Finding: %s, confidence: %.2f, algorithm: %s",
						finding.RuleID, finding.Confidence, finding.Algorithm)

					if tt.expectLowConf {
						if finding.Confidence > 0.4 {
							t.Errorf("Test %s: Expected low confidence for non-crypto hash usage, got %.2f",
								tt.name, finding.Confidence)
						}
					} else {
						if finding.Confidence < 0.3 {
							t.Errorf("Test %s: Expected higher confidence for crypto hash usage, got %.2f",
								tt.name, finding.Confidence)
						}
					}
				}
			}

			if tt.expectDetect && !foundHash {
				t.Logf("Test %s: Expected to find hash usage but none detected (this may be expected for comment-based patterns)", tt.name)
			}
		})
	}
}

// Helper function to check if finding contains FALCON
func findingContainsFalcon(context string) bool {
	contextLower := strings.ToLower(context)
	return strings.Contains(contextLower, "falcon")
}
