package classifier

import (
	"strings"

	"github.com/pqswitch/scanner/internal/types"
)

// Classifier classifies cryptographic findings
type Classifier struct {
	algorithmPatterns map[string][]string
	severityRules     map[string]func(*types.Finding) string
}

// NewClassifier creates a new classifier
func NewClassifier() *Classifier {
	return &Classifier{
		algorithmPatterns: map[string][]string{
			"aes":      {"aes", "rijndael"},
			"rsa":      {"rsa", "rsa-", "rsa_"},
			"ecdsa":    {"ecdsa", "ec-", "ec_"},
			"ed25519":  {"ed25519", "ed-", "ed_"},
			"sha":      {"sha", "sha-", "sha_"},
			"md5":      {"md5", "md-", "md_"},
			"hmac":     {"hmac", "hmac-", "hmac_"},
			"pbkdf2":   {"pbkdf2", "pbkdf-", "pbkdf_"},
			"bcrypt":   {"bcrypt", "bcrypt-", "bcrypt_"},
			"argon2":   {"argon2", "argon-", "argon_"},
			"chacha20": {"chacha20", "chacha-", "chacha_"},
			"blake2":   {"blake2", "blake-", "blake_"},
		},
		severityRules: map[string]func(*types.Finding) string{
			"algorithm": func(f *types.Finding) string {
				algo := strings.ToLower(f.Algorithm)
				if strings.Contains(algo, "md5") || strings.Contains(algo, "sha1") {
					return "high"
				}
				if strings.Contains(algo, "des") || strings.Contains(algo, "rc4") {
					return "critical"
				}
				return "medium"
			},
			"key_size": func(f *types.Finding) string {
				if f.KeySize > 0 {
					if f.KeySize < 128 {
						return "critical"
					}
					if f.KeySize < 256 {
						return "high"
					}
				}
				return "medium"
			},
			"crypto_type": func(f *types.Finding) string {
				switch strings.ToLower(f.CryptoType) {
				case "asymmetric":
					return "high"
				case "symmetric":
					return "medium"
				case "hash":
					return "low"
				default:
					return "info"
				}
			},
		},
	}
}

// ClassifyFinding classifies a finding based on its properties
func (c *Classifier) ClassifyFinding(finding *types.Finding) {
	// Detect algorithm if not specified
	if finding.Algorithm == "" {
		finding.Algorithm = c.detectAlgorithm(finding.Context)
	}

	// Determine severity if not specified
	if finding.Severity == "" {
		finding.Severity = c.determineSeverity(finding)
	}

	// Determine crypto type if not specified
	if finding.CryptoType == "" {
		finding.CryptoType = c.determineCryptoType(finding)
	}
}

// detectAlgorithm detects the cryptographic algorithm from context
func (c *Classifier) detectAlgorithm(context string) string {
	context = strings.ToLower(context)
	for algo, patterns := range c.algorithmPatterns {
		for _, pattern := range patterns {
			if strings.Contains(context, pattern) {
				return algo
			}
		}
	}
	return ""
}

// determineSeverity determines the severity of a finding
func (c *Classifier) determineSeverity(finding *types.Finding) string {
	// Apply severity rules in order
	for _, rule := range c.severityRules {
		if severity := rule(finding); severity != "" {
			return severity
		}
	}
	return "medium"
}

// determineCryptoType determines the type of cryptography
func (c *Classifier) determineCryptoType(finding *types.Finding) string {
	algo := strings.ToLower(finding.Algorithm)

	// Check for asymmetric algorithms
	if strings.Contains(algo, "rsa") ||
		strings.Contains(algo, "ecdsa") ||
		strings.Contains(algo, "ed25519") {
		return "asymmetric"
	}

	// Check for symmetric algorithms
	if strings.Contains(algo, "aes") ||
		strings.Contains(algo, "chacha20") {
		return "symmetric"
	}

	// Check for hash functions
	if strings.Contains(algo, "sha") ||
		strings.Contains(algo, "md5") ||
		strings.Contains(algo, "blake2") {
		return "hash"
	}

	// Check for key derivation
	if strings.Contains(algo, "pbkdf2") ||
		strings.Contains(algo, "bcrypt") ||
		strings.Contains(algo, "argon2") {
		return "key_derivation"
	}

	return "unknown"
}

// CalculateConfidence calculates the confidence score for a finding
func (c *Classifier) CalculateConfidence(finding *types.Finding) float64 {
	var confidence float64

	// Base confidence on algorithm detection
	if finding.Algorithm != "" {
		confidence += 0.4
	}

	// Add confidence for key size information
	if finding.KeySize > 0 {
		confidence += 0.3
	}

	// Add confidence for context
	if finding.Context != "" {
		confidence += 0.3
	}

	return confidence
}
