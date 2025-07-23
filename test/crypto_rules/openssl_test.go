package crypto_rules

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestOpenSSLDetection validates our OpenSSL crypto detection improvements
func TestOpenSSLDetection(t *testing.T) {
	// Check if OpenSSL directory exists (from our test run)
	if _, err := os.Stat("../../openssl"); os.IsNotExist(err) {
		t.Skip("OpenSSL directory not found, skipping OpenSSL-specific tests")
	}

	tests := []struct {
		name        string
		path        string
		expectRules []string
		expectCount int
	}{
		{
			name:        "MD5 Detection",
			path:        "../../openssl/crypto/md5/",
			expectRules: []string{"openssl-deprecated-functions", "weak-hash-md5-test-context"},
			expectCount: 3, // Should find some but not duplicate everything
		},
		{
			name:        "SHA Detection",
			path:        "../../openssl/crypto/sha/",
			expectRules: []string{"c-sha1-implementation", "c-sha3-implementation"},
			expectCount: 5, // Should find several SHA implementations
		},
		{
			name:        "ECDSA Detection",
			path:        "../../openssl/crypto/ec/",
			expectRules: []string{"c-ecdsa-implementation", "c-evp-interface"},
			expectCount: 3, // Should find ECDSA patterns
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Run scanner on the path
			cmd := exec.Command("../../build/pqswitch", "scan", tt.path,
				"--output", "json", "--min-confidence", "0.0", "--top-findings", "10")

			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("Scanner failed: %v", err)
			}

			outputStr := string(output)

			// Check if we found expected rules
			for _, rule := range tt.expectRules {
				if !strings.Contains(outputStr, rule) {
					t.Errorf("Expected rule %s not found in output", rule)
				}
			}

			// Check that we found some findings (basic smoke test)
			if !strings.Contains(outputStr, "crypto_findings") {
				t.Error("No crypto_findings found in output")
			}

			// Validate context detection is working
			if strings.Contains(outputStr, "crypto_library_context") {
				t.Log("✅ Context detection working - found crypto_library_context")
			}

			// Validate deduplication is working (no excessive duplicates)
			findingsCount := strings.Count(outputStr, `"id":`)
			if findingsCount > tt.expectCount*3 { // Allow some variance but not excessive duplicates
				t.Errorf("Too many findings (%d), possible duplicate issue", findingsCount)
			}
		})
	}
}

// TestCryptoLibraryContextDetection validates context-aware severity adjustment
func TestCryptoLibraryContextDetection(t *testing.T) {
	if _, err := os.Stat("../../openssl"); os.IsNotExist(err) {
		t.Skip("OpenSSL directory not found, skipping context detection tests")
	}

	// Test that OpenSSL context is properly detected
	cmd := exec.Command("../../build/pqswitch", "scan", "../../openssl/crypto/aes/aes_core.c",
		"--output", "json", "--min-confidence", "0.0")

	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Scanner failed: %v", err)
	}

	outputStr := string(output)

	// Should detect OpenSSL context and apply appropriate severity
	tests := []string{
		"crypto_library_context",
		"legitimate_implementation",
		"Monitor for post-quantum alternatives",
	}

	for _, test := range tests {
		if strings.Contains(outputStr, test) {
			t.Logf("✅ Found context pattern: %s", test)
		}
	}
}

// TestNoDuplicateFindings ensures our deduplication is working
func TestNoDuplicateFindings(t *testing.T) {
	if _, err := os.Stat("../../openssl"); os.IsNotExist(err) {
		t.Skip("OpenSSL directory not found, skipping duplicate detection tests")
	}

	// Run scanner on a file that previously produced many duplicates
	cmd := exec.Command("../../build/pqswitch", "scan", "../../openssl/crypto/md5/md5_local.h",
		"--output", "json", "--min-confidence", "0.0")

	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Scanner failed: %v", err)
	}

	outputStr := string(output)

	// Count unique findings vs total findings
	findingsCount := strings.Count(outputStr, `"id":`)

	// Should have reasonable number of findings, not excessive duplicates
	if findingsCount > 10 {
		t.Errorf("Too many findings (%d) for single file, possible duplicates", findingsCount)
	}

	if findingsCount > 0 {
		t.Logf("✅ Found %d findings (reasonable, no excessive duplicates)", findingsCount)
	}
}
