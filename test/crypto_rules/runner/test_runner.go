package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// TestCase represents an expected test result
type TestCase struct {
	File             string   `json:"file"`
	ExpectedSeverity string   `json:"expected_severity"`
	ExpectedRuleIDs  []string `json:"expected_rule_ids"`
	ExpectedMessage  string   `json:"expected_message"`
	Description      string   `json:"description"`
	Category         string   `json:"category"`
}

// ScanResult represents scanner output (updated for new format)
type ScanResult struct {
	ProjectInfo       ProjectInfo   `json:"project_info"`
	CryptoFindings    []Finding     `json:"crypto_findings"`
	CryptoErrors      []string      `json:"crypto_errors,omitempty"`
	DependencyResults []interface{} `json:"dependency_results,omitempty"`
	ScanTime          string        `json:"scan_time"`
	Duration          int64         `json:"duration"`
}

type ProjectInfo struct {
	Languages         []Language `json:"languages"`
	PackageManagers   []string   `json:"package_managers"`
	SourceDirectories []string   `json:"source_directories"`
	ExcludedPaths     []string   `json:"excluded_paths"`
}

type Language struct {
	Language   string   `json:"language"`
	Files      []string `json:"files"`
	Confidence float64  `json:"confidence"`
}

type Finding struct {
	ID         string  `json:"id"`
	RuleID     string  `json:"rule_id"`
	File       string  `json:"file"`
	Line       int     `json:"line"`
	Column     int     `json:"column"`
	Message    string  `json:"message"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	CryptoType string  `json:"crypto_type"`
	Algorithm  string  `json:"algorithm"`
	Context    string  `json:"context"`
	Suggestion string  `json:"suggestion"`
}

func main() {
	fmt.Println("🔍 PQSwitch Crypto Rules Test Suite")
	fmt.Println("===================================")

	testCases := loadTestCases()
	results := runTests(testCases)

	fmt.Printf("\n📊 Test Results Summary:\n")
	fmt.Printf("Total test cases: %d\n", len(testCases))
	fmt.Printf("Passed: %d\n", results.Passed)
	fmt.Printf("Failed: %d\n", results.Failed)
	fmt.Printf("Success rate: %.1f%%\n", float64(results.Passed)/float64(len(testCases))*100)

	if results.Failed > 0 {
		fmt.Println("\n❌ Failed tests:")
		for _, failure := range results.Failures {
			fmt.Printf("  - %s: %s\n", failure.TestCase.File, failure.Reason)
		}
		os.Exit(1)
	}

	fmt.Println("\n✅ All tests passed!")
}

type TestResults struct {
	Passed   int
	Failed   int
	Failures []TestFailure
}

type TestFailure struct {
	TestCase TestCase
	Reason   string
}

func loadTestCases() []TestCase {
	return []TestCase{
		// Application Vulnerabilities (Should be HIGH/CRITICAL)
		{
			File:             "test/crypto_rules/application_vulnerabilities/c/password_hashing_vulnerabilities.c",
			ExpectedSeverity: "critical",
			ExpectedRuleIDs:  []string{"weak-hash-md5", "weak-hash-sha1", "l0-hash-algorithms"},
			ExpectedMessage:  "MD5 hash algorithm detected",
			Description:      "Application crypto vulnerabilities should be HIGH/CRITICAL",
			Category:         "application_vulnerability",
		},
		{
			File:             "test/crypto_rules/application_vulnerabilities/go/key_generation_vulnerabilities.go",
			ExpectedSeverity: "critical", // MD5 usage makes this critical
			ExpectedRuleIDs:  []string{"go-rsa-keygen", "go-ecdsa-keygen", "go-ed25519-usage"},
			ExpectedMessage:  "RSA key generation detected",
			Description:      "Application crypto vulnerabilities should be HIGH/CRITICAL",
			Category:         "application_vulnerability",
		},

		// Test Context (Should be INFO)
		{
			File:             "test/crypto_rules/test_context/crypto_test_suite.py",
			ExpectedSeverity: "info",
			ExpectedRuleIDs:  []string{"weak-hash-md5-test-context", "tls-version-test-context", "l0-hash-algorithms"},
			ExpectedMessage:  "test context",
			Description:      "Crypto usage in test files should have INFO context-aware rules",
			Category:         "test_context",
		},

		// Configuration (Should be INFO)
		{
			File:             "test/crypto_rules/configuration/Kconfig.crypto",
			ExpectedSeverity: "info",
			ExpectedRuleIDs:  []string{"tls-config-kconfig", "tls-cipher-config"},
			ExpectedMessage:  "TLS configuration option detected in build system",
			Description:      "Build configuration should have INFO context-aware rules",
			Category:         "configuration",
		},

		// False Positives (Should have NO findings)
		{
			File:             "test/crypto_rules/false_positives/README_ssl_mention.md",
			ExpectedSeverity: "",
			ExpectedRuleIDs:  []string{},
			ExpectedMessage:  "",
			Description:      "Documentation files should not trigger crypto findings",
			Category:         "false_positive",
		},
	}
}

func runTests(testCases []TestCase) TestResults {
	results := TestResults{
		Passed:   0,
		Failed:   0,
		Failures: []TestFailure{},
	}

	for _, testCase := range testCases {
		fmt.Printf("🧪 Testing: %s (%s)\n", filepath.Base(testCase.File), testCase.Category)

		if runSingleTest(testCase) {
			results.Passed++
			fmt.Printf("   ✅ PASS: %s\n", testCase.Description)
		} else {
			results.Failed++
			failure := TestFailure{
				TestCase: testCase,
				Reason:   "Rule validation failed",
			}
			results.Failures = append(results.Failures, failure)
			fmt.Printf("   ❌ FAIL: %s\n", testCase.Description)
		}
	}

	return results
}

func runSingleTest(testCase TestCase) bool {
	// Get absolute paths
	workDir, _ := os.Getwd()
	rootDir := filepath.Join(workDir, "../../../")
	testFilePath := filepath.Join(rootDir, testCase.File)

	// Check if test file exists
	if _, err := os.Stat(testFilePath); os.IsNotExist(err) {
		fmt.Printf("   ⚠️  Test file does not exist: %s\n", testFilePath)
		return false
	}

	// Run scanner on test file with proper flags
	binaryPath := filepath.Join(rootDir, "build/pqswitch")

	cmd := exec.Command(binaryPath, "scan",
		"--output", "json",
		"--min-confidence", "0.0", // Catch all findings regardless of confidence
		testCase.File) // Path as last argument
	cmd.Dir = rootDir // Run from root directory where rules are accessible
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("   ⚠️  Scanner failed: %v\n", err)
		fmt.Printf("   📄 Scanner output: %s\n", string(output))
		return false
	}

	// Parse scanner output - filter out warning lines
	outputStr := string(output)
	lines := strings.Split(outputStr, "\n")
	var jsonLines []string

	for _, line := range lines {
		if !strings.HasPrefix(line, "Warning:") && strings.TrimSpace(line) != "" {
			jsonLines = append(jsonLines, line)
		}
	}

	jsonOutput := strings.Join(jsonLines, "\n")

	var scanResult ScanResult
	if err := json.Unmarshal([]byte(jsonOutput), &scanResult); err != nil {
		fmt.Printf("   ⚠️  Failed to parse scanner output: %v\n", err)
		fmt.Printf("   📄 Raw output: %s\n", outputStr)
		return false
	}

	// Validate results
	return validateScanResults(testCase, scanResult)
}

func validateScanResults(testCase TestCase, result ScanResult) bool {
	// Handle false positive tests (should have NO findings)
	if testCase.Category == "false_positive" {
		if len(result.CryptoFindings) > 0 {
			fmt.Printf("   ⚠️  False positive detected: %d findings when none expected\n", len(result.CryptoFindings))
			for _, finding := range result.CryptoFindings {
				fmt.Printf("      - Rule: %s, Message: %s\n", finding.RuleID, finding.Message)
			}
			return false
		}
		return true
	}

	if len(result.CryptoFindings) == 0 {
		fmt.Printf("   ⚠️  No findings detected for %s\n", testCase.File)
		return false
	}

	// Check if expected rule IDs are present
	foundRules := make(map[string]bool)
	maxSeverity := ""
	severityOrder := map[string]int{
		"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5,
	}

	for _, finding := range result.CryptoFindings {
		foundRules[finding.RuleID] = true
		if severityOrder[finding.Severity] > severityOrder[maxSeverity] {
			maxSeverity = finding.Severity
		}

		// Check if message contains expected content (we'll validate this at the end)
		// Just collect individual mismatches for now
	}

	// Validate severity - for mixed results, check if we have the expected context-aware rules
	if testCase.Category == "protocol_implementation" || testCase.Category == "test_context" || testCase.Category == "configuration" {
		// For these categories, we expect INFO severity rules to be present (context-aware)
		hasExpectedSeverity := false
		for _, finding := range result.CryptoFindings {
			if finding.Severity == "info" {
				hasExpectedSeverity = true
				break
			}
		}
		if !hasExpectedSeverity {
			fmt.Printf("   ⚠️  Expected INFO severity rules for context-aware detection\n")
			return false
		}
	} else {
		// For application vulnerabilities, check the max severity
		if maxSeverity != testCase.ExpectedSeverity {
			fmt.Printf("   ⚠️  Expected severity '%s' but got '%s'\n",
				testCase.ExpectedSeverity, maxSeverity)
			return false
		}
	}

	// Validate rule IDs - be more flexible about matching
	ruleMatches := 0
	for _, expectedRule := range testCase.ExpectedRuleIDs {
		if foundRules[expectedRule] {
			ruleMatches++
		} else {
			// Check for partial matches (e.g., if we expect "weak-hash-sha1" but find "l0-hash-algorithms")
			for foundRule := range foundRules {
				if strings.Contains(foundRule, "sha1") && strings.Contains(expectedRule, "sha1") {
					ruleMatches++
					break
				}
				if strings.Contains(foundRule, "md5") && strings.Contains(expectedRule, "md5") {
					ruleMatches++
					break
				}
				if strings.Contains(foundRule, "hash") && strings.Contains(expectedRule, "hash") {
					ruleMatches++
					break
				}
			}
		}
	}

	// Require at least one rule to match
	if ruleMatches == 0 {
		fmt.Printf("   ⚠️  No expected rules found. Expected: %v, Found: %v\n",
			testCase.ExpectedRuleIDs, getKeys(foundRules))
		return false
	}

	// Validate expected message appears somewhere in the findings
	if testCase.ExpectedMessage != "" {
		messageFound := false
		for _, finding := range result.CryptoFindings {
			if strings.Contains(strings.ToLower(finding.Message), strings.ToLower(testCase.ExpectedMessage)) {
				messageFound = true
				break
			}
		}
		if !messageFound {
			fmt.Printf("   ⚠️  Expected message '%s' not found in any findings\n", testCase.ExpectedMessage)
			return false
		}
	}

	return true
}

// getKeys extracts keys from a map
func getKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
