// Package enhanced_scanner_test provides a comprehensive test for the enhanced scanner functionality
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pqswitch/scanner/internal/config"
	"github.com/pqswitch/scanner/internal/scanner"
)

// TestProject represents a test project structure
type TestProject struct {
	Name           string
	Path           string
	Languages      []string
	HasDeps        bool
	ExpectedCrypto int
}

func mainTest() {
	fmt.Println("🔍 Enhanced Scanner Test Suite")
	fmt.Println("==============================")

	// Create test projects
	projects := []TestProject{
		{
			Name:           "Go Project with Crypto",
			Path:           createGoProject(),
			Languages:      []string{"go"},
			HasDeps:        true,
			ExpectedCrypto: 2,
		},
		{
			Name:           "JavaScript Project with Dependencies",
			Path:           createJSProject(),
			Languages:      []string{"javascript"},
			HasDeps:        true,
			ExpectedCrypto: 1,
		},
	}

	// Test each project
	for i, project := range projects {
		fmt.Printf("\n%d. Testing: %s\n", i+1, project.Name)
		fmt.Printf("   Path: %s\n", project.Path)

		if err := testProject(project); err != nil {
			fmt.Printf("   ❌ FAILED: %v\n", err)
		} else {
			fmt.Printf("   ✅ PASSED\n")
		}

		// Cleanup
		if err := os.RemoveAll(project.Path); err != nil {
			fmt.Printf("   ⚠️  Warning: Failed to cleanup %s: %v\n", project.Path, err)
		}
	}

	fmt.Println("\n🎉 Enhanced Scanner Test Suite Complete!")
}

func testProject(project TestProject) error {
	// Load configuration
	cfg := config.Load()

	// Create enhanced detector
	detector := scanner.NewDetector(cfg)

	// Test 1: Source Detection
	fmt.Printf("     Testing source detection...\n")
	sourceDetector := scanner.NewSourceDetector(project.Path)
	projectInfo, err := sourceDetector.DetectProject()
	if err != nil {
		return fmt.Errorf("source detection failed: %w", err)
	}

	// Verify languages detected
	if len(projectInfo.Languages) == 0 {
		return fmt.Errorf("no languages detected")
	}

	fmt.Printf("       Detected languages: ")
	for _, lang := range projectInfo.Languages {
		fmt.Printf("%s (%.1f%%) ", lang.Language, lang.Confidence*100)
	}
	fmt.Println()

	// Test 2: Enhanced Ignore Patterns
	fmt.Printf("     Testing intelligent exclusions...\n")
	ignorePatterns := sourceDetector.GetEnhancedIgnorePatterns()
	fmt.Printf("       Generated %d exclusion patterns\n", len(ignorePatterns))

	// Update config with enhanced patterns
	cfg.Scanner.IgnorePatterns = append(cfg.Scanner.IgnorePatterns, ignorePatterns...)

	// Test 3: Crypto Scanning with Enhanced Exclusions
	fmt.Printf("     Testing crypto scanning...\n")

	// Load rules
	rulesPath := "internal/scanner/rules"
	if err := detector.LoadRules(rulesPath); err != nil {
		// Try alternative path for test
		if err := detector.LoadRules("../../internal/scanner/rules"); err != nil {
			return fmt.Errorf("failed to load rules: %w", err)
		}
	}

	// Collect and scan files
	files, err := detector.CollectFiles(project.Path)
	if err != nil {
		return fmt.Errorf("failed to collect files: %w", err)
	}

	fmt.Printf("       Scanning %d files...\n", len(files))
	cryptoFindings, cryptoErrors := detector.ScanFiles(files, false)

	fmt.Printf("       Found %d crypto findings\n", len(cryptoFindings))
	if len(cryptoErrors) > 0 {
		fmt.Printf("       Scan errors: %d\n", len(cryptoErrors))
	}

	// Test 4: Dependency Scanning (if enabled)
	var dependencyResults []*scanner.DependencyScanResult
	if project.HasDeps {
		fmt.Printf("     Testing dependency scanning...\n")

		depConfig := &scanner.DependencyScanConfig{
			UseExternalTools: false, // Use built-in only for tests
			TimeoutMinutes:   2,
			ScanDevDeps:      false,
		}

		depManager := scanner.NewDependencyScannerManager(depConfig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		dependencyResults, err = depManager.ScanProject(ctx, project.Path)
		if err != nil {
			fmt.Printf("       Warning: Dependency scanning failed: %v\n", err)
		} else {
			fmt.Printf("       Dependency scan completed (%d results)\n", len(dependencyResults))
		}
	}

	// Test 5: Enhanced Scan Result
	fmt.Printf("     Testing enhanced result generation...\n")

	result := &scanner.EnhancedScanResult{
		ProjectInfo:       projectInfo,
		CryptoFindings:    cryptoFindings,
		CryptoErrors:      cryptoErrors,
		DependencyResults: dependencyResults,
		ScanTime:          time.Now(),
		Duration:          1 * time.Second,
	}

	// Test JSON serialization
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize result: %w", err)
	}

	fmt.Printf("       Generated %d bytes of JSON output\n", len(jsonData))

	// Test vulnerability summary
	summary := result.GetVulnerabilitySummary()
	totalVulns := summary["crypto_critical"] + summary["crypto_high"] +
		summary["crypto_medium"] + summary["crypto_low"] +
		summary["dep_critical"] + summary["dep_high"] +
		summary["dep_medium"] + summary["dep_low"]

	fmt.Printf("       Summary: %d total vulnerabilities\n", totalVulns)

	return nil
}

func createGoProject() string {
	tmpDir, _ := os.MkdirTemp("", "test-go-project-*")

	// Create go.mod
	goMod := `module test-project

go 1.21

require (
	github.com/golang/crypto v0.0.0-20191011191535-87dc89f01550
)
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0600); err != nil {
		fmt.Printf("Warning: Failed to create go.mod: %v\n", err)
	}

	// Create main.go with crypto usage
	mainGo := `package main

import (
	"crypto/md5"
	"crypto/rsa"
	"crypto/rand"
	"fmt"
)

func main() {
	// Weak crypto - should be detected
	hash := md5.New()
	hash.Write([]byte("test"))
	
	// RSA key generation - should be detected
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	
	fmt.Printf("Key: %v\n", privateKey)
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(mainGo), 0600); err != nil {
		fmt.Printf("Warning: Failed to create main.go: %v\n", err)
	}

	// Create some build artifacts that should be ignored
	if err := os.MkdirAll(filepath.Join(tmpDir, "build"), 0750); err != nil {
		fmt.Printf("Warning: Failed to create build directory: %v\n", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "build", "main"), []byte("binary"), 0600); err != nil {
		fmt.Printf("Warning: Failed to create binary: %v\n", err)
	}

	return tmpDir
}

func createJSProject() string {
	tmpDir, _ := os.MkdirTemp("", "test-js-project-*")

	// Create package.json
	packageJSON := `{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "crypto": "^1.0.0",
    "lodash": "^4.17.21"
  }
}
`
	if err := os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(packageJSON), 0600); err != nil {
		fmt.Printf("Warning: Failed to create package.json: %v\n", err)
	}

	// Create src directory with crypto usage
	if err := os.MkdirAll(filepath.Join(tmpDir, "src"), 0750); err != nil {
		fmt.Printf("Warning: Failed to create src directory: %v\n", err)
	}
	indexJS := `const crypto = require('crypto');

// Weak crypto usage - should be detected
const hash = crypto.createHash('md5');
hash.update('test');
console.log(hash.digest('hex'));
`
	if err := os.WriteFile(filepath.Join(tmpDir, "src", "index.js"), []byte(indexJS), 0600); err != nil {
		fmt.Printf("Warning: Failed to create index.js: %v\n", err)
	}

	return tmpDir
}

// For testing purposes, call mainTest when this file is executed directly
func init() {
	if len(os.Args) > 0 && filepath.Base(os.Args[0]) == "test_enhanced_scanner" {
		mainTest()
	}
}
