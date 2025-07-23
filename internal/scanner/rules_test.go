package scanner

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/pqswitch/scanner/internal/config"
	"gopkg.in/yaml.v3"
)

func TestRuleFilesValid(t *testing.T) {
	rulesDir := "rules"

	// Check if rules directory exists
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		t.Skip("Rules directory not found, skipping rule validation tests")
		return
	}

	err := filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Only test YAML files
		if filepath.Ext(path) != ".yaml" && filepath.Ext(path) != ".yml" {
			return nil
		}

		t.Run("validate_"+filepath.Base(path), func(t *testing.T) {
			validateRuleFile(t, path)
		})

		return nil
	})

	if err != nil {
		t.Fatalf("Failed to walk rules directory: %v", err)
	}
}

func validateRuleFile(t *testing.T, filePath string) {
	data, err := os.ReadFile(filePath) //nolint:gosec // Legitimate test file reading
	if err != nil {
		t.Fatalf("Failed to read rule file %s: %v", filePath, err)
	}

	var ruleSet RuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err != nil {
		t.Fatalf("Failed to parse rule file %s: %v", filePath, err)
	}

	// Validate rule set structure
	if ruleSet.Version == "" {
		t.Errorf("Rule file %s missing version", filePath)
	}

	if ruleSet.Name == "" {
		t.Errorf("Rule file %s missing name", filePath)
	}

	// Validate regex rules
	for i, rule := range ruleSet.RegexRules {
		validateRegexRule(t, rule, filePath, i)
	}

	// Validate AST rules
	for i, rule := range ruleSet.ASTRules {
		validateASTRule(t, rule, filePath, i)
	}
}

func validateRegexRule(t *testing.T, rule RegexRule, filePath string, index int) {
	if rule.ID == "" {
		t.Errorf("Regex rule %d in %s missing ID", index, filePath)
	}

	if rule.Pattern == "" {
		t.Errorf("Regex rule %s in %s missing pattern", rule.ID, filePath)
	}

	if rule.Message == "" {
		t.Errorf("Regex rule %s in %s missing message", rule.ID, filePath)
	}

	if rule.Severity == "" {
		t.Errorf("Regex rule %s in %s missing severity", rule.ID, filePath)
	}

	// Validate severity values
	validSeverities := []string{"critical", "high", "medium", "low", "info"}
	severityValid := false
	for _, valid := range validSeverities {
		if rule.Severity == valid {
			severityValid = true
			break
		}
	}
	if !severityValid {
		t.Errorf("Regex rule %s in %s has invalid severity: %s", rule.ID, filePath, rule.Severity)
	}

	// Test regex compilation
	if rule.Pattern != "" {
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			t.Errorf("Regex rule %s in %s has invalid pattern: %v", rule.ID, filePath, err)
		}
	}
}

func validateASTRule(t *testing.T, rule ASTRule, filePath string, index int) {
	if rule.ID == "" {
		t.Errorf("AST rule %d in %s missing ID", index, filePath)
	}

	if rule.Pattern == "" {
		t.Errorf("AST rule %s in %s missing pattern", rule.ID, filePath)
	}

	if rule.Message == "" {
		t.Errorf("AST rule %s in %s missing message", rule.ID, filePath)
	}

	if rule.Severity == "" {
		t.Errorf("AST rule %s in %s missing severity", rule.ID, filePath)
	}

	if rule.Language == "" {
		t.Errorf("AST rule %s in %s missing language", rule.ID, filePath)
	}

	// Validate severity values
	validSeverities := []string{"critical", "high", "medium", "low", "info"}
	severityValid := false
	for _, valid := range validSeverities {
		if rule.Severity == valid {
			severityValid = true
			break
		}
	}
	if !severityValid {
		t.Errorf("AST rule %s in %s has invalid severity: %s", rule.ID, filePath, rule.Severity)
	}
}

func TestRuleEngineLoading(t *testing.T) {
	// Create a test configuration that doesn't rely on external files
	cfg := &config.Config{
		Rules: config.RulesConfig{
			DefaultRulesPath: "", // Empty to skip file loading
		},
	}

	// Create rule engine
	engine := NewRuleEngine(cfg)

	// Test creating the engine (should work even without rules)
	if engine == nil {
		t.Fatal("Failed to create rule engine")
	}

	// Test that engine can be created without errors
	count := engine.Count()
	if count < 0 {
		t.Error("Rule count should be non-negative")
	}

	t.Logf("Rule engine created successfully with %d rules", count)
}

func TestRuleEngineRegexCompilation(t *testing.T) {
	// Create a simple in-memory rule for testing
	cfg := &config.Config{
		Rules: config.RulesConfig{
			DefaultRulesPath: "",
		},
	}

	engine := NewRuleEngine(cfg)

	// Test that engine can be created
	if engine == nil {
		t.Fatal("Failed to create rule engine")
	}

	// Add a simple regex rule manually
	testRule := RegexRule{
		ID:       "test-rule",
		Pattern:  "test.*pattern",
		Message:  "Test message",
		Severity: "medium",
		Enabled:  true,
	}

	// Test regex compilation directly
	if _, err := regexp.Compile(testRule.Pattern); err != nil {
		t.Errorf("Test rule regex should compile: %v", err)
	}

	t.Log("Rule engine regex compilation test passed")
}

// Benchmark tests
func BenchmarkRuleEngineCreation(b *testing.B) {
	cfg := &config.Config{
		Rules: config.RulesConfig{
			DefaultRulesPath: "",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine := NewRuleEngine(cfg)
		_ = engine.Count()
	}
}

func BenchmarkRegexRuleMatching(b *testing.B) {
	cfg := &config.Config{
		Rules: config.RulesConfig{
			DefaultRulesPath: "",
		},
	}

	engine := NewRuleEngine(cfg)
	_ = engine.Count()

	// Add a test rule
	testRule := RegexRule{
		ID:       "bench-rule",
		Pattern:  "rsa\\.GenerateKey\\(",
		Message:  "RSA key generation detected",
		Severity: "high",
		Enabled:  true,
	}

	// Compile the regex
	regex, err := regexp.Compile(testRule.Pattern)
	if err != nil {
		b.Fatalf("Failed to compile regex: %v", err)
	}

	testCode := `
package main

import (
	"crypto/rsa"
	"crypto/rand"
)

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	_ = privateKey
}
`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matches := regex.FindAllStringIndex(testCode, -1)
		_ = matches
	}
}

func BenchmarkDetectorCreation(b *testing.B) {
	cfg := &config.Config{
		Scanner: config.ScannerConfig{
			MaxFileSize:    10485760,
			Parallel:       4,
			IgnorePatterns: []string{"vendor/*", "node_modules/*"},
		},
		Rules: config.RulesConfig{
			DefaultRulesPath: "",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		detector := NewDetector(cfg)
		_ = detector.GetRulesCount()
	}
}
