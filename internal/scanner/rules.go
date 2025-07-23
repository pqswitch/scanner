package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pqswitch/scanner/internal/config"
	"gopkg.in/yaml.v3"
)

// RuleEngine manages detection rules
type RuleEngine struct {
	config     *config.Config
	astRules   map[string][]ASTRule
	regexRules []RegexRule
}

// ASTRule represents an AST-based detection rule
type ASTRule struct {
	ID          string            `yaml:"id"`
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Language    string            `yaml:"language"`
	Pattern     string            `yaml:"pattern"`
	Message     string            `yaml:"message"`
	Severity    string            `yaml:"severity"`
	CryptoType  string            `yaml:"crypto_type"`
	Algorithm   string            `yaml:"algorithm"`
	Suggestion  string            `yaml:"suggestion"`
	References  []string          `yaml:"references"`
	Metadata    map[string]string `yaml:"metadata"`
	Enabled     bool              `yaml:"enabled"`
}

// RegexRule represents a regex-based detection rule
type RegexRule struct {
	ID          string            `yaml:"id"`
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Pattern     string            `yaml:"pattern"`
	Regex       *regexp.Regexp    `yaml:"-"`
	Message     string            `yaml:"message"`
	Severity    string            `yaml:"severity"`
	CryptoType  string            `yaml:"crypto_type"`
	Algorithm   string            `yaml:"algorithm"`
	Suggestion  string            `yaml:"suggestion"`
	References  []string          `yaml:"references"`
	Metadata    map[string]string `yaml:"metadata"`
	Enabled     bool              `yaml:"enabled"`
	Languages   []string          `yaml:"languages"`
}

// RuleSet represents a collection of rules
type RuleSet struct {
	Version    string      `yaml:"version"`
	Name       string      `yaml:"name"`
	Author     string      `yaml:"author"`
	ASTRules   []ASTRule   `yaml:"ast_rules"`
	RegexRules []RegexRule `yaml:"regex_rules"`
}

// ASTMatch represents a match from AST scanning
type ASTMatch struct {
	Line    int
	Column  int
	Context string
}

// NewRuleEngine creates a new rule engine
func NewRuleEngine(cfg *config.Config) *RuleEngine {
	return &RuleEngine{
		config:     cfg,
		astRules:   make(map[string][]ASTRule),
		regexRules: make([]RegexRule, 0),
	}
}

// LoadRules loads rules from the specified path
func (re *RuleEngine) LoadRules(rulesPath string) error {
	// Load default rules
	defaultPath := re.config.Rules.DefaultRulesPath

	if defaultPath != "" {
		if err := re.loadRulesFromPath(defaultPath); err != nil {
			return fmt.Errorf("failed to load default rules: %w", err)
		}
	}

	// Load custom rules if specified
	if rulesPath != "" {
		if err := re.loadRulesFromPath(rulesPath); err != nil {
			return fmt.Errorf("failed to load custom rules: %w", err)
		}
	}

	// Load additional custom rules paths from config
	for _, customPath := range re.config.Rules.CustomRulesPaths {
		if err := re.loadRulesFromPath(customPath); err != nil {
			return fmt.Errorf("failed to load custom rules from %s: %w", customPath, err)
		}
	}

	err := re.compileRegexRules()
	if err != nil {
		return err
	}

	return nil
}

// loadRulesFromPath loads rules from a file or directory
func (re *RuleEngine) loadRulesFromPath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if info.IsDir() {
		return re.loadRulesFromDirectory(path)
	}

	return re.loadRulesFromFile(path)
}

// loadRulesFromDirectory loads all rule files from a directory
func (re *RuleEngine) loadRulesFromDirectory(dirPath string) error {
	return filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			return re.loadRulesFromFile(path)
		}

		return nil
	})
}

// loadRulesFromFile loads rules from a single YAML file
func (re *RuleEngine) loadRulesFromFile(filePath string) error {
	data, err := os.ReadFile(filePath) //nolint:gosec // Legitimate rule file reading
	if err != nil {
		return err
	}

	var ruleSet RuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err != nil {
		return fmt.Errorf("failed to parse rule file %s: %w", filePath, err)
	}

	// Process AST rules
	for _, rule := range ruleSet.ASTRules {
		if !rule.Enabled {
			continue
		}

		if re.isRuleEnabled(rule.ID) {
			if re.astRules[rule.Language] == nil {
				re.astRules[rule.Language] = make([]ASTRule, 0)
			}
			re.astRules[rule.Language] = append(re.astRules[rule.Language], rule)
		}
	}

	// Process regex rules
	for _, rule := range ruleSet.RegexRules {
		if !rule.Enabled {
			continue
		}

		if re.isRuleEnabled(rule.ID) {
			re.regexRules = append(re.regexRules, rule)
		}
	}

	return nil
}

// compileRegexRules compiles all regex patterns
func (re *RuleEngine) compileRegexRules() error {
	for i := range re.regexRules {
		regex, err := regexp.Compile(re.regexRules[i].Pattern)
		if err != nil {
			return fmt.Errorf("failed to compile regex for rule %s: %w", re.regexRules[i].ID, err)
		}
		re.regexRules[i].Regex = regex
	}
	return nil
}

// isRuleEnabled checks if a rule is enabled based on configuration
func (re *RuleEngine) isRuleEnabled(ruleID string) bool {
	// Check if rule is explicitly disabled
	for _, disabledRule := range re.config.Rules.DisabledRules {
		if disabledRule == ruleID {
			return false
		}
	}

	// If enabled rules list is empty, all rules are enabled by default
	if len(re.config.Rules.EnabledRules) == 0 {
		return true
	}

	// Check if rule is explicitly enabled
	for _, enabledRule := range re.config.Rules.EnabledRules {
		if enabledRule == ruleID {
			return true
		}
	}

	return false
}

// GetASTRules returns AST rules for a specific language
func (re *RuleEngine) GetASTRules(language string) []ASTRule {
	return re.astRules[language]
}

// GetRegexRules returns all regex rules
func (re *RuleEngine) GetRegexRules() []RegexRule {
	return re.regexRules
}

// Count returns the total number of loaded rules
func (re *RuleEngine) Count() int {
	count := len(re.regexRules)
	for _, rules := range re.astRules {
		count += len(rules)
	}
	return count
}

// GetRuleByID returns a rule by its ID
func (re *RuleEngine) GetRuleByID(ruleID string) (interface{}, bool) {
	// Search in AST rules
	for _, rules := range re.astRules {
		for _, rule := range rules {
			if rule.ID == ruleID {
				return rule, true
			}
		}
	}

	// Search in regex rules
	for _, rule := range re.regexRules {
		if rule.ID == ruleID {
			return rule, true
		}
	}

	return nil, false
}

// ValidateRules validates all loaded rules
func (re *RuleEngine) ValidateRules() []error {
	var errors []error

	// Validate AST rules
	for language, rules := range re.astRules {
		for _, rule := range rules {
			if err := re.validateASTRule(rule, language); err != nil {
				errors = append(errors, err)
			}
		}
	}

	// Validate regex rules
	for _, rule := range re.regexRules {
		if err := re.validateRegexRule(rule); err != nil {
			errors = append(errors, err)
		}
	}

	return errors
}

// validateASTRule validates an AST rule
func (re *RuleEngine) validateASTRule(rule ASTRule, language string) error {
	if rule.ID == "" {
		return fmt.Errorf("AST rule missing ID")
	}
	if rule.Pattern == "" {
		return fmt.Errorf("AST rule %s missing pattern", rule.ID)
	}
	if rule.Message == "" {
		return fmt.Errorf("AST rule %s missing message", rule.ID)
	}
	if rule.Severity == "" {
		return fmt.Errorf("AST rule %s missing severity", rule.ID)
	}
	if !isValidSeverity(rule.Severity) {
		return fmt.Errorf("AST rule %s has invalid severity: %s", rule.ID, rule.Severity)
	}
	return nil
}

// validateRegexRule validates a regex rule
func (re *RuleEngine) validateRegexRule(rule RegexRule) error {
	if rule.ID == "" {
		return fmt.Errorf("regex rule missing ID")
	}
	if rule.Pattern == "" {
		return fmt.Errorf("regex rule %s missing pattern", rule.ID)
	}
	if rule.Message == "" {
		return fmt.Errorf("regex rule %s missing message", rule.ID)
	}
	if rule.Severity == "" {
		return fmt.Errorf("regex rule %s missing severity", rule.ID)
	}
	if !isValidSeverity(rule.Severity) {
		return fmt.Errorf("regex rule %s has invalid severity: %s", rule.ID, rule.Severity)
	}
	return nil
}

// isValidSeverity checks if a severity level is valid
func isValidSeverity(severity string) bool {
	validSeverities := []string{"critical", "high", "medium", "low", "info"}
	severityLower := strings.ToLower(severity)

	for _, valid := range validSeverities {
		if severityLower == valid {
			return true
		}
	}
	return false
}

// GetRuleStatistics returns statistics about loaded rules
func (re *RuleEngine) GetRuleStatistics() map[string]interface{} {
	stats := make(map[string]interface{})

	// Count rules by language
	languageCounts := make(map[string]int)
	for language, rules := range re.astRules {
		languageCounts[language] = len(rules)
	}

	// Count rules by severity
	severityCounts := make(map[string]int)
	for _, rules := range re.astRules {
		for _, rule := range rules {
			severityCounts[rule.Severity]++
		}
	}
	for _, rule := range re.regexRules {
		severityCounts[rule.Severity]++
	}

	// Count rules by crypto type
	cryptoTypeCounts := make(map[string]int)
	for _, rules := range re.astRules {
		for _, rule := range rules {
			cryptoTypeCounts[rule.CryptoType]++
		}
	}
	for _, rule := range re.regexRules {
		cryptoTypeCounts[rule.CryptoType]++
	}

	stats["total_rules"] = re.Count()
	stats["ast_rules"] = len(re.astRules)
	stats["regex_rules"] = len(re.regexRules)
	stats["rules_by_language"] = languageCounts
	stats["rules_by_severity"] = severityCounts
	stats["rules_by_crypto_type"] = cryptoTypeCounts

	return stats
}
