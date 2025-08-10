package config

import (
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

var ConfigFile string

// Config holds the application configuration
type Config struct {
	Scanner ScannerConfig `mapstructure:"scanner"`
	Rules   RulesConfig   `mapstructure:"rules"`
	Output  OutputConfig  `mapstructure:"output"`
	Patch   PatchConfig   `mapstructure:"patch"`
}

// ScannerConfig holds scanner-specific configuration
type ScannerConfig struct {
	MaxFileSize    int64    `mapstructure:"max_file_size"`
	IgnorePatterns []string `mapstructure:"ignore_patterns"`
	Languages      []string `mapstructure:"languages"`
	Parallel       int      `mapstructure:"parallel"`
	EnableAST      bool     `mapstructure:"enable_ast"`
	EnableDataFlow bool     `mapstructure:"enable_dataflow"`
	Offline        bool     `mapstructure:"offline"`
}

// RulesConfig holds rules configuration
type RulesConfig struct {
	DefaultRulesPath string   `mapstructure:"default_rules_path"`
	CustomRulesPaths []string `mapstructure:"custom_rules_paths"`
	EnabledRules     []string `mapstructure:"enabled_rules"`
	DisabledRules    []string `mapstructure:"disabled_rules"`
}

// OutputConfig holds output configuration
type OutputConfig struct {
	DefaultFormat string `mapstructure:"default_format"`
	IncludeSource bool   `mapstructure:"include_source"`
	Verbose       bool   `mapstructure:"verbose"`
}

// PatchConfig holds patch generation configuration
type PatchConfig struct {
	TemplatesPath string            `mapstructure:"templates_path"`
	DefaultEngine string            `mapstructure:"default_engine"`
	Variables     map[string]string `mapstructure:"variables"`
}

// Load loads configuration from file and environment variables
func Load() *Config {
	setDefaults()

	cfg := &Config{}
	if err := viper.Unmarshal(cfg); err != nil {
		// Return defaults if unmarshal fails
		return getDefaults()
	}

	// Resolve relative paths to absolute paths
	cfg.resolveRelativePaths()

	return cfg
}

// resolveRelativePaths converts relative paths to absolute paths based on binary location
func (c *Config) resolveRelativePaths() {
	// Get the binary's directory
	binaryPath, err := os.Executable()
	if err != nil {
		// Fallback to current working directory if we can't determine binary path
		return
	}
	binaryDir := filepath.Dir(binaryPath)

	// Resolve default rules path relative to binary
	if c.Rules.DefaultRulesPath != "" && !filepath.IsAbs(c.Rules.DefaultRulesPath) {
		// Try relative to binary directory first
		absolutePath := filepath.Join(binaryDir, c.Rules.DefaultRulesPath)
		if _, err := os.Stat(absolutePath); err == nil {
			c.Rules.DefaultRulesPath = absolutePath
		} else {
			// Try relative to binary parent directory (for build/ subdirectory scenario)
			parentPath := filepath.Join(filepath.Dir(binaryDir), c.Rules.DefaultRulesPath)
			if _, err := os.Stat(parentPath); err == nil {
				c.Rules.DefaultRulesPath = parentPath
			}
			// If neither exists, keep the original path (will fail later with clear error)
		}
	}

	// Resolve custom rules paths
	for i, path := range c.Rules.CustomRulesPaths {
		if path != "" && !filepath.IsAbs(path) {
			absolutePath := filepath.Join(binaryDir, path)
			if _, err := os.Stat(absolutePath); err == nil {
				c.Rules.CustomRulesPaths[i] = absolutePath
			} else {
				parentPath := filepath.Join(filepath.Dir(binaryDir), path)
				if _, err := os.Stat(parentPath); err == nil {
					c.Rules.CustomRulesPaths[i] = parentPath
				}
			}
		}
	}

	// Resolve patch templates path
	if c.Patch.TemplatesPath != "" && !filepath.IsAbs(c.Patch.TemplatesPath) {
		absolutePath := filepath.Join(binaryDir, c.Patch.TemplatesPath)
		if _, err := os.Stat(absolutePath); err == nil {
			c.Patch.TemplatesPath = absolutePath
		} else {
			parentPath := filepath.Join(filepath.Dir(binaryDir), c.Patch.TemplatesPath)
			if _, err := os.Stat(parentPath); err == nil {
				c.Patch.TemplatesPath = parentPath
			}
		}
	}
}

// setDefaults sets default configuration values
func setDefaults() {
	// Scanner defaults
	viper.SetDefault("scanner.max_file_size", 10*1024*1024) // 10MB
	viper.SetDefault("scanner.ignore_patterns", []string{
		"*.git/*",
		"node_modules/*",
		"vendor/*",
		"*.min.js",
		"*.min.css",
		"*.map",
		"*.lock",
		"*.log",
	})
	viper.SetDefault("scanner.languages", []string{
		"go", "java", "javascript", "typescript", "python", "c", "cpp", "rust", "kotlin",
	})
	viper.SetDefault("scanner.parallel", 4)
	viper.SetDefault("scanner.enable_ast", false)      // Disabled by default for stability
	viper.SetDefault("scanner.enable_dataflow", false) // L2 dataflow analysis disabled by default
	viper.SetDefault("scanner.offline", false)

	// Rules defaults
	viper.SetDefault("rules.default_rules_path", "internal/scanner/rules")
	viper.SetDefault("rules.custom_rules_paths", []string{})
	viper.SetDefault("rules.enabled_rules", []string{})
	viper.SetDefault("rules.disabled_rules", []string{})

	// Output defaults
	viper.SetDefault("output.default_format", "json")
	viper.SetDefault("output.include_source", true)
	viper.SetDefault("output.verbose", false)

	// Patch defaults
	viper.SetDefault("patch.templates_path", "internal/patch/templates")
	viper.SetDefault("patch.default_engine", "cue")
	viper.SetDefault("patch.variables", map[string]string{})
}

// getDefaults returns a Config struct with default values
func getDefaults() *Config {
	cfg := &Config{
		Scanner: ScannerConfig{
			MaxFileSize: 10 * 1024 * 1024,
			IgnorePatterns: []string{
				"*.git/*",
				"node_modules/*",
				"vendor/*",
				"*.min.js",
				"*.min.css",
				"*.map",
				"*.lock",
				"*.log",
			},
			Languages: []string{
				"go", "java", "javascript", "typescript", "python", "c", "cpp", "rust", "kotlin",
			},
			Parallel:       4,
			EnableAST:      false, // Disabled by default for stability
			EnableDataFlow: false, // L2 dataflow analysis disabled by default
			Offline:        false,
		},
		Rules: RulesConfig{
			DefaultRulesPath: "internal/scanner/rules",
			CustomRulesPaths: []string{},
			EnabledRules:     []string{},
			DisabledRules:    []string{},
		},
		Output: OutputConfig{
			DefaultFormat: "json",
			IncludeSource: true,
			Verbose:       false,
		},
		Patch: PatchConfig{
			TemplatesPath: "internal/patch/templates",
			DefaultEngine: "cue",
			Variables:     map[string]string{},
		},
	}

	// Resolve relative paths for default config too
	cfg.resolveRelativePaths()

	return cfg
}
