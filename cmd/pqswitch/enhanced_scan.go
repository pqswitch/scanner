package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pqswitch/scanner/internal/config"
	"github.com/pqswitch/scanner/internal/ml"
	"github.com/pqswitch/scanner/internal/scanner"
	"github.com/pqswitch/scanner/internal/types"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan with intelligent source detection and layered crypto analysis",
	Long: `Performs comprehensive scanning that includes:
- Intelligent source code detection  
- Multi-layered crypto vulnerability detection (L0/L1/L2)
- ML-powered confidence scoring and false positive reduction
- Performance benchmarking and optimization
- Dependency vulnerability scanning (when enabled)

Layered Detection Pipeline:
- L0: Regex pre-filtering (fast initial detection)
- L1: AST-based analysis (structural pattern matching)  
- L2: Data flow analysis (taint tracking and inter-procedural)

This scanner automatically excludes non-source code directories and files 
like node_modules, vendor, build outputs, etc.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

var scanConfig struct {
	// Core scanning options
	enableL1      bool
	enableL2      bool
	enableAST     bool
	minConfidence float64
	topFindings   int
	showBenchmark bool

	// Output options
	outputFile      string
	outputFormat    string
	legacyFormat    bool
	verbose         bool
	showProjectInfo bool

	// Dependency scanning
	includeDependencies bool
	useExternalTools    bool
	snykToken           string

	// Advanced options
	parallel    int
	maxFileSize int64
	enableML    bool
}

func init() {
	rootCmd.AddCommand(scanCmd)

	// Core scanning flags (as documented in README)
	scanCmd.Flags().BoolVar(&scanConfig.enableL1, "enable-l1", true, "Enable L1 AST-based analysis (default: true)")
	scanCmd.Flags().BoolVar(&scanConfig.enableL2, "enable-l2", false, "Enable L2 data flow analysis (default: false)")
	scanCmd.Flags().BoolVar(&scanConfig.enableAST, "enable-ast", false, "Enable AST parsing (same as --enable-l1)")
	scanCmd.Flags().Float64Var(&scanConfig.minConfidence, "min-confidence", 0.5, "Minimum confidence threshold (0.0-1.0)")
	scanCmd.Flags().IntVar(&scanConfig.topFindings, "top-findings", 1000, "Maximum number of findings to report")
	scanCmd.Flags().BoolVar(&scanConfig.showBenchmark, "show-benchmark", false, "Show performance benchmarking results")

	// Output flags
	scanCmd.Flags().StringVar(&scanConfig.outputFile, "output-file", "", "Output file path")
	scanCmd.Flags().StringVar(&scanConfig.outputFormat, "output", "json", "Output format (json, pretty, sarif)")
	scanCmd.Flags().BoolVar(&scanConfig.legacyFormat, "legacy-format", false, "Use legacy API-compatible output format")
	scanCmd.Flags().BoolVar(&scanConfig.verbose, "verbose", false, "Verbose output")
	scanCmd.Flags().BoolVar(&scanConfig.showProjectInfo, "show-project-info", false, "Show detected project information")

	// Dependency scanning flags
	scanCmd.Flags().BoolVar(&scanConfig.includeDependencies, "include-deps", false, "Include dependency vulnerability scanning")
	scanCmd.Flags().BoolVar(&scanConfig.useExternalTools, "external-tools", false, "Use external tools for dependency scanning")
	scanCmd.Flags().StringVar(&scanConfig.snykToken, "snyk-token", "", "Snyk API token for enhanced dependency scanning")

	// Advanced flags
	scanCmd.Flags().IntVar(&scanConfig.parallel, "parallel", 0, "Number of parallel workers (0 = auto)")
	scanCmd.Flags().Int64Var(&scanConfig.maxFileSize, "max-file-size", 0, "Maximum file size to scan in bytes (0 = use config default)")
	scanCmd.Flags().BoolVar(&scanConfig.enableML, "enable-ml", false, "Enable ML-enhanced detection (experimental)")
}

func runScan(cmd *cobra.Command, args []string) error {
	scanPath := "."
	if len(args) > 0 {
		scanPath = args[0]
	}

	// Validate path
	if _, err := os.Stat(scanPath); os.IsNotExist(err) {
		return fmt.Errorf("scan path does not exist: %s", scanPath)
	}

	// Initialize configuration
	cfg, err := initializeScanConfig(scanPath)
	if err != nil {
		return err
	}

	// Create detector
	layeredDetector := scanner.NewLayeredDetector(cfg)

	// Detect project structure
	projectInfo, err := analyzeEnhancedProjectStructure(scanPath)
	if err != nil {
		return err
	}

	// Collect files to scan
	files, err := collectFilesToScan(scanPath, projectInfo, cfg)
	if err != nil {
		return err
	}

	// Load rules
	if err := layeredDetector.LoadRules(cfg.Rules.DefaultRulesPath); err != nil {
		return fmt.Errorf("failed to load rules into detector: %w", err)
	}

	// Perform crypto scanning
	cryptoFindings, cryptoErrors, scanDuration, err := performCryptoScan(layeredDetector, files)
	if err != nil {
		return err
	}

	// Apply filtering
	filteredFindings := filterFindings(cryptoFindings, scanConfig.minConfidence, scanConfig.topFindings)

	if scanConfig.verbose {
		fmt.Printf("📊 Scan Results: %d findings found, %d after filtering (%.1fs)\n",
			len(cryptoFindings), len(filteredFindings), scanDuration.Seconds())
	}

	// Perform dependency scanning if enabled
	dependencyResults, err := performDependencyScanning(scanPath)
	if err != nil {
		return err
	}

	// Generate and output results
	result := &scanner.EnhancedScanResult{
		ProjectInfo:       projectInfo,
		CryptoFindings:    filteredFindings,
		CryptoErrors:      cryptoErrors,
		DependencyResults: dependencyResults,
		ScanTime:          time.Now(),
		Duration:          scanDuration,
	}

	// Show benchmark data if requested
	showBenchmarkResults(files, cryptoFindings, filteredFindings, scanDuration)

	return outputResults(result)
}

// initializeScanConfig initializes and configures the scan settings
func initializeScanConfig(scanPath string) (*config.Config, error) {
	if scanConfig.verbose {
		fmt.Printf("🔍 Starting PQSwitch scan of: %s\n", scanPath)
		fmt.Printf("📋 Configuration:\n")
		fmt.Printf("  • L1 (AST): %v\n", scanConfig.enableL1 || scanConfig.enableAST)
		fmt.Printf("  • L2 (Data Flow): %v\n", scanConfig.enableL2)
		fmt.Printf("  • Min Confidence: %.2f\n", scanConfig.minConfidence)
		fmt.Printf("  • Max Findings: %d\n", scanConfig.topFindings)
		fmt.Printf("  • Benchmarking: %v\n", scanConfig.showBenchmark)
		fmt.Println()
	}

	// Load and customize configuration
	cfg := config.Load()

	// Apply CLI overrides to configuration
	if scanConfig.parallel > 0 {
		cfg.Scanner.Parallel = scanConfig.parallel
	}
	if scanConfig.maxFileSize > 0 {
		cfg.Scanner.MaxFileSize = scanConfig.maxFileSize
	}

	// Enable AST if L1 or explicit AST flag is set
	cfg.Scanner.EnableAST = scanConfig.enableL1 || scanConfig.enableAST

	// Enable data flow analysis if L2 is set
	cfg.Scanner.EnableDataFlow = scanConfig.enableL2

	// Show ML enhancement status
	if scanConfig.enableML {
		if scanConfig.verbose {
			fmt.Println("🧠 Enabling ML-enhanced detection...")
		}
	}

	return cfg, nil
}

// analyzeEnhancedProjectStructure detects and analyzes project structure
func analyzeEnhancedProjectStructure(scanPath string) (*scanner.ProjectInfo, error) {
	if scanConfig.verbose {
		fmt.Println("📋 Analyzing project structure...")
	}

	sourceDetector := scanner.NewSourceDetector(scanPath)
	projectInfo, err := sourceDetector.DetectProject()
	if err != nil {
		return nil, fmt.Errorf("failed to detect project structure: %w", err)
	}

	if scanConfig.showProjectInfo {
		printProjectInfo(projectInfo)
	}

	return projectInfo, nil
}

// collectFilesToScan collects files to be scanned based on path type
func collectFilesToScan(scanPath string, projectInfo *scanner.ProjectInfo, cfg *config.Config) ([]string, error) {
	if scanConfig.verbose {
		fmt.Println("🔐 Scanning for crypto vulnerabilities...")
		if scanConfig.enableML {
			fmt.Println("🧠 ML enhancements will be applied to findings...")
		}
	}

	// Check if scanPath is a specific file or directory
	fileInfo, err := os.Stat(scanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat scan path: %w", err)
	}

	if fileInfo.IsDir() {
		return collectFilesFromDirectory(scanPath, projectInfo, cfg)
	}

	// For specific files, bypass exclusion patterns and scan the file directly
	if scanConfig.verbose {
		fmt.Printf("📄 Scanning specific file: %s\n", scanPath)
	}
	return []string{scanPath}, nil
}

// collectFilesFromDirectory collects files from a directory with exclusion patterns
func collectFilesFromDirectory(scanPath string, projectInfo *scanner.ProjectInfo, cfg *config.Config) ([]string, error) {
	sourceDetector := scanner.NewSourceDetector(scanPath)

	// For directories, apply enhanced ignore patterns
	enhancedIgnorePatterns := sourceDetector.GetEnhancedIgnorePatterns()
	cfg.Scanner.IgnorePatterns = append(cfg.Scanner.IgnorePatterns, enhancedIgnorePatterns...)

	if scanConfig.verbose {
		fmt.Printf("📁 Found %d files to scan (after applying %d exclusion patterns)\n",
			len(projectInfo.SourceDirectories), len(enhancedIgnorePatterns))
	}

	// Create fallback detector for file collection
	fallbackDetector := scanner.NewDetector(cfg)
	if err := fallbackDetector.LoadRules(cfg.Rules.DefaultRulesPath); err != nil {
		return nil, fmt.Errorf("failed to load rules: %w", err)
	}

	// Collect files using fallback detector
	files, err := fallbackDetector.CollectFiles(scanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to collect files: %w", err)
	}

	return files, nil
}

// performCryptoScan performs the actual crypto vulnerability scanning
func performCryptoScan(layeredDetector *scanner.LayeredDetector, files []string) ([]types.Finding, []string, time.Duration, error) {
	startTime := time.Now()
	var cryptoFindings []types.Finding
	var cryptoErrors []string

	ctx := context.Background()
	for i, file := range files {
		if scanConfig.verbose && i%50 == 0 {
			fmt.Printf("📄 Scanning file %d/%d...\n", i+1, len(files))
		}

		findings, err := scanSingleFile(ctx, layeredDetector, file)
		if err != nil {
			cryptoErrors = append(cryptoErrors, fmt.Sprintf("analysis failed for %s: %v", file, err))
			continue
		}

		cryptoFindings = append(cryptoFindings, findings...)
	}

	return cryptoFindings, cryptoErrors, time.Since(startTime), nil
}

// scanSingleFile scans a single file for crypto vulnerabilities
func scanSingleFile(ctx context.Context, layeredDetector *scanner.LayeredDetector, file string) ([]types.Finding, error) {
	// Create file context for analysis
	content, err := os.ReadFile(file) //nolint:gosec // Legitimate file reading for scanner functionality
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", file, err)
	}

	fileCtx := &scanner.FileContext{
		FilePath:    file,
		Content:     content,
		Language:    getLanguageFromExtension(file),
		IsVendored:  isVendorFile(file),
		IsGenerated: isGeneratedFile(file),
		IsTest:      isTestFile(file),
	}

	// Analyze file with detection
	result, err := layeredDetector.AnalyzeFile(ctx, fileCtx)
	if err != nil {
		return nil, err
	}

	// Apply ML enhancement if enabled
	findings := result.Findings
	if scanConfig.enableML {
		findings = applyMLEnhancements(findings)
	}

	return findings, nil
}

// performDependencyScanning performs dependency vulnerability scanning if enabled
func performDependencyScanning(scanPath string) ([]*scanner.DependencyScanResult, error) {
	if !scanConfig.includeDependencies {
		return nil, nil
	}

	if scanConfig.verbose {
		fmt.Println("📦 Scanning for dependency vulnerabilities...")
	}

	depConfig := &scanner.DependencyScanConfig{
		UseExternalTools: scanConfig.useExternalTools,
		SnykToken:        scanConfig.snykToken,
		TimeoutMinutes:   5,
		ScanDevDeps:      false,
	}

	depManager := scanner.NewDependencyScannerManager(depConfig)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	dependencyResults, err := depManager.ScanProject(ctx, scanPath)
	if err != nil {
		fmt.Printf("⚠️  Warning: Dependency scanning failed: %v\n", err)
		return nil, nil // Don't fail the entire scan for dependency issues
	}

	return dependencyResults, nil
}

// showBenchmarkResults displays benchmark information if requested
func showBenchmarkResults(files []string, cryptoFindings, filteredFindings []types.Finding, scanDuration time.Duration) {
	if !scanConfig.showBenchmark || !scanConfig.verbose {
		return
	}

	fmt.Printf("📊 Benchmark Results:\n")
	fmt.Printf("  • Total Duration: %.2fs\n", scanDuration.Seconds())
	fmt.Printf("  • Files Scanned: %d\n", len(files))
	fmt.Printf("  • Findings Found: %d\n", len(cryptoFindings))
	fmt.Printf("  • Findings After Filter: %d\n", len(filteredFindings))
	fmt.Printf("  • Confidence Threshold: %.2f\n", scanConfig.minConfidence)
	fmt.Println()
}

// filterFindings applies confidence and limit filtering with intelligent prioritization
func filterFindings(findings []types.Finding, minConfidence float64, maxFindings int) []types.Finding {
	var filtered []types.Finding

	for _, finding := range findings {
		// Apply confidence threshold
		if finding.Confidence >= minConfidence {
			filtered = append(filtered, finding)
		}
	}

	// Apply intelligent prioritization if we need to limit findings
	if maxFindings > 0 && len(filtered) > maxFindings {
		filtered = prioritizeFindings(filtered, maxFindings)
	}

	return filtered
}

// applyMLEnhancements applies ML enhancements to findings
func applyMLEnhancements(findings []types.Finding) []types.Finding {
	// Import ML models
	mlModels := ml.NewMLModels()

	enhanced := make([]types.Finding, len(findings))
	for i, finding := range findings {
		// Convert finding to map for ML processing
		findingMap := map[string]interface{}{
			"algorithm":   finding.Algorithm,
			"severity":    finding.Severity,
			"confidence":  finding.Confidence,
			"crypto_type": finding.CryptoType,
			"language":    getLanguageFromExtension(finding.File),
			"rule_id":     finding.RuleID,
			"line":        float64(finding.Line),
			"file":        finding.File,
			"pattern":     getPatternFromMetadata(finding.Metadata),
			"message":     finding.Message,
			"context":     finding.Context,
		}

		// Apply ML enhancements
		enhancedMap := ml.EnhanceFindingWithML(findingMap, mlModels)

		// Update finding with ML predictions
		enhanced[i] = finding
		if enhanced[i].Metadata == nil {
			enhanced[i].Metadata = make(map[string]string)
		}

		if fpScore, ok := enhancedMap["ml_false_positive_score"].(float64); ok {
			enhanced[i].Metadata["ml_false_positive_score"] = fmt.Sprintf("%.3f", fpScore)

			// Adjust confidence based on ML prediction
			if fpScore < 0.3 {
				// High likelihood of false positive - reduce confidence
				enhanced[i].Confidence *= 0.5
				enhanced[i].Metadata["ml_adjustment"] = "confidence_reduced_likely_fp"
			} else if fpScore > 0.8 {
				// High likelihood of valid finding - boost confidence
				enhanced[i].Confidence = min(1.0, enhanced[i].Confidence*1.2)
				enhanced[i].Metadata["ml_adjustment"] = "confidence_boosted_likely_valid"
			}
		}

		if confClass, ok := enhancedMap["ml_confidence_class"].(string); ok {
			enhanced[i].Metadata["ml_confidence_class"] = confClass
		}

		if sevClass, ok := enhancedMap["ml_predicted_severity"].(string); ok {
			enhanced[i].Metadata["ml_predicted_severity"] = sevClass
		}

		// Add ML enhancement marker
		enhanced[i].Metadata["ml_enhanced"] = "true"
	}

	return enhanced
}

// Helper functions for ML enhancement
func getPatternFromMetadata(metadata map[string]string) string {
	if pattern, exists := metadata["pattern"]; exists {
		return pattern
	}
	if matchText, exists := metadata["match_text"]; exists {
		return matchText
	}
	return ""
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func printProjectInfo(info *scanner.ProjectInfo) {
	fmt.Println("\n📊 Project Analysis:")
	fmt.Printf("  Languages detected: %d\n", len(info.Languages))
	for _, lang := range info.Languages {
		fmt.Printf("    • %s (confidence: %.1f%%, %d files)\n",
			lang.Language, lang.Confidence*100, len(lang.Files))
	}

	if len(info.PackageManagers) > 0 {
		fmt.Printf("  Package managers: %v\n", info.PackageManagers)
	}

	if len(info.SourceDirectories) > 0 {
		fmt.Printf("  Source directories: %v\n", info.SourceDirectories)
	}

	fmt.Printf("  Exclusion patterns applied: %d\n", len(info.ExcludedPaths))
	fmt.Println()
}

func outputResults(result *scanner.EnhancedScanResult) error {
	switch scanConfig.outputFormat {
	case "json":
		return outputJSON(result)
	case "pretty":
		return outputPretty(result)
	case "sarif":
		return outputSarif(result)
	default:
		return fmt.Errorf("unsupported output format: %s", scanConfig.outputFormat)
	}
}

func outputJSON(result *scanner.EnhancedScanResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if scanConfig.outputFile == "" {
		fmt.Println(string(data))
		return nil
	}

	return os.WriteFile(scanConfig.outputFile, data, 0600)
}

func outputPretty(result *scanner.EnhancedScanResult) error {
	fmt.Println("\n🔍 Scan Results")
	fmt.Println("=" + strings.Repeat("=", 40))

	// Project info summary
	fmt.Printf("📋 Project: %d languages, %d package managers\n",
		len(result.ProjectInfo.Languages),
		len(result.ProjectInfo.PackageManagers))

	// Crypto findings summary
	summary := result.GetVulnerabilitySummary()
	fmt.Printf("🔐 Crypto Issues: %d critical, %d high, %d medium, %d low\n",
		summary["crypto_critical"], summary["crypto_high"],
		summary["crypto_medium"], summary["crypto_low"])

	// Dependency findings summary
	if len(result.DependencyResults) > 0 {
		fmt.Printf("📦 Dependency Issues: %d critical, %d high, %d medium, %d low\n",
			summary["dep_critical"], summary["dep_high"],
			summary["dep_medium"], summary["dep_low"])
	}

	fmt.Printf("⏱️  Scan completed in %v\n", result.Duration)

	// Detailed crypto findings
	if len(result.CryptoFindings) > 0 {
		fmt.Println("\n🔐 Crypto Vulnerabilities:")
		for _, finding := range result.CryptoFindings {
			severity := getSeverityEmoji(finding.Severity)
			fmt.Printf("  %s %s:%d - %s\n", severity,
				filepath.Base(finding.File), finding.Line, finding.Message)
			if finding.Algorithm != "" {
				fmt.Printf("     Algorithm: %s\n", finding.Algorithm)
			}
		}
	}

	// Detailed dependency findings
	for _, depResult := range result.DependencyResults {
		if len(depResult.Vulnerabilities) > 0 {
			fmt.Printf("\n📦 %s Dependencies:\n", depResult.PackageManager)
			for _, vuln := range depResult.Vulnerabilities {
				severity := getSeverityEmoji(vuln.Severity)
				fmt.Printf("  %s %s@%s - %s\n", severity,
					vuln.Package, vuln.Version, vuln.Title)
			}
		}
	}

	// Errors
	if len(result.CryptoErrors) > 0 {
		fmt.Println("\n⚠️  Scan Errors:")
		for _, err := range result.CryptoErrors {
			fmt.Printf("  • %s\n", err)
		}
	}

	return nil
}

func outputSarif(result *scanner.EnhancedScanResult) error {
	// SARIF (Static Analysis Results Interchange Format) output
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "PQSwitch",
						"version": "2.0.0",
						"rules": []map[string]interface{}{
							{
								"id":               "pqswitch-crypto",
								"name":             "CryptographicVulnerability",
								"shortDescription": map[string]string{"text": "Cryptographic vulnerability detected"},
								"fullDescription":  map[string]string{"text": "Classical cryptographic implementation that needs post-quantum migration"},
							},
						},
					},
				},
				"results": []map[string]interface{}{},
			},
		},
	}

	// Convert findings to SARIF format
	var results []map[string]interface{}
	for _, finding := range result.CryptoFindings {
		sarifResult := map[string]interface{}{
			"ruleId":    finding.RuleID,
			"ruleIndex": 0,
			"message":   map[string]string{"text": finding.Message},
			"level":     getSarifLevel(finding.Severity),
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{
							"uri": finding.File,
						},
						"region": map[string]interface{}{
							"startLine":   finding.Line,
							"startColumn": finding.Column,
						},
					},
				},
			},
			"properties": map[string]interface{}{
				"algorithm":  finding.Algorithm,
				"cryptoType": finding.CryptoType,
				"confidence": finding.Confidence,
				"suggestion": finding.Suggestion,
			},
		}
		results = append(results, sarifResult)
	}

	// Add results to SARIF structure
	sarif["runs"].([]map[string]interface{})[0]["results"] = results

	// Output SARIF
	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SARIF: %w", err)
	}

	if scanConfig.outputFile == "" {
		fmt.Println(string(data))
		return nil
	}

	return os.WriteFile(scanConfig.outputFile, data, 0600)
}

// getSarifLevel converts severity to SARIF level
func getSarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	default:
		return "note"
	}
}

func getSeverityEmoji(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	default:
		return "⚪"
	}
}

// Helper functions for file analysis
func getLanguageFromExtension(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".go":
		return "go"
	case ".js", ".mjs", ".jsx":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".py":
		return "python"
	case ".java":
		return "java"
	case ".kt":
		return "kotlin"
	case ".rs":
		return "rust"
	case ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp":
		return "cpp"
	case ".cs":
		return "csharp"
	case ".rb":
		return "ruby"
	case ".php":
		return "php"
	default:
		return "unknown"
	}
}
