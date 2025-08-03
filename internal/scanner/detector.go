package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pqswitch/scanner/internal/ast"
	"github.com/pqswitch/scanner/internal/classifier"
	"github.com/pqswitch/scanner/internal/config"
	"github.com/pqswitch/scanner/internal/types"
)

// Config holds scan configuration
type Config struct {
	Path         string
	OutputFormat string
	OutputFile   string
	RulesPath    string
	Verbose      bool
}

// Detector is the main scanning engine
type Detector struct {
	config             *config.Config
	rules              *RuleEngine
	ast                *ast.TreeSitter
	enhancedClassifier *classifier.EnhancedClassifier
}

// NewDetector creates a new detector instance
func NewDetector(cfg *config.Config) *Detector {
	detector := &Detector{
		config:             cfg,
		rules:              NewRuleEngine(cfg),
		enhancedClassifier: classifier.NewEnhancedClassifier(),
	}

	// Only initialize AST if it's enabled to avoid tree-sitter crashes
	if cfg.Scanner.EnableAST {
		detector.ast = ast.NewTreeSitter()
	}

	return detector
}

// Scan performs the main scanning operation
func (d *Detector) Scan(scanConfig *Config) error {
	startTime := time.Now()

	if scanConfig.Verbose {
		fmt.Printf("Starting scan of: %s\n", scanConfig.Path)
	}

	// Load rules
	if err := d.rules.LoadRules(scanConfig.RulesPath); err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	// Collect files to scan
	files, err := d.CollectFiles(scanConfig.Path)
	if err != nil {
		return fmt.Errorf("failed to collect files: %w", err)
	}

	if scanConfig.Verbose {
		fmt.Printf("Found %d files to scan\n", len(files))
	}

	// Scan files
	findings, errors := d.ScanFiles(files, scanConfig.Verbose)

	// Enhanced classification and risk scoring
	for i := range findings {
		// Store original rule-based severity for context-aware rules
		originalSeverity := findings[i].Severity

		result := d.enhancedClassifier.ClassifyFinding(&findings[i])
		findings[i].Confidence = result.Confidence
		findings[i].Algorithm = result.Algorithm
		findings[i].CryptoType = result.CryptoType
		findings[i].KeySize = result.KeySize

		// Preserve context-aware severity for specific rule types
		// If the original rule provided context-aware analysis, don't override
		if d.isContextAwareRule(findings[i].RuleID) {
			findings[i].Severity = originalSeverity
		} else {
			findings[i].Severity = result.Severity
		}

		// Add enhanced metadata
		if findings[i].Metadata == nil {
			findings[i].Metadata = make(map[string]string)
		}
		findings[i].Metadata["quantum_vulnerable"] = fmt.Sprintf("%t", result.QuantumVulnerable)
		findings[i].Metadata["deprecated"] = fmt.Sprintf("%t", result.Deprecated)

		// Add migration recommendations
		if len(result.MigrationPath.Recommended) > 0 {
			findings[i].Metadata["recommended_migration"] = strings.Join(result.MigrationPath.Recommended, ", ")
		}
	}

	// Generate scan result
	result := &types.ScanResult{
		Summary:  d.GenerateSummary(files, findings, time.Since(startTime)),
		Findings: findings,
		Errors:   errors,
		Metadata: types.ScanMetadata{
			Version:     "dev",
			ScanPath:    scanConfig.Path,
			StartTime:   startTime,
			EndTime:     time.Now(),
			RulesLoaded: d.rules.Count(),
			Config: map[string]interface{}{
				"output_format": scanConfig.OutputFormat,
				"rules_path":    scanConfig.RulesPath,
			},
		},
	}

	// Generate output
	return d.generateOutput(result, scanConfig)
}

// CollectFiles recursively collects files to scan
func (d *Detector) CollectFiles(path string) ([]string, error) {
	var files []string

	err := filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Check if file should be ignored
		if d.shouldIgnoreFile(filePath) {
			return nil
		}

		// Check file size
		if info.Size() > d.config.Scanner.MaxFileSize {
			return nil
		}

		files = append(files, filePath)
		return nil
	})

	return files, err
}

// shouldIgnoreFile checks if a file should be ignored based on patterns
func (d *Detector) shouldIgnoreFile(filePath string) bool {
	// Check configured ignore patterns
	for _, pattern := range d.config.Scanner.IgnorePatterns {
		if matched, _ := filepath.Match(pattern, filePath); matched {
			return true
		}
		if strings.Contains(filePath, strings.TrimSuffix(pattern, "*")) {
			return true
		}
	}

	// Smart binary file detection - ignore common binary/media file types
	if d.isBinaryFile(filePath) {
		return true
	}

	return false
}

// isBinaryFile determines if a file is binary and should be skipped
func (d *Detector) isBinaryFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))

	// Image files
	imageExts := []string{
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif",
		".webp", ".svg", ".ico", ".cur", ".psd", ".raw",
	}

	// Video files
	videoExts := []string{
		".mp4", ".avi", ".mov", ".wmv", ".flv", ".webm", ".mkv",
		".m4v", ".3gp", ".ogv", ".f4v",
	}

	// Audio files
	audioExts := []string{
		".mp3", ".wav", ".flac", ".aac", ".ogg", ".wma", ".m4a",
		".opus", ".amr", ".aiff",
	}

	// Archive files
	archiveExts := []string{
		".zip", ".tar", ".gz", ".rar", ".7z", ".bz2", ".xz",
		".lz", ".z", ".jar", ".war", ".ear",
	}

	// Binary/executable files
	binaryExts := []string{
		".exe", ".dll", ".so", ".dylib", ".bin", ".out", ".app",
		".deb", ".rpm", ".msi", ".dmg", ".pkg", ".apk",
	}

	// Font files
	fontExts := []string{
		".ttf", ".otf", ".woff", ".woff2", ".eot",
	}

	// Database files
	dbExts := []string{
		".db", ".sqlite", ".sqlite3", ".mdb", ".accdb",
	}

	// Office/document files (often contain binary data)
	officeExts := []string{
		".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".pdf", ".odt", ".ods", ".odp",
	}

	// Combine all binary extensions
	allBinaryExts := make([]string, 0, len(imageExts)+len(videoExts)+len(audioExts)+len(archiveExts)+len(binaryExts)+len(fontExts)+len(dbExts)+len(officeExts))
	allBinaryExts = append(allBinaryExts, imageExts...)
	allBinaryExts = append(allBinaryExts, videoExts...)
	allBinaryExts = append(allBinaryExts, audioExts...)
	allBinaryExts = append(allBinaryExts, archiveExts...)
	allBinaryExts = append(allBinaryExts, binaryExts...)
	allBinaryExts = append(allBinaryExts, fontExts...)
	allBinaryExts = append(allBinaryExts, dbExts...)
	allBinaryExts = append(allBinaryExts, officeExts...)

	// Check if file extension matches any binary type
	for _, binExt := range allBinaryExts {
		if ext == binExt {
			return true
		}
	}

	// Additional check: if filename suggests binary content
	filename := strings.ToLower(filepath.Base(filePath))
	binaryPatterns := []string{
		"binary", "compiled", "minified", "compressed",
	}

	for _, pattern := range binaryPatterns {
		if strings.Contains(filename, pattern) {
			return true
		}
	}

	return false
}

// isContextAwareRule checks if a rule provides context-aware severity analysis
func (d *Detector) isContextAwareRule(ruleID string) bool {
	// These rules perform intelligent context analysis and should preserve their severity
	contextAwareRules := []string{
		"dnssec-protocol-sha1",           // DNSSEC protocol compliance (INFO)
		"dns-tls-client-usage",           // DNS-over-TLS implementation (INFO)
		"crypto-protocol-implementation", // Protocol implementation (INFO)
		"system-service-crypto",          // System service context (INFO)
		"weak-hash-md5-test-context",     // Test context (INFO)
		"tls-version-test-context",       // TLS test context (INFO)
		"tls-config-kconfig",             // Build configuration (INFO)
		"tls-cipher-config",              // Cipher configuration (INFO)
		"tls-enum-definition",            // Protocol definitions (INFO)
		"crypto-implementation-context",  // Implementation detection (INFO)
		"comment-crypto-mention",         // Comment mentions (INFO)
		"third-party-crypto-module",      // Third-party modules (INFO)
	}

	for _, contextRule := range contextAwareRules {
		if ruleID == contextRule {
			return true
		}
	}
	return false
}

// ScanFiles scans multiple files concurrently using a worker pool
func (d *Detector) ScanFiles(files []string, verbose bool) ([]types.Finding, []string) {
	if len(files) == 0 {
		return []types.Finding{}, []string{}
	}

	var findings []types.Finding
	var errors []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Determine optimal number of workers
	numWorkers := d.config.Scanner.Parallel
	if numWorkers <= 0 {
		numWorkers = 4 // Default fallback
	}
	if numWorkers > len(files) {
		numWorkers = len(files) // Don't create more workers than files
	}

	// Create channels for work distribution - buffer size ensures no blocking
	workChan := make(chan string, len(files))       // Can hold all work items
	resultChan := make(chan scanResult, len(files)) // Can hold all results

	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			for filePath := range workChan {
				if verbose {
					fmt.Printf("Worker %d processing: %s\n", workerID, filePath)
				}

				// Safely scan file with recovery from panics
				func() {
					defer func() {
						if r := recover(); r != nil {
							// Send error result if worker panics
							resultChan <- scanResult{
								filePath: filePath,
								findings: []types.Finding{},
								err:      fmt.Errorf("worker panic: %v", r),
							}
						}
					}()

					fileFindings, err := d.scanFile(filePath)

					result := scanResult{
						filePath: filePath,
						findings: fileFindings,
						err:      err,
					}

					resultChan <- result
				}()
			}
		}(i)
	}

	// Send all work items to channel
	go func() {
		defer close(workChan)
		for _, file := range files {
			workChan <- file
		}
	}()

	// Wait for all workers to complete
	wg.Wait()

	// Collect all results (we know exactly how many to expect)
	for i := 0; i < len(files); i++ {
		result := <-resultChan

		if result.err != nil {
			mu.Lock()
			errors = append(errors, fmt.Sprintf("%s: %v", result.filePath, result.err))
			mu.Unlock()
		} else {
			mu.Lock()
			findings = append(findings, result.findings...)
			mu.Unlock()
		}
	}

	return findings, errors
}

// scanResult holds the result of scanning a single file
type scanResult struct {
	filePath string
	findings []types.Finding
	err      error
}

// scanFile scans a single file
func (d *Detector) scanFile(filePath string) ([]types.Finding, error) {
	// Quick binary content check for files without clear extensions
	if !d.hasKnownTextExtension(filePath) {
		if isBinary, err := d.isFileContentBinary(filePath); err == nil && isBinary {
			// Skip binary files silently
			return []types.Finding{}, nil
		}
	}

	content, err := os.ReadFile(filePath) //nolint:gosec // Legitimate file reading for scanner functionality
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var allFindings []types.Finding

	// Always run regex scanning for basic pattern matching
	regexFindings := d.scanWithRegex(filePath, content)
	allFindings = append(allFindings, regexFindings...)

	// Additionally run AST scanning if language is supported, AST is enabled, and AST is initialized
	language := d.detectLanguage(filePath)
	if language != "" && d.config.Scanner.EnableAST && d.ast != nil {
		astFindings, err := d.scanWithAST(filePath, content, language)
		if err != nil {
			// If AST parsing fails, log but don't fail the entire scan
			// We still have regex results
			fmt.Printf("Warning: AST parsing failed for %s: %v\n", filePath, err)
		} else {
			allFindings = append(allFindings, astFindings...)
		}
	}

	// Apply global deduplication and context-aware severity adjustment
	finalFindings := d.deduplicateAndAdjustFindings(allFindings, filePath)

	return finalFindings, nil
}

// deduplicateAndAdjustFindings removes duplicates and applies context-aware severity
func (d *Detector) deduplicateAndAdjustFindings(findings []types.Finding, filePath string) []types.Finding {
	// Step 1: Deduplicate findings based on file, line, column, and message
	dedupeMap := make(map[string]types.Finding)

	for _, finding := range findings {
		// Create a comprehensive key for deduplication
		key := fmt.Sprintf("%s:%d:%d:%s:%s",
			finding.File, finding.Line, finding.Column,
			finding.RuleID, finding.Message)

		// Keep the finding with highest confidence if duplicates exist
		if existing, exists := dedupeMap[key]; exists {
			if finding.Confidence > existing.Confidence {
				dedupeMap[key] = finding
			}
		} else {
			dedupeMap[key] = finding
		}
	}

	// Step 2: Apply context-aware severity adjustment
	var adjustedFindings []types.Finding
	isOpenSSLContext := d.isOpenSSLContext(filePath)
	isCryptoLibraryContext := d.isCryptoLibraryContext(filePath)

	for _, finding := range dedupeMap {
		// Apply context-aware severity adjustment
		if isOpenSSLContext || isCryptoLibraryContext {
			finding = d.adjustSeverityForCryptoLibrary(finding, filePath)
		}

		adjustedFindings = append(adjustedFindings, finding)
	}

	return adjustedFindings
}

// isOpenSSLContext detects if we're scanning OpenSSL source code
func (d *Detector) isOpenSSLContext(filePath string) bool {
	pathLower := strings.ToLower(filePath)

	// Direct OpenSSL detection
	if strings.Contains(pathLower, "openssl") {
		return true
	}

	// OpenSSL-specific patterns
	openSSLIndicators := []string{
		"crypto/", "/ssl/", "/evp/", "/bn/", "/dh/", "/ec/", "/rsa/",
		"/md5/", "/sha/", "/aes/", "/des/", "/blowfish/", "/rc4/",
		"libssl", "libcrypto", "ossl_", "OSSL_",
	}

	for _, indicator := range openSSLIndicators {
		if strings.Contains(pathLower, indicator) {
			return true
		}
	}

	return false
}

// isCryptoLibraryContext detects if we're scanning any major crypto library
func (d *Detector) isCryptoLibraryContext(filePath string) bool {
	pathLower := strings.ToLower(filePath)

	cryptoLibraryIndicators := []string{
		"boringssl", "libressl", "mbedtls", "wolfssl", "libsodium",
		"cryptopp", "crypto++", "bouncy", "conscrypt", "nettle",
		"gcrypt", "gnutls", "/crypto/", "/ssl/", "/tls/",
	}

	for _, indicator := range cryptoLibraryIndicators {
		if strings.Contains(pathLower, indicator) {
			return true
		}
	}

	return false
}

// adjustSeverityForCryptoLibrary adjusts severity for legitimate crypto library context
func (d *Detector) adjustSeverityForCryptoLibrary(finding types.Finding, filePath string) types.Finding {
	// Don't adjust severity for truly broken algorithms (MD5, SHA-1, DES)
	// These should remain CRITICAL even in crypto libraries for migration planning
	brokenAlgorithms := []string{"MD5", "SHA1", "DES", "3DES", "RC4"}
	for _, broken := range brokenAlgorithms {
		if strings.ToUpper(finding.Algorithm) == broken {
			// Keep CRITICAL severity but update message for library context
			finding.Message = fmt.Sprintf("%s implementation in crypto library. Plan migration strategy.",
				finding.Algorithm)
			if finding.Metadata == nil {
				finding.Metadata = make(map[string]string)
			}
			finding.Metadata["crypto_library_context"] = "true"
			finding.Metadata["migration_priority"] = "high"
			return finding
		}
	}

	// For quantum-vulnerable but not yet broken algorithms (RSA, ECDSA, AES)
	// Reduce severity in crypto library context
	quantumVulnerable := []string{"RSA", "ECDSA", "ECDH", "AES"}
	for _, qv := range quantumVulnerable {
		if strings.ToUpper(finding.Algorithm) == qv {
			// Reduce severity for crypto library implementations
			switch finding.Severity {
			case "critical":
				finding.Severity = "medium"
			case "high":
				finding.Severity = "low"
			case "medium":
				finding.Severity = "info"
			}

			finding.Message = fmt.Sprintf("%s implementation in crypto library. Monitor for post-quantum alternatives.",
				finding.Algorithm)
			if finding.Metadata == nil {
				finding.Metadata = make(map[string]string)
			}
			finding.Metadata["crypto_library_context"] = "true"
			finding.Metadata["legitimate_implementation"] = "true"
			finding.Metadata["migration_timeline"] = "long_term"
			return finding
		}
	}

	// For general crypto patterns in library context
	if finding.CryptoType == "symmetric" || finding.CryptoType == "asymmetric" {
		// Reduce severity for library implementations
		switch finding.Severity {
		case "critical":
			finding.Severity = "high"
		case "high":
			finding.Severity = "medium"
		case "medium":
			finding.Severity = "info"
		}

		finding.Message = "Crypto implementation in library context. Review for standards compliance."
		if finding.Metadata == nil {
			finding.Metadata = make(map[string]string)
		}
		finding.Metadata["crypto_library_context"] = "true"
		finding.Metadata["legitimate_implementation"] = "true"
	}

	return finding
}

// scanWithAST scans a file using AST analysis with robust error handling
func (d *Detector) scanWithAST(filePath string, content []byte, language string) (findings []types.Finding, err error) {
	// Safety check: ensure AST is initialized
	if d.ast == nil {
		return []types.Finding{}, fmt.Errorf("AST parser not initialized")
	}

	// Protect against crashes in tree-sitter C library
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("AST parsing crashed for %s: %v", filePath, r)
			findings = []types.Finding{}
		}
	}()

	// Skip AST parsing for very large files to avoid crashes
	const maxASTFileSize = 512 * 1024 // Reduced to 512KB limit for better stability
	if len(content) > maxASTFileSize {
		return []types.Finding{}, fmt.Errorf("file too large for AST parsing (%d bytes)", len(content))
	}

	// Skip AST parsing for files with null bytes (likely binary)
	for _, b := range content {
		if b == 0 {
			return []types.Finding{}, fmt.Errorf("file contains null bytes, likely binary")
		}
	}

	// Validate language is supported before parsing
	if !d.ast.SupportsLanguage(language) {
		return []types.Finding{}, fmt.Errorf("language %s not supported for AST parsing", language)
	}

	// Parse the file - now thread-safe since each call creates its own parser
	tree, err := d.ast.ParseToTree(string(content), language)
	if err != nil {
		return nil, fmt.Errorf("failed to parse file: %w", err)
	}
	if tree == nil {
		return nil, fmt.Errorf("parsing returned nil tree")
	}

	// Apply AST rules
	astRules := d.rules.GetASTRules(language)
	for _, rule := range astRules {
		// Protect each rule application
		func() {
			defer func() {
				if r := recover(); r != nil {
					// Log the error but continue with other rules
					fmt.Printf("Warning: AST rule %s crashed on %s: %v\n", rule.ID, filePath, r)
				}
			}()

			matches := d.ast.Query(tree, rule.Pattern, content)
			for _, match := range matches {
				finding := types.Finding{
					ID:         generateFindingID(),
					RuleID:     rule.ID,
					File:       filePath,
					Line:       match.Line,
					Column:     match.Column,
					Message:    rule.Message,
					Severity:   rule.Severity,
					Confidence: 0.7, // Higher default confidence for AST-based findings
					CryptoType: rule.CryptoType,
					Algorithm:  rule.Algorithm,
					Context:    match.Context,
					Suggestion: rule.Suggestion,
					References: rule.References,
					Timestamp:  time.Now(),
				}
				findings = append(findings, finding)
			}
		}()
	}

	return findings, nil
}

// scanWithRegex scans a file using regex patterns
func (d *Detector) scanWithRegex(filePath string, content []byte) []types.Finding {
	var findings []types.Finding
	contentStr := string(content)

	// Detect file language and type
	language := d.detectLanguage(filePath)
	isDocumentationFile := d.isDocumentationFile(filePath)

	for _, rule := range d.rules.GetRegexRules() {
		// Skip rules that don't apply to this file type
		if !d.shouldApplyRule(rule, language, filePath, isDocumentationFile) {
			continue
		}

		matches := rule.Regex.FindAllStringIndex(contentStr, -1)
		for _, match := range matches {
			line, column := d.getLineColumn(content, match[0])
			context := d.extractContext(content, match[0], match[1])

			finding := types.Finding{
				ID:         generateFindingID(),
				RuleID:     rule.ID,
				File:       filePath,
				Line:       line,
				Column:     column,
				Message:    rule.Message,
				Severity:   rule.Severity,
				Confidence: 0.5, // Default confidence for regex-based findings
				CryptoType: rule.CryptoType,
				Algorithm:  rule.Algorithm,
				Context:    context,
				Suggestion: rule.Suggestion,
				References: rule.References,
				Timestamp:  time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// detectLanguage detects the programming language of a file
func (d *Detector) detectLanguage(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".go":
		return "go"
	case ".java":
		return "java"
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	case ".py":
		return "python"
	case ".c":
		return "c"
	case ".cpp", ".cc", ".cxx":
		return "cpp"
	case ".rs":
		return "rust"
	case ".kt":
		return "kotlin"
	default:
		return ""
	}
}

// getLineColumn converts a byte offset to line and column numbers
func (d *Detector) getLineColumn(content []byte, offset int) (int, int) {
	line := 1
	column := 1

	for i := 0; i < offset; i++ {
		if content[i] == '\n' {
			line++
			column = 1
		} else {
			column++
		}
	}

	return line, column
}

// extractContext extracts the context around a match
func (d *Detector) extractContext(content []byte, start, end int) string {
	contextStart := start - 50
	if contextStart < 0 {
		contextStart = 0
	}

	contextEnd := end + 50
	if contextEnd > len(content) {
		contextEnd = len(content)
	}

	return string(content[contextStart:contextEnd])
}

// GenerateSummary generates a summary of the scan results
func (d *Detector) GenerateSummary(files []string, findings []types.Finding, duration time.Duration) types.ScanSummary {
	summary := types.ScanSummary{
		TotalFiles:         len(files),
		ScannedFiles:       len(files),
		TotalFindings:      len(findings),
		FindingsBySeverity: make(map[string]int),
		FindingsByType:     make(map[string]int),
		DurationSeconds:    duration.Seconds(),
	}

	for _, finding := range findings {
		summary.FindingsBySeverity[finding.Severity]++
		summary.FindingsByType[finding.CryptoType]++
	}

	// Calculate risk score
	totalWeight := 0.0
	weightedScore := 0.0

	severityWeights := map[string]float64{
		"critical": 1.0,
		"high":     0.8,
		"medium":   0.5,
		"low":      0.2,
		"info":     0.1,
	}

	for severity, count := range summary.FindingsBySeverity {
		weight := severityWeights[strings.ToLower(severity)]
		totalWeight += weight
		weightedScore += float64(count) * weight
	}

	if totalWeight > 0 {
		summary.RiskScore = weightedScore / totalWeight
	}

	return summary
}

// generateOutput generates the output in the specified format
func (d *Detector) generateOutput(result *types.ScanResult, scanConfig *Config) error {
	switch scanConfig.OutputFormat {
	case "json":
		return d.outputJSON(result, scanConfig.OutputFile)
	case "sarif":
		return d.outputSARIF(result, scanConfig.OutputFile)
	case "html":
		return d.outputHTML(result, scanConfig.OutputFile)
	default:
		return fmt.Errorf("unsupported output format: %s", scanConfig.OutputFormat)
	}
}

// outputJSON outputs the results in JSON format
func (d *Detector) outputJSON(result *types.ScanResult, outputFile string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if outputFile == "" {
		fmt.Println(string(data))
		return nil
	}

	return os.WriteFile(outputFile, data, 0600)
}

// outputSARIF outputs the results in SARIF format
func (d *Detector) outputSARIF(result *types.ScanResult, outputFile string) error {
	// TODO: Implement SARIF output
	return fmt.Errorf("SARIF output not implemented")
}

// outputHTML outputs the results in HTML format
func (d *Detector) outputHTML(result *types.ScanResult, outputFile string) error {
	// TODO: Implement HTML output
	return fmt.Errorf("HTML output not implemented")
}

// GetEnhancedClassifier returns the enhanced classifier instance
func (d *Detector) GetEnhancedClassifier() *classifier.EnhancedClassifier {
	return d.enhancedClassifier
}

// LoadRules loads rules from the specified path
func (d *Detector) LoadRules(rulesPath string) error {
	err := d.rules.LoadRules(rulesPath)
	if err != nil {
		return err
	}

	return nil
}

// GetRulesCount returns the number of loaded rules
func (d *Detector) GetRulesCount() int {
	return d.rules.Count()
}

// GetRuleStatistics returns rule statistics
func (d *Detector) GetRuleStatistics() map[string]interface{} {
	return d.rules.GetRuleStatistics()
}

// generateFindingID generates a unique finding ID
func generateFindingID() string {
	return fmt.Sprintf("F%d", time.Now().UnixNano())
}

// hasKnownTextExtension checks if a file has a known text file extension
func (d *Detector) hasKnownTextExtension(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))

	textExts := []string{
		// Programming languages
		".go", ".java", ".js", ".ts", ".py", ".rb", ".php", ".c", ".cpp", ".h", ".hpp",
		".rs", ".swift", ".kt", ".scala", ".cs", ".vb", ".fs", ".clj", ".ex", ".elixir",
		".lua", ".perl", ".r", ".julia", ".dart", ".nim", ".zig", ".crystal",

		// Web technologies
		".html", ".htm", ".css", ".scss", ".sass", ".less", ".jsx", ".tsx", ".vue",
		".svelte", ".astro",

		// Config/data files
		".json", ".yaml", ".yml", ".xml", ".toml", ".ini", ".cfg", ".conf", ".properties",
		".env", ".dotenv",

		// Documentation
		".md", ".txt", ".rst", ".org", ".adoc", ".tex",

		// Shell/scripts
		".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",

		// SQL
		".sql", ".ddl", ".dml",

		// Misc text formats
		".log", ".csv", ".tsv", ".gitignore", ".dockerignore",
	}

	for _, textExt := range textExts {
		if ext == textExt {
			return true
		}
	}

	// Check for common text filenames without extensions
	filename := strings.ToLower(filepath.Base(filePath))
	textFilenames := []string{
		"readme", "license", "changelog", "makefile", "dockerfile", "rakefile",
		"gemfile", "pipfile", "requirements", "setup", "manifest",
	}

	for _, textName := range textFilenames {
		if filename == textName {
			return true
		}
	}

	return false
}

// isFileContentBinary checks if file content appears to be binary
func (d *Detector) isFileContentBinary(filePath string) (bool, error) {
	// Read first 1024 bytes to check for binary content
	file, err := os.Open(filePath) //nolint:gosec // Legitimate file opening for scanner functionality
	if err != nil {
		return false, err
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			// Log the error but don't fail the function
			fmt.Printf("Warning: failed to close file %s: %v\n", filePath, closeErr)
		}
	}()

	buffer := make([]byte, 1024)
	n, err := file.Read(buffer)
	if err != nil && err.Error() != "EOF" {
		return false, err
	}

	// Check for null bytes (strong indicator of binary content)
	for i := 0; i < n; i++ {
		if buffer[i] == 0 {
			return true, nil
		}
	}

	// Check for high percentage of non-printable characters
	nonPrintable := 0
	for i := 0; i < n; i++ {
		if buffer[i] < 32 && buffer[i] != 9 && buffer[i] != 10 && buffer[i] != 13 {
			nonPrintable++
		}
	}

	// If more than 30% non-printable, likely binary
	if n > 0 && float64(nonPrintable)/float64(n) > 0.3 {
		return true, nil
	}

	return false, nil
}

// isDocumentationFile checks if a file is documentation and should be excluded from certain crypto rules
func (d *Detector) isDocumentationFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	filename := strings.ToLower(filepath.Base(filePath))

	// Documentation file extensions
	docExts := []string{
		".md", ".txt", ".rst", ".org", ".adoc", ".tex",
	}

	for _, docExt := range docExts {
		if ext == docExt {
			return true
		}
	}

	// Documentation filenames (without extensions)
	docFiles := []string{
		"readme", "changelog", "license", "copying", "authors",
		"contributors", "install", "news", "todo", "history",
	}

	for _, docFile := range docFiles {
		if strings.HasPrefix(filename, docFile) {
			return true
		}
	}

	// Documentation directories
	if strings.Contains(filePath, "/docs/") || strings.Contains(filePath, "/doc/") ||
		strings.Contains(filePath, "/documentation/") || strings.Contains(filePath, "/manual/") {
		return true
	}

	return false
}

// shouldApplyRule determines if a rule should be applied to a specific file
func (d *Detector) shouldApplyRule(rule RegexRule, language, filePath string, isDocumentationFile bool) bool {
	ruleID := rule.ID
	languages := rule.Languages

	// Special handling for documentation files
	if isDocumentationFile {
		// Documentation files should generally not trigger crypto security findings
		// as they contain explanatory text, not executable code

		// Only allow very specific documentation-related rules (currently none)
		docAllowedRules := []string{
			// Placeholder for future documentation-specific rules
			// "documentation-crypto-mention", // Future: detect crypto mentions in docs for inventory
		}

		for _, allowedRule := range docAllowedRules {
			if ruleID == allowedRule {
				return true
			}
		}

		// Skip all other crypto rules for documentation files
		return false
	}

	// If rule specifies languages, check if file language matches
	if len(languages) > 0 && language != "" {
		for _, ruleLanguage := range languages {
			if strings.EqualFold(ruleLanguage, language) {
				return true
			}
		}
		// File language doesn't match rule languages
		return false
	}

	// If no language specified or file language not detected, apply rule
	return true
}
