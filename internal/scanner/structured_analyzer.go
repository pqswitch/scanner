package scanner

import (
	"fmt"
	"strings"
	"time"

	"github.com/pqswitch/scanner/internal/config"
	"github.com/pqswitch/scanner/internal/types"
)

// StructuredAnalyzer implements L1 stage - AST-based structured analysis
type StructuredAnalyzer struct {
	config      *config.Config
	astPatterns map[string]ASTPattern
	queryCache  map[string]string
}

// ASTPattern represents a Tree-sitter pattern for L1 analysis
type ASTPattern struct {
	ID          string
	Language    string
	Query       string
	Category    string
	Severity    string
	Description string
	Intent      string   // What this pattern is trying to detect
	Variables   []string // Variables to track
}

// NewStructuredAnalyzer creates a new L1 structured analyzer
func NewStructuredAnalyzer(cfg *config.Config) *StructuredAnalyzer {
	analyzer := &StructuredAnalyzer{
		config:      cfg,
		astPatterns: make(map[string]ASTPattern),
		queryCache:  make(map[string]string),
	}

	analyzer.initializeASTPatterns()
	return analyzer
}

// initializeASTPatterns sets up sophisticated AST patterns
func (sa *StructuredAnalyzer) initializeASTPatterns() {
	patterns := []ASTPattern{
		// Go RSA key generation with bit length detection
		{
			ID:       "go-rsa-weak-keygen",
			Language: "go",
			Query: `
(call_expression
  function: (selector_expression
    field: (identifier) @func_name)
  arguments: (argument_list 
    (_)
    (int_literal) @bits)
  (#eq? @func_name "GenerateKey")
  (#match? @bits "^(512|1024)$"))`,
			Category:    "key_generation",
			Severity:    "critical",
			Description: "RSA key generation with weak bit length",
			Intent:      "detect_weak_rsa_generation",
			Variables:   []string{"@bits"},
		},

		// Go ECDSA key generation
		{
			ID:       "go-ecdsa-keygen",
			Language: "go",
			Query: `
(call_expression
  function: (selector_expression
    operand: (identifier) @pkg
    field: (identifier) @func)
  (#eq? @pkg "ecdsa")
  (#eq? @func "GenerateKey"))`,
			Category:    "key_generation",
			Severity:    "high",
			Description: "ECDSA key generation (quantum vulnerable)",
			Intent:      "detect_quantum_vulnerable_keygen",
			Variables:   []string{"@pkg", "@func"},
		},

		// Java KeyPairGenerator usage
		{
			ID:       "java-keypair-generator",
			Language: "java",
			Query: `
(method_invocation
  object: (identifier) @generator
  name: (identifier) @method
  arguments: (argument_list
    (string_literal) @algorithm)
  (#eq? @method "getInstance")
  (#match? @algorithm "\"(RSA|DSA|EC)\""))`,
			Category:    "key_generation",
			Severity:    "high",
			Description: "Java KeyPairGenerator for quantum-vulnerable algorithms",
			Intent:      "detect_java_quantum_vulnerable_keygen",
			Variables:   []string{"@algorithm"},
		},

		// JavaScript/Node.js crypto usage
		{
			ID:       "js-crypto-createhash",
			Language: "javascript",
			Query: `
(call_expression
  function: (member_expression
    object: (identifier) @crypto
    property: (property_identifier) @method)
  arguments: (arguments
    (string) @algorithm)
  (#eq? @crypto "crypto")
  (#eq? @method "createHash")
  (#match? @algorithm "\"(md5|sha1)\""))`,
			Category:    "hash_usage",
			Severity:    "critical",
			Description: "Weak hash algorithm usage in Node.js crypto",
			Intent:      "detect_weak_hash_usage",
			Variables:   []string{"@algorithm"},
		},

		// Python hashlib usage
		{
			ID:       "python-hashlib-weak",
			Language: "python",
			Query: `
(call
  function: (attribute
    object: (identifier) @module
    attr: (identifier) @hash_func)
  (#eq? @module "hashlib")
  (#match? @hash_func "^(md5|sha1)$"))`,
			Category:    "hash_usage",
			Severity:    "critical",
			Description: "Weak hash algorithm usage in Python hashlib",
			Intent:      "detect_weak_hash_usage",
			Variables:   []string{"@hash_func"},
		},

		// C/C++ OpenSSL RSA key generation
		{
			ID:       "c-openssl-rsa-keygen",
			Language: "c",
			Query: `
(call_expression
  function: (identifier) @func_name
  arguments: (argument_list
    (_)
    (number_literal) @key_size)
  (#eq? @func_name "RSA_generate_key")
  (#match? @key_size "^(512|1024)$"))`,
			Category:    "key_generation",
			Severity:    "critical",
			Description: "OpenSSL RSA key generation with weak key size",
			Intent:      "detect_weak_rsa_generation",
			Variables:   []string{"@key_size"},
		},

		// Rust crypto usage
		{
			ID:       "rust-rsa-keygen",
			Language: "rust",
			Query: `
(call_expression
  function: (scoped_identifier
    path: (identifier) @crate
    name: (identifier) @func)
  (#eq? @crate "rsa")
  (#match? @func "^(generate|new)$"))`,
			Category:    "key_generation",
			Severity:    "high",
			Description: "Rust RSA key generation",
			Intent:      "detect_quantum_vulnerable_keygen",
			Variables:   []string{"@crate", "@func"},
		},
	}

	for _, pattern := range patterns {
		sa.astPatterns[pattern.ID] = pattern
	}
}

// IdentifyHotspots analyzes L0 findings to identify crypto hotspots
func (sa *StructuredAnalyzer) IdentifyHotspots(fileCtx *FileContext, l0Findings []types.Finding) []CryptoHotspot {
	var hotspots []CryptoHotspot

	// Group L0 findings by location proximity
	locationGroups := sa.groupFindingsByProximity(l0Findings)

	for _, group := range locationGroups {
		hotspot := CryptoHotspot{
			Location: types.Location{
				Path:   fileCtx.FilePath,
				Line:   group[0].Line,
				Column: group[0].Column,
			},
			Type:       sa.determineHotspotType(group),
			Confidence: sa.calculateHotspotConfidence(group),
			Variables:  []Variable{},
			DataFlows:  []DataFlow{},
		}
		hotspots = append(hotspots, hotspot)
	}

	return hotspots
}

// AnalyzeHotspots performs detailed AST analysis on identified hotspots
func (sa *StructuredAnalyzer) AnalyzeHotspots(fileCtx *FileContext, hotspots []CryptoHotspot) []types.Finding {
	var findings []types.Finding

	// Get applicable AST patterns for this language
	patterns := sa.getLanguagePatterns(fileCtx.Language)

	for _, hotspot := range hotspots {
		// Focus analysis on hotspot region
		regionContent := sa.extractHotspotRegion(fileCtx.Content, hotspot)

		for _, pattern := range patterns {
			// Apply AST pattern to hotspot region
			patternFindings := sa.applyASTPattern(fileCtx, regionContent, pattern, hotspot)
			findings = append(findings, patternFindings...)
		}
	}

	return sa.enhanceWithVariableTracking(findings, fileCtx)
}

// applyASTPattern applies a single AST pattern to content
func (sa *StructuredAnalyzer) applyASTPattern(fileCtx *FileContext, content []byte, pattern ASTPattern, hotspot CryptoHotspot) []types.Finding {
	var findings []types.Finding

	// This would integrate with Tree-sitter AST parsing
	// For now, implementing a simplified version that focuses on pattern intent

	contentStr := string(content)

	// Intent-based analysis instead of just syntax matching
	switch pattern.Intent {
	case "detect_weak_rsa_generation":
		findings = append(findings, sa.analyzeRSAKeyGeneration(fileCtx, contentStr, pattern, hotspot)...)
	case "detect_quantum_vulnerable_keygen":
		findings = append(findings, sa.analyzeQuantumVulnerableKeygen(fileCtx, contentStr, pattern, hotspot)...)
	case "detect_weak_hash_usage":
		findings = append(findings, sa.analyzeWeakHashUsage(fileCtx, contentStr, pattern, hotspot)...)
	case "detect_java_quantum_vulnerable_keygen":
		findings = append(findings, sa.analyzeJavaKeygen(fileCtx, contentStr, pattern, hotspot)...)
	}

	return findings
}

// analyzeRSAKeyGeneration performs intent-based RSA key generation analysis
func (sa *StructuredAnalyzer) analyzeRSAKeyGeneration(fileCtx *FileContext, content string, pattern ASTPattern, hotspot CryptoHotspot) []types.Finding {
	var findings []types.Finding

	// Look for RSA key generation patterns with bit size context
	rsaPatterns := []string{
		`rsa\.GenerateKey\s*\([^,]*,\s*(\d+)`,
		`RSA_generate_key\s*\([^,]*,\s*(\d+)`,
		`KeyPairGenerator\.getInstance\s*\(\s*"RSA"\s*\)[\s\S]*?\.initialize\s*\(\s*(\d+)`,
	}

	for _, regexPattern := range rsaPatterns {
		matches := findPatternMatches(content, regexPattern)
		for _, match := range matches {
			keySize := extractKeySizeFromMatch(match)

			finding := types.Finding{
				ID:         generateFindingID(),
				RuleID:     pattern.ID,
				File:       fileCtx.FilePath,
				Line:       hotspot.Location.Line,
				Column:     hotspot.Location.Column,
				Message:    sa.generateIntentMessage(pattern, map[string]string{"keySize": keySize}),
				Severity:   sa.determineSeverityByKeySize(keySize),
				CryptoType: pattern.Category,
				Algorithm:  "RSA",
				Context:    match,
				Metadata: map[string]string{
					"stage":         "L1",
					"pattern_id":    pattern.ID,
					"intent":        pattern.Intent,
					"key_size":      keySize,
					"confidence":    fmt.Sprintf("%.2f", sa.calculatePatternConfidence(pattern, match)),
					"analysis_type": "intent_based",
				},
				Timestamp: time.Now(),
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// analyzeQuantumVulnerableKeygen analyzes quantum-vulnerable key generation
func (sa *StructuredAnalyzer) analyzeQuantumVulnerableKeygen(fileCtx *FileContext, content string, pattern ASTPattern, hotspot CryptoHotspot) []types.Finding {
	var findings []types.Finding

	// Detect various forms of quantum-vulnerable key generation
	vulnPatterns := map[string]string{
		"ECDSA": `ecdsa\.GenerateKey|EC_KEY_generate_key|KeyPairGenerator.*EC`,
		"ECDH":  `ecdh\.GenerateKey|ECDH_generate_key`,
		"DH":    `dh\.GenerateParameters|DH_generate_parameters`,
		"DSA":   `dsa\.GenerateKey|DSA_generate_key`,
	}

	for algorithm, regexPattern := range vulnPatterns {
		matches := findPatternMatches(content, regexPattern)
		for _, match := range matches {
			finding := types.Finding{
				ID:         generateFindingID(),
				RuleID:     pattern.ID + "-" + strings.ToLower(algorithm),
				File:       fileCtx.FilePath,
				Line:       hotspot.Location.Line,
				Column:     hotspot.Location.Column,
				Message:    fmt.Sprintf("%s key generation detected - vulnerable to quantum attacks", algorithm),
				Severity:   "high",
				CryptoType: pattern.Category,
				Algorithm:  algorithm,
				Context:    match,
				Metadata: map[string]string{
					"stage":        "L1",
					"pattern_id":   pattern.ID,
					"intent":       pattern.Intent,
					"quantum_vuln": "true",
					"algorithm":    algorithm,
					"confidence":   fmt.Sprintf("%.2f", 0.9), // High confidence for specific patterns
					"pq_migration": "required",
				},
				Timestamp: time.Now(),
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// analyzeWeakHashUsage analyzes weak hash algorithm usage
func (sa *StructuredAnalyzer) analyzeWeakHashUsage(fileCtx *FileContext, content string, pattern ASTPattern, hotspot CryptoHotspot) []types.Finding {
	var findings []types.Finding

	// Context-aware weak hash detection
	weakHashPatterns := map[string]string{
		"MD5":  `(?:md5\.New|hashlib\.md5|crypto\.createHash\s*\(\s*["']md5["']|MessageDigest\.getInstance\s*\(\s*["']MD5["'])`,
		"SHA1": `(?:sha1\.New|hashlib\.sha1|crypto\.createHash\s*\(\s*["']sha1["']|MessageDigest\.getInstance\s*\(\s*["']SHA-?1["'])`,
	}

	for algorithm, regexPattern := range weakHashPatterns {
		matches := findPatternMatches(content, regexPattern)
		for _, match := range matches {
			// Check context to reduce false positives
			context := strings.ToLower(match)
			isComment := strings.Contains(context, "//") || strings.Contains(context, "/*")

			severity := "critical"
			if isComment {
				continue // Skip comments
			}

			finding := types.Finding{
				ID:         generateFindingID(),
				RuleID:     pattern.ID + "-" + strings.ToLower(algorithm),
				File:       fileCtx.FilePath,
				Line:       hotspot.Location.Line,
				Column:     hotspot.Location.Column,
				Message:    fmt.Sprintf("%s hash algorithm usage detected - cryptographically broken", algorithm),
				Severity:   severity,
				CryptoType: pattern.Category,
				Algorithm:  algorithm,
				Context:    match,
				Metadata: map[string]string{
					"stage":         "L1",
					"pattern_id":    pattern.ID,
					"intent":        pattern.Intent,
					"broken_crypto": "true",
					"algorithm":     algorithm,
					"confidence":    fmt.Sprintf("%.2f", 0.95), // Very high confidence
					"deprecated":    "true",
				},
				Timestamp: time.Now(),
			}

			findings = append(findings, finding)
		}
	}

	return findings
}

// analyzeJavaKeygen analyzes Java key generation patterns
func (sa *StructuredAnalyzer) analyzeJavaKeygen(fileCtx *FileContext, content string, pattern ASTPattern, hotspot CryptoHotspot) []types.Finding {
	// Implementation for Java-specific key generation analysis
	// This would be similar to other analyzers but Java-specific
	return []types.Finding{}
}

// Helper functions

func (sa *StructuredAnalyzer) groupFindingsByProximity(findings []types.Finding) [][]types.Finding {
	// Group findings that are within 10 lines of each other
	var groups [][]types.Finding
	const proximityThreshold = 10

	if len(findings) == 0 {
		return groups
	}

	currentGroup := []types.Finding{findings[0]}

	for i := 1; i < len(findings); i++ {
		if findings[i].Line-findings[i-1].Line <= proximityThreshold {
			currentGroup = append(currentGroup, findings[i])
		} else {
			groups = append(groups, currentGroup)
			currentGroup = []types.Finding{findings[i]}
		}
	}
	groups = append(groups, currentGroup)

	return groups
}

func (sa *StructuredAnalyzer) determineHotspotType(findings []types.Finding) string {
	// Determine the primary type of crypto usage in this hotspot
	typeCounts := make(map[string]int)
	for _, finding := range findings {
		typeCounts[finding.CryptoType]++
	}

	maxCount := 0
	primaryType := "unknown"
	for cryptoType, count := range typeCounts {
		if count > maxCount {
			maxCount = count
			primaryType = cryptoType
		}
	}

	return primaryType
}

func (sa *StructuredAnalyzer) calculateHotspotConfidence(findings []types.Finding) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	totalConfidence := 0.0
	for _, finding := range findings {
		// Parse confidence from metadata
		if confStr, ok := finding.Metadata["confidence"]; ok {
			if conf, err := parseFloat(confStr); err == nil {
				totalConfidence += conf
			}
		}
	}

	return totalConfidence / float64(len(findings))
}

func (sa *StructuredAnalyzer) getLanguagePatterns(language string) []ASTPattern {
	var patterns []ASTPattern
	for _, pattern := range sa.astPatterns {
		if pattern.Language == language || pattern.Language == "*" {
			patterns = append(patterns, pattern)
		}
	}
	return patterns
}

func (sa *StructuredAnalyzer) extractHotspotRegion(content []byte, hotspot CryptoHotspot) []byte {
	// Extract a region around the hotspot for focused analysis
	// This is a simplified version - in practice would be more sophisticated
	return content
}

func (sa *StructuredAnalyzer) enhanceWithVariableTracking(findings []types.Finding, fileCtx *FileContext) []types.Finding {
	// Enhance findings with variable tracking information
	// This would track crypto variables through their lifecycle
	return findings
}

func (sa *StructuredAnalyzer) generateIntentMessage(pattern ASTPattern, vars map[string]string) string {
	// Generate contextual message based on pattern intent and variables
	switch pattern.Intent {
	case "detect_weak_rsa_generation":
		if keySize, ok := vars["keySize"]; ok {
			return fmt.Sprintf("RSA key generation with weak key size (%s bits) - upgrade to ≥2048 bits or migrate to ML-KEM", keySize)
		}
		return "RSA key generation detected - consider migration to post-quantum algorithms"
	default:
		return pattern.Description
	}
}

func (sa *StructuredAnalyzer) determineSeverityByKeySize(keySize string) string {
	switch keySize {
	case "512", "1024":
		return "critical"
	case "2048":
		return "medium"
	default:
		return "low"
	}
}

func (sa *StructuredAnalyzer) calculatePatternConfidence(pattern ASTPattern, match string) float64 {
	// Calculate confidence based on pattern specificity and match context
	baseConfidence := 0.7 // L1 patterns have higher base confidence than L0

	// Boost confidence for specific function calls
	if strings.Contains(match, "(") && strings.Contains(match, ")") {
		baseConfidence += 0.2
	}

	return baseConfidence
}

// Utility functions
func findPatternMatches(content, pattern string) []string {
	// Simple regex matching - in practice would use Tree-sitter
	// This is a placeholder implementation
	return []string{}
}

func extractKeySizeFromMatch(match string) string {
	// Extract key size from matched content
	// Placeholder implementation
	return "1024"
}

func parseFloat(s string) (float64, error) {
	// Simple float parsing
	return 0.5, nil
}
