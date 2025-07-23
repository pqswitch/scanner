package scanner

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/pqswitch/scanner/internal/config"
	"github.com/pqswitch/scanner/internal/types"
)

// RegexPreFilter implements L0 stage - blazing fast regex pre-filtering
type RegexPreFilter struct {
	config           *config.Config
	compiledPatterns map[string]*regexp.Regexp
	patternMetadata  map[string]PatternMetadata
	rules            *RuleEngine
	mu               sync.RWMutex
}

// PatternMetadata contains metadata for L0 patterns
type PatternMetadata struct {
	RuleID      string
	Category    string
	Priority    int
	Languages   []string
	Description string
	FastPath    bool // Whether this pattern is optimized for speed
}

// NewRegexPreFilter creates a new L0 regex pre-filter
func NewRegexPreFilter(cfg *config.Config) *RegexPreFilter {
	filter := &RegexPreFilter{
		config:           cfg,
		compiledPatterns: make(map[string]*regexp.Regexp),
		patternMetadata:  make(map[string]PatternMetadata),
		rules:            NewRuleEngine(cfg),
	}

	filter.initializePatterns()
	return filter
}

// initializePatterns sets up optimized regex patterns for L0 scanning
func (rf *RegexPreFilter) initializePatterns() {
	// Fast crypto detection patterns - optimized for speed with word boundaries
	l0Patterns := map[string]PatternMetadata{
		// Crypto function calls (fast detection)
		`\b(md5|sha1|sha256|rsa|ecdsa|ecdh|aes|des|3des|rc4|blowfish)\.(?:new|generate|create|compute)\b`: {
			RuleID:      "l0-crypto-functions",
			Category:    "crypto_usage",
			Priority:    1,
			Languages:   []string{"go", "java", "javascript", "python"},
			Description: "Fast detection of crypto function calls",
			FastPath:    true,
		},

		// Key generation patterns
		`\b(?:rsa|ecdsa|ecdh)\.?(?:generate|create)(?:key|keypair)\b`: {
			RuleID:      "l0-key-generation",
			Category:    "key_generation",
			Priority:    1,
			Languages:   []string{"go", "java", "javascript", "python", "c", "cpp"},
			Description: "Fast detection of key generation",
			FastPath:    true,
		},

		// Hash algorithm usage
		`\b(?:md5|sha1|sha224|sha256|sha384|sha512)\b`: {
			RuleID:      "l0-hash-algorithms",
			Category:    "hash_usage",
			Priority:    2,
			Languages:   []string{"*"},
			Description: "Fast detection of hash algorithm mentions",
			FastPath:    true,
		},

		// Crypto library imports (very fast)
		`\b(?:crypto|openssl|boringssl|cryptopp|libsodium|nacl)\b`: {
			RuleID:      "l0-crypto-libraries",
			Category:    "crypto_import",
			Priority:    3,
			Languages:   []string{"*"},
			Description: "Fast detection of crypto library usage",
			FastPath:    true,
		},

		// Weak crypto constants
		`\b(?:512|1024|2048|4096)\b`: {
			RuleID:      "l0-key-sizes",
			Category:    "key_sizes",
			Priority:    2,
			Languages:   []string{"*"},
			Description: "Fast detection of potential key sizes",
			FastPath:    true,
		},

		// TLS/SSL patterns
		`\b(?:tls|ssl|https|x509|certificate|cipher)\b`: {
			RuleID:      "l0-tls-ssl",
			Category:    "tls_ssl",
			Priority:    2,
			Languages:   []string{"*"},
			Description: "Fast detection of TLS/SSL usage",
			FastPath:    true,
		},

		// Potential PQ algorithms - detect all instances, rely on confidence scoring for context filtering
		`\b(?:kyber|dilithium|falcon|sphincs|ntru|saber|frodo)\b`: {
			RuleID:      "l0-pq-algorithms",
			Category:    "post_quantum",
			Priority:    1,
			Languages:   []string{"*"},
			Description: "Fast detection of post-quantum algorithms",
			FastPath:    true,
		},
	}

	// Compile all patterns
	rf.mu.Lock()
	defer rf.mu.Unlock()

	for pattern, metadata := range l0Patterns {
		compiled, err := regexp.Compile(`(?i)` + pattern) // Case-insensitive
		if err != nil {
			continue // Skip invalid patterns
		}
		rf.compiledPatterns[pattern] = compiled
		rf.patternMetadata[pattern] = metadata
	}
}

// ScanContent performs L0 regex scanning on file content
func (rf *RegexPreFilter) ScanContent(content []byte, filePath, language string) []types.Finding {
	var findings []types.Finding
	contentStr := string(content)

	// Skip if content is too large for L0 (should be very rare)
	if len(content) > 5*1024*1024 { // 5MB limit for L0
		return findings
	}

	rf.mu.RLock()
	defer rf.mu.RUnlock()

	// Process patterns in priority order (high priority first)
	for pattern, metadata := range rf.patternMetadata {
		// Language filtering
		if !rf.matchesLanguage(metadata.Languages, language) {
			continue
		}

		regex := rf.compiledPatterns[pattern]
		if regex == nil {
			continue
		}

		// Find all matches
		matches := regex.FindAllStringIndex(contentStr, -1)
		for _, match := range matches {
			line, column := rf.getLineColumn(content, match[0])
			context := rf.extractContext(content, match[0], match[1])

			// Create L0 finding with basic metadata
			finding := types.Finding{
				ID:         generateFindingID(),
				RuleID:     metadata.RuleID,
				File:       filePath,
				Line:       line,
				Column:     column,
				Message:    rf.generateL0Message(metadata),
				Severity:   rf.determineL0Severity(metadata),
				Confidence: rf.calculateL0Confidence(metadata, context, filePath),
				CryptoType: metadata.Category,
				Algorithm:  rf.extractAlgorithm(contentStr[match[0]:match[1]]),
				Context:    context,
				Metadata: map[string]string{
					"stage":      "L0",
					"pattern":    pattern,
					"priority":   fmt.Sprintf("%d", metadata.Priority),
					"fast_path":  fmt.Sprintf("%t", metadata.FastPath),
					"confidence": fmt.Sprintf("%.2f", rf.calculateL0Confidence(metadata, context, filePath)),
					"match_text": contentStr[match[0]:match[1]],
				},
			}

			// Skip findings with very low confidence (likely false positives)
			if finding.Confidence < 0.2 {
				continue
			}

			findings = append(findings, finding)
		}
	}

	return rf.deduplicateFindings(findings)
}

// matchesLanguage checks if pattern applies to the given language
func (rf *RegexPreFilter) matchesLanguage(languages []string, fileLanguage string) bool {
	if len(languages) == 0 {
		return true
	}

	for _, lang := range languages {
		if lang == "*" || strings.EqualFold(lang, fileLanguage) {
			return true
		}
	}
	return false
}

// generateL0Message creates appropriate message for L0 findings
func (rf *RegexPreFilter) generateL0Message(metadata PatternMetadata) string {
	// For YAML-based rules (non-FastPath), get the actual rule message
	if !metadata.FastPath {
		if rule, found := rf.rules.GetRuleByID(metadata.RuleID); found {
			if regexRule, ok := rule.(RegexRule); ok {
				return regexRule.Message
			}
		}
		return fmt.Sprintf("Crypto pattern detected: %s", metadata.RuleID)
	}

	// For hardcoded fast-path rules, use category-specific messages
	switch metadata.Category {
	case "crypto_usage":
		return "Potential crypto function usage detected (L0 pre-filter)"
	case "key_generation":
		return "Potential key generation detected (L0 pre-filter)"
	case "hash_usage":
		return "Hash algorithm usage detected (L0 pre-filter)"
	case "crypto_import":
		return "Crypto library reference detected (L0 pre-filter)"
	case "key_sizes":
		return "Potential crypto key size detected (L0 pre-filter)"
	case "tls_ssl":
		return "TLS/SSL usage detected (L0 pre-filter)"
	case "post_quantum":
		return "Post-quantum algorithm detected (L0 pre-filter)"
	default:
		return "Crypto-related content detected (L0 pre-filter)"
	}
}

// determineL0Severity assigns severity for L0 findings
func (rf *RegexPreFilter) determineL0Severity(metadata PatternMetadata) string {
	// For YAML-based rules (non-FastPath), we need to get the original severity
	if !metadata.FastPath {
		// Try to get the original severity from the rule
		if rule, found := rf.rules.GetRuleByID(metadata.RuleID); found {
			if regexRule, ok := rule.(RegexRule); ok {
				return regexRule.Severity
			}
		}
	}

	// For hardcoded fast-path rules, use priority-based severity
	switch metadata.Priority {
	case 1:
		return "medium" // High-priority patterns get medium severity at L0
	case 2:
		return "low" // Medium-priority patterns get low severity at L0
	default:
		return "info" // Low-priority patterns get info severity at L0
	}
}

// extractAlgorithm tries to extract specific algorithm name from match
func (rf *RegexPreFilter) extractAlgorithm(matchText string) string {
	algorithms := []string{
		"md5", "sha1", "sha256", "sha384", "sha512",
		"rsa", "ecdsa", "ecdh", "aes", "des", "3des",
		"kyber", "dilithium", "falcon", "sphincs",
	}

	matchLower := strings.ToLower(matchText)
	for _, alg := range algorithms {
		if strings.Contains(matchLower, alg) {
			return strings.ToUpper(alg)
		}
	}

	return "UNKNOWN"
}

// calculateL0Confidence calculates confidence score for L0 findings
func (rf *RegexPreFilter) calculateL0Confidence(metadata PatternMetadata, context string, filePath string) float64 {
	confidence := 0.3 // Base L0 confidence (low since it's just regex)

	// Boost confidence based on priority
	switch metadata.Priority {
	case 1:
		confidence += 0.3
	case 2:
		confidence += 0.2
	default:
		confidence += 0.1
	}

	// Boost confidence if in function call context
	if strings.Contains(context, "(") && strings.Contains(context, ")") {
		confidence += 0.2
	}

	// Reduce confidence if in comment-like context
	if strings.Contains(context, "//") || strings.Contains(context, "/*") {
		confidence -= 0.3
	}

	// Reduce confidence for sample data context (e.g., Apache Spark dataframes)
	if rf.isSampleDataContext(context) {
		confidence -= 0.4
	}

	// Reduce confidence for hardware/platform contexts (addresses FALCON false positives)
	hardwarePlatformPatterns := []string{
		// Device tree and platform naming patterns
		"lantiq,", "motorola,", "atari,", "qcom,", "renesas,", "broadcom,",
		".dts", ".dtb", ".dtsi", // Device tree files
		"compatible =", "device_node", "of_find_compatible",
		// Hardware/platform naming patterns
		"-falcon", "falcon-", "falcon.dtb", "falcon_",
		"ide", "sysctrl", "gpio", "ebu", "syseth", "sysgpe", "sys1",
		// CPU/SoC naming patterns
		"r8a779", "msm8226", "apq8016", "msm8916",
		// Platform/board file patterns
		"platform:", "board:", "mach-", "arch/", "drivers/",
		// Hardware documentation patterns
		"screen size", "resolution", "gpu", "nvidia", "sec2", "fwsec",
	}

	contextLower := strings.ToLower(context)
	for _, pattern := range hardwarePlatformPatterns {
		if strings.Contains(contextLower, pattern) {
			confidence -= 0.3
			break
		}
	}

	// Additional confidence reduction for specific FALCON hardware pattern detection
	if strings.Contains(contextLower, "falcon") {
		// Very specific hardware/platform indicators
		falconHardwarePatterns := []string{
			"atari", "lantiq", "motorola", "renesas", "r8a779", "msm8226",
			"pata_", "ide", "sysctrl", "dts", "dtb", "compatible",
			"gpu", "nvidia", "sec2", "fwsec", "gsp", "firmware",
			// Additional documentation and build patterns
			"problems on", "cause not yet", "note:", "values >",
			"commands per", "default id", "both, tt and",
			"config_soc", "obj-$(", "+=", "/falcon/",
			// Computer/hardware references
			"computer", "machine", "kernel", "driver", "module",
		}

		for _, pattern := range falconHardwarePatterns {
			if strings.Contains(contextLower, pattern) {
				confidence -= 0.5 // Strong reduction for hardware context
				break
			}
		}
	}

	// Kubernetes-specific context detection
	if rf.isKubernetesContext(context) || rf.isKubernetesContext(filePath) {
		confidence = rf.adjustForKubernetesContext(confidence, metadata, context)
	}

	// Test file context detection
	if rf.isTestFileContext(context) {
		confidence -= 0.2 // Reduce severity for test files
	}

	// Non-cryptographic hash usage detection
	if rf.isNonCryptographicHashUsage(context, rf.extractAlgorithm(context)) {
		confidence -= 0.3 // Reduce severity for utility hashing
	}

	// Ensure confidence stays within bounds
	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0.1 {
		confidence = 0.1
	}

	return confidence
}

// isSampleDataContext detects if code is sample/demo data context
func (rf *RegexPreFilter) isSampleDataContext(context string) bool {
	contextLower := strings.ToLower(context)
	sampleDataPatterns := []string{
		"bird", "animal", "eagle", "parrot", "horse", "spider", "ostrich",
		"example", "demo", "test", "sample", "dataframe", ">>> ", "...",
		"mammal", "lion", "monkey", "duck", // Additional animal names
	}
	for _, pattern := range sampleDataPatterns {
		if strings.Contains(contextLower, pattern) {
			return true
		}
	}
	return false
}

// isKubernetesContext detects if code is part of Kubernetes infrastructure
func (rf *RegexPreFilter) isKubernetesContext(context string) bool {
	k8sPatterns := []string{
		"k8s.io/", "kubernetes/", "kubeadm", "kubelet", "kubectl",
		"pkg/api/", "staging/src/k8s.io/", "client-go",
		"pkg/controller/", "pkg/kubeapiserver/", "apiserver",
		"certificates/", "pki", "cert.go", "certificate",
		"pkiutil", "pki_helpers", // Added for kubeadm PKI utilities
	}

	contextLower := strings.ToLower(context)
	for _, pattern := range k8sPatterns {
		if strings.Contains(contextLower, pattern) {
			return true
		}
	}
	return false
}

// adjustForKubernetesContext adjusts confidence for Kubernetes-specific contexts
func (rf *RegexPreFilter) adjustForKubernetesContext(confidence float64, metadata PatternMetadata, context string) float64 {
	contextLower := strings.ToLower(context)
	algorithm := rf.extractAlgorithm(context)

	// PKI infrastructure context (legitimate certificate management)
	pkiPatterns := []string{
		"pki_helpers", "cert.go", "certificate_manager", "certlist",
		"keyutil", "bootstrap", "csr", "ca", "tls", "x509",
		"generatekey", "createa", "newprivatekey", "signing",
	}

	for _, pattern := range pkiPatterns {
		if strings.Contains(contextLower, pattern) {
			// Reduce severity for legitimate PKI infrastructure
			if algorithm == "RSA" || algorithm == "ECDSA" {
				confidence -= 0.2 // PKI infrastructure is legitimate
			}
			break
		}
	}

	// Endpoint/controller utility context (non-cryptographic hashing)
	utilityHashPatterns := []string{
		"endpoints/util", "controller_utils", "staticpod/utils",
		"hashobject", "deephashobject", "hash(", "hasher :=",
		"attach_limit", "volume", "driver", "uid",
	}

	for _, pattern := range utilityHashPatterns {
		if strings.Contains(contextLower, pattern) {
			// Strong reduction for utility hashing
			if algorithm == "MD5" || algorithm == "SHA1" {
				confidence -= 0.4 // Utility hashing is not a security issue
			}
			break
		}
	}

	// Service account JWT context (legitimate cryptographic usage)
	jwtPatterns := []string{
		"serviceaccount", "jwt", "externaljwt", "plugin",
		"thumbprint", "publickey", "der", "hasher := crypto",
	}

	for _, pattern := range jwtPatterns {
		if strings.Contains(contextLower, pattern) {
			// Slight reduction for legitimate JWT operations
			confidence -= 0.1
			break
		}
	}

	return confidence
}

// isTestFileContext detects if code is in a test file
func (rf *RegexPreFilter) isTestFileContext(context string) bool {
	testPatterns := []string{
		"_test.go", "test/", "testing.T", "t.Helper()", "t.Fatal",
		"func Test", "func Benchmark", "require.NoError",
		"assert.", "mock", "fake", "stub",
	}

	contextLower := strings.ToLower(context)
	for _, pattern := range testPatterns {
		if strings.Contains(contextLower, pattern) {
			return true
		}
	}
	return false
}

// isNonCryptographicHashUsage detects non-security hash usage
func (rf *RegexPreFilter) isNonCryptographicHashUsage(context string, algorithm string) bool {
	if algorithm != "MD5" && algorithm != "SHA1" {
		return false
	}

	nonCryptoPatterns := []string{
		// Object/data hashing for comparison
		"hashobject", "deephashobject", "hash(", "hasher :=",
		"compare", "equal", "checksum", "fingerprint",
		// File/license hashing
		"license", "vendor", "util::md5", "sum(",
		// Identifier generation
		"uid", "etag", "driver", "attach_limit", "volume",
		// Git/version control
		"commit", "sha1", "git", "rev-parse",
		// Test utilities
		"test", "unique", "sprintf", "format",
	}

	contextLower := strings.ToLower(context)
	for _, pattern := range nonCryptoPatterns {
		if strings.Contains(contextLower, pattern) {
			return true
		}
	}
	return false
}

// deduplicateFindings removes duplicate L0 findings
func (rf *RegexPreFilter) deduplicateFindings(findings []types.Finding) []types.Finding {
	seen := make(map[string]bool)
	var unique []types.Finding

	for _, finding := range findings {
		// Create key based on file, line, and rule
		key := fmt.Sprintf("%s:%d:%s", finding.File, finding.Line, finding.RuleID)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, finding)
		}
	}

	return unique
}

// getLineColumn converts byte offset to line/column
func (rf *RegexPreFilter) getLineColumn(content []byte, offset int) (int, int) {
	line := 1
	column := 1

	for i := 0; i < offset && i < len(content); i++ {
		if content[i] == '\n' {
			line++
			column = 1
		} else {
			column++
		}
	}

	return line, column
}

// extractContext extracts context around a match
func (rf *RegexPreFilter) extractContext(content []byte, start, end int) string {
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

// LoadRules loads regex rules from the RuleEngine
func (rf *RegexPreFilter) LoadRules(rulesPath string) error {
	// Load rules into the rule engine
	if err := rf.rules.LoadRules(rulesPath); err != nil {
		return fmt.Errorf("failed to load rules into regex prefilter: %w", err)
	}

	// Add YAML-based regex rules to the prefilter
	rf.addYAMLRules()

	return nil
}

// addYAMLRules adds regex rules from the YAML file to the prefilter
func (rf *RegexPreFilter) addYAMLRules() {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	// Get regex rules from the rule engine
	regexRules := rf.rules.GetRegexRules()

	for _, rule := range regexRules {
		if !rule.Enabled {
			continue
		}

		// Convert rule severity to priority for L0
		priority := rf.severityToPriority(rule.Severity)

		// Create pattern metadata from YAML rule
		metadata := PatternMetadata{
			RuleID:      rule.ID,
			Category:    rule.CryptoType,
			Priority:    priority,
			Languages:   rule.Languages,
			Description: rule.Description,
			FastPath:    false, // YAML rules are not optimized for speed like hardcoded ones
		}

		// Compile regex if not already compiled
		if rule.Regex != nil {
			rf.compiledPatterns[rule.Pattern] = rule.Regex
			rf.patternMetadata[rule.Pattern] = metadata
		}
	}
}

// severityToPriority converts severity to priority for L0 processing
func (rf *RegexPreFilter) severityToPriority(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 1
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 2
	default:
		return 3
	}
}
