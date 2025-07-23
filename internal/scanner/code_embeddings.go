package scanner

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pqswitch/scanner/internal/types"
)

// CodeEmbedder creates vector embeddings from code patterns
type CodeEmbedder struct {
	vocabulary       map[string]int
	inverseVocab     map[int]string
	cryptoPatterns   map[string]float64
	languagePatterns map[string]map[string]float64
	contextPatterns  map[string]float64
	embeddingSize    int
}

// CodeEmbedding represents a vector embedding of code
type CodeEmbedding struct {
	Vector           []float64              `json:"vector"`
	Tokens           []string               `json:"tokens"`
	CryptoScore      float64                `json:"crypto_score"`
	LanguageFeatures map[string]float64     `json:"language_features"`
	ContextFeatures  map[string]float64     `json:"context_features"`
	SemanticFeatures map[string]float64     `json:"semantic_features"`
	Metadata         map[string]interface{} `json:"metadata"`
}

// NewCodeEmbedder creates a new code embedder
func NewCodeEmbedder(embeddingSize int) *CodeEmbedder {
	embedder := &CodeEmbedder{
		vocabulary:       make(map[string]int),
		inverseVocab:     make(map[int]string),
		cryptoPatterns:   make(map[string]float64),
		languagePatterns: make(map[string]map[string]float64),
		contextPatterns:  make(map[string]float64),
		embeddingSize:    embeddingSize,
	}

	embedder.initializeCryptoPatterns()
	embedder.initializeLanguagePatterns()
	embedder.initializeContextPatterns()

	return embedder
}

// initializeCryptoPatterns initializes crypto-specific patterns and weights
func (ce *CodeEmbedder) initializeCryptoPatterns() {
	// High-weight patterns for critical crypto algorithms
	ce.cryptoPatterns = map[string]float64{
		// Critical vulnerabilities (highest weight)
		"md5":  10.0,
		"sha1": 9.0,
		"des":  10.0,
		"rc4":  10.0,

		// Quantum-vulnerable (high weight)
		"rsa":        8.0,
		"ecdsa":      8.0,
		"ecdh":       8.0,
		"dh":         7.0,
		"ed25519":    7.0,
		"curve25519": 7.0,

		// Modern but review-worthy (medium weight)
		"aes":    6.0,
		"sha256": 5.0,
		"sha512": 5.0,
		"hmac":   5.0,

		// Modern quantum-resistant (lower weight)
		"chacha20": 4.0,
		"poly1305": 4.0,
		"blake2":   3.0,
		"argon2":   3.0,

		// Post-quantum (info weight)
		"kyber":     2.0,
		"dilithium": 2.0,
		"falcon":    2.0,
		"sphincs":   2.0,

		// Context patterns
		"encrypt":  6.0,
		"decrypt":  6.0,
		"sign":     6.0,
		"verify":   6.0,
		"hash":     5.0,
		"cipher":   6.0,
		"key":      5.0,
		"crypto":   5.0,
		"ssl":      4.0,
		"tls":      4.0,
		"password": 4.0,
		"secret":   4.0,
		"salt":     3.0,
		"nonce":    3.0,
		"iv":       3.0,
	}
}

// initializeLanguagePatterns initializes language-specific patterns
func (ce *CodeEmbedder) initializeLanguagePatterns() {
	ce.languagePatterns = map[string]map[string]float64{
		"go": {
			"crypto/":             8.0,
			"golang.org/x/crypto": 8.0,
			"GenerateKey":         7.0,
			"NewHash":             6.0,
			"Sum":                 5.0,
			"Write":               4.0,
			"package crypto":      9.0,
			"import":              3.0,
		},
		"javascript": {
			"crypto.createHash":      8.0,
			"crypto.createCipher":    8.0,
			"crypto.generateKeyPair": 8.0,
			"require('crypto')":      7.0,
			"subtle.digest":          7.0,
			"subtle.encrypt":         7.0,
			"WebCrypto":              6.0,
			"CryptoJS":               6.0,
		},
		"python": {
			"from cryptography":    8.0,
			"import hashlib":       7.0,
			"Crypto.Cipher":        8.0,
			"generate_private_key": 8.0,
			"digest()":             6.0,
			"encrypt()":            7.0,
			"decrypt()":            7.0,
		},
		"java": {
			"java.security":   8.0,
			"javax.crypto":    8.0,
			"BouncyCastle":    7.0,
			"getInstance":     6.0,
			"generateKeyPair": 8.0,
			"doFinal":         6.0,
			"MessageDigest":   7.0,
		},
		"c": {
			"#include <openssl": 8.0,
			"EVP_":              7.0,
			"RSA_":              8.0,
			"AES_":              7.0,
			"SHA1_":             8.0,
			"MD5_":              9.0,
			"_init":             6.0,
			"_update":           6.0,
			"_final":            6.0,
		},
		"cpp": {
			"#include <cryptopp": 8.0,
			"CryptoPP::":         7.0,
			"Botan::":            7.0,
			"class.*Cipher":      7.0,
			"class.*Hash":        7.0,
		},
		"rust": {
			"use ring::":       7.0,
			"use rustcrypto::": 7.0,
			"RsaPrivateKey":    8.0,
			"EcdsaKeyPair":     8.0,
			"digest::":         6.0,
			"aead::":           6.0,
		},
	}
}

// initializeContextPatterns initializes context-based patterns
func (ce *CodeEmbedder) initializeContextPatterns() {
	ce.contextPatterns = map[string]float64{
		// Positive context indicators
		"function_call":       3.0,
		"method_invocation":   3.0,
		"import_statement":    2.0,
		"variable_assignment": 2.0,
		"class_definition":    2.0,

		// Negative context indicators
		"comment":        -2.0,
		"string_literal": -1.0,
		"test_file":      -1.5,
		"documentation":  -2.0,
		"vendor_code":    -1.0,

		// Structural indicators
		"crypto_directory": 4.0,
		"security_context": 3.0,
		"library_code":     2.0,
		"application_code": 1.0,
	}
}

// CreateEmbedding creates a vector embedding from a code finding
func (ce *CodeEmbedder) CreateEmbedding(finding types.Finding, astFeatures *ASTFeatures, fileContent []byte) (*CodeEmbedding, error) {
	// Tokenize the code context
	tokens := ce.tokenizeCode(finding.Context, finding.File)

	// Build vocabulary if needed
	ce.updateVocabulary(tokens)

	// Create base vector
	vector := make([]float64, ce.embeddingSize)

	// Extract semantic features
	semanticFeatures := ce.extractSemanticFeatures(finding, astFeatures)

	// Extract language-specific features
	languageFeatures := ce.extractLanguageFeatures(finding, tokens)

	// Extract context features
	contextFeatures := ce.extractContextFeatures(finding, astFeatures)

	// Compute crypto relevance score
	cryptoScore := ce.computeCryptoScore(finding, tokens, semanticFeatures)

	// Build the embedding vector
	ce.buildEmbeddingVector(vector, tokens, semanticFeatures, languageFeatures, contextFeatures)

	// Normalize the vector
	ce.normalizeVector(vector)

	embedding := &CodeEmbedding{
		Vector:           vector,
		Tokens:           tokens,
		CryptoScore:      cryptoScore,
		LanguageFeatures: languageFeatures,
		ContextFeatures:  contextFeatures,
		SemanticFeatures: semanticFeatures,
		Metadata: map[string]interface{}{
			"algorithm":  finding.Algorithm,
			"severity":   finding.Severity,
			"confidence": finding.Confidence,
			"file":       finding.File,
			"line":       finding.Line,
			"rule_id":    finding.RuleID,
		},
	}

	return embedding, nil
}

// tokenizeCode tokenizes code content into meaningful tokens
func (ce *CodeEmbedder) tokenizeCode(context string, filePath string) []string {
	// Basic tokenization - split on common delimiters
	delimiters := regexp.MustCompile(`[\s\(\)\[\]\{\}\.,;:=\+\-\*\/\<\>\!\&\|\^%]+`)
	rawTokens := delimiters.Split(context, -1)

	var tokens []string
	for _, token := range rawTokens {
		token = strings.TrimSpace(token)
		if len(token) > 0 && len(token) < 50 { // Filter out very long tokens
			tokens = append(tokens, strings.ToLower(token))
		}
	}

	// Add special tokens for file type
	language := ce.detectLanguageFromPath(filePath)
	tokens = append(tokens, fmt.Sprintf("__LANG_%s__", language))

	return tokens
}

// updateVocabulary updates the vocabulary with new tokens
func (ce *CodeEmbedder) updateVocabulary(tokens []string) {
	for _, token := range tokens {
		if _, exists := ce.vocabulary[token]; !exists {
			index := len(ce.vocabulary)
			ce.vocabulary[token] = index
			ce.inverseVocab[index] = token
		}
	}
}

// extractSemanticFeatures extracts semantic features from the finding
func (ce *CodeEmbedder) extractSemanticFeatures(finding types.Finding, astFeatures *ASTFeatures) map[string]float64 {
	features := make(map[string]float64)

	// Algorithm-based features
	algorithm := strings.ToLower(finding.Algorithm)
	if weight, exists := ce.cryptoPatterns[algorithm]; exists {
		features["algorithm_weight"] = weight
	}

	// Severity-based features
	switch finding.Severity {
	case "critical":
		features["severity_score"] = 10.0
	case "high":
		features["severity_score"] = 8.0
	case "medium":
		features["severity_score"] = 6.0
	case "low":
		features["severity_score"] = 4.0
	case "info":
		features["severity_score"] = 2.0
	}

	// Confidence-based features
	features["confidence_score"] = finding.Confidence * 10.0

	// AST-based features (if available)
	if astFeatures != nil {
		features["function_calls"] = float64(astFeatures.FunctionCallDepth)
		features["complexity"] = float64(astFeatures.CyclomaticComplexity)
		features["crypto_functions"] = float64(astFeatures.CryptoFunctionCalls)
		features["lines_of_code"] = float64(astFeatures.LinesOfCode)

		// Boolean features as 0/1
		if astFeatures.HasCryptoLoop {
			features["has_crypto_loop"] = 1.0
		}
		if astFeatures.HasCryptoConditional {
			features["has_crypto_conditional"] = 1.0
		}
		if astFeatures.InCryptoNamespace {
			features["in_crypto_namespace"] = 1.0
		}
		if astFeatures.NearCryptoImports {
			features["near_crypto_imports"] = 1.0
		}
	}

	return features
}

// extractLanguageFeatures extracts language-specific features
func (ce *CodeEmbedder) extractLanguageFeatures(finding types.Finding, tokens []string) map[string]float64 {
	features := make(map[string]float64)

	language := ce.detectLanguageFromPath(finding.File)
	features["language_detected"] = 1.0

	// Language-specific pattern matching
	if patterns, exists := ce.languagePatterns[language]; exists {
		context := strings.ToLower(finding.Context)
		for pattern, weight := range patterns {
			if strings.Contains(context, pattern) {
				features[fmt.Sprintf("lang_%s_%s", language, pattern)] = weight
			}
		}
	}

	// Token-based language features
	tokenCounts := make(map[string]int)
	for _, token := range tokens {
		tokenCounts[token]++
	}

	// Calculate token frequency features
	totalTokens := len(tokens)
	for token, count := range tokenCounts {
		if weight, exists := ce.cryptoPatterns[token]; exists {
			frequency := float64(count) / float64(totalTokens)
			features[fmt.Sprintf("token_freq_%s", token)] = frequency * weight
		}
	}

	return features
}

// extractContextFeatures extracts context-based features
func (ce *CodeEmbedder) extractContextFeatures(finding types.Finding, astFeatures *ASTFeatures) map[string]float64 {
	features := make(map[string]float64)

	// File path analysis
	filePath := strings.ToLower(finding.File)

	// Directory context
	if strings.Contains(filePath, "crypto") {
		features["crypto_directory"] = ce.contextPatterns["crypto_directory"]
	}
	if strings.Contains(filePath, "security") {
		features["security_context"] = ce.contextPatterns["security_context"]
	}
	if strings.Contains(filePath, "test") {
		features["test_file"] = ce.contextPatterns["test_file"]
	}
	if strings.Contains(filePath, "vendor") || strings.Contains(filePath, "node_modules") {
		features["vendor_code"] = ce.contextPatterns["vendor_code"]
	}

	// Context pattern analysis
	context := strings.ToLower(finding.Context)

	// Function call patterns
	if strings.Contains(context, "(") && strings.Contains(context, ")") {
		features["function_call"] = ce.contextPatterns["function_call"]
	}

	// Import/include patterns
	if strings.Contains(context, "import") || strings.Contains(context, "include") || strings.Contains(context, "require") {
		features["import_statement"] = ce.contextPatterns["import_statement"]
	}

	// Comment patterns
	if strings.Contains(context, "//") || strings.Contains(context, "/*") || strings.Contains(context, "#") {
		features["comment"] = ce.contextPatterns["comment"]
	}

	// Variable assignment patterns
	if strings.Contains(context, "=") || strings.Contains(context, ":=") {
		features["variable_assignment"] = ce.contextPatterns["variable_assignment"]
	}

	return features
}

// computeCryptoScore computes overall crypto relevance score
func (ce *CodeEmbedder) computeCryptoScore(finding types.Finding, tokens []string, semanticFeatures map[string]float64) float64 {
	score := 0.0

	// Base score from algorithm
	if algorithmWeight, exists := ce.cryptoPatterns[strings.ToLower(finding.Algorithm)]; exists {
		score += algorithmWeight
	}

	// Token-based scoring
	for _, token := range tokens {
		if weight, exists := ce.cryptoPatterns[token]; exists {
			score += weight * 0.1 // Scale down token contributions
		}
	}

	// Semantic feature contributions
	if algWeight, exists := semanticFeatures["algorithm_weight"]; exists {
		score += algWeight * 0.5
	}
	if severity, exists := semanticFeatures["severity_score"]; exists {
		score += severity * 0.3
	}
	if confidence, exists := semanticFeatures["confidence_score"]; exists {
		score += confidence * 0.2
	}

	// Normalize to 0-10 range
	return math.Min(10.0, math.Max(0.0, score))
}

// buildEmbeddingVector builds the actual embedding vector
func (ce *CodeEmbedder) buildEmbeddingVector(vector []float64, tokens []string, semanticFeatures, languageFeatures, contextFeatures map[string]float64) {
	// Section 1: Token embeddings (first 40% of vector)
	tokenSection := int(float64(ce.embeddingSize) * 0.4)
	ce.encodeTokens(vector[:tokenSection], tokens)

	// Section 2: Semantic features (next 25% of vector)
	semanticSection := int(float64(ce.embeddingSize) * 0.25)
	startIdx := tokenSection
	ce.encodeFeatures(vector[startIdx:startIdx+semanticSection], semanticFeatures)

	// Section 3: Language features (next 20% of vector)
	languageSection := int(float64(ce.embeddingSize) * 0.20)
	startIdx += semanticSection
	ce.encodeFeatures(vector[startIdx:startIdx+languageSection], languageFeatures)

	// Section 4: Context features (remaining 15% of vector)
	contextSection := ce.embeddingSize - startIdx - languageSection
	startIdx += languageSection
	ce.encodeFeatures(vector[startIdx:startIdx+contextSection], contextFeatures)
}

// encodeTokens encodes tokens into vector section
func (ce *CodeEmbedder) encodeTokens(section []float64, tokens []string) {
	// Simple bag-of-words encoding with TF-IDF-like weighting
	tokenCounts := make(map[string]int)
	for _, token := range tokens {
		tokenCounts[token]++
	}

	// Hash tokens to vector positions
	for token, count := range tokenCounts {
		hash := ce.hashToken(token)
		positions := ce.getHashPositions(hash, len(section), 3) // Use 3 positions per token

		weight := float64(count) / float64(len(tokens)) // TF
		if cryptoWeight, exists := ce.cryptoPatterns[token]; exists {
			weight *= cryptoWeight // Boost crypto-relevant tokens
		}

		for _, pos := range positions {
			section[pos] += weight
		}
	}
}

// encodeFeatures encodes feature map into vector section
func (ce *CodeEmbedder) encodeFeatures(section []float64, features map[string]float64) {
	if len(section) == 0 {
		return
	}

	// Sort features for consistent encoding
	var keys []string
	for key := range features {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// Distribute features across section
	for i, key := range keys {
		if i >= len(section) {
			break
		}
		section[i] = features[key]
	}
}

// hashToken creates a hash for a token
func (ce *CodeEmbedder) hashToken(token string) uint32 {
	hash := sha256.Sum256([]byte(token))
	return uint32(hash[0])<<24 | uint32(hash[1])<<16 | uint32(hash[2])<<8 | uint32(hash[3])
}

// getHashPositions gets multiple positions for a hash
func (ce *CodeEmbedder) getHashPositions(hash uint32, sectionSize int, numPositions int) []int {
	positions := make([]int, numPositions)
	for i := 0; i < numPositions; i++ {
		// Use int64 for intermediate calculation to prevent overflow
		offset := int64(i) * 17
		hashWithOffset := int64(hash) + offset
		positions[i] = int(hashWithOffset % int64(sectionSize))
	}
	return positions
}

// normalizeVector normalizes the embedding vector
func (ce *CodeEmbedder) normalizeVector(vector []float64) {
	// L2 normalization
	var norm float64
	for _, val := range vector {
		norm += val * val
	}
	norm = math.Sqrt(norm)

	if norm > 0 {
		for i := range vector {
			vector[i] /= norm
		}
	}
}

// detectLanguageFromPath detects language from file path
func (ce *CodeEmbedder) detectLanguageFromPath(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".go":
		return "go"
	case ".js", ".mjs", ".jsx":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".py", ".pyw":
		return "python"
	case ".c", ".h":
		return "c"
	case ".cpp", ".cc", ".cxx", ".hpp", ".hxx":
		return "cpp"
	case ".java":
		return "java"
	case ".rs":
		return "rust"
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

// ComputeSimilarity computes cosine similarity between two embeddings
func (ce *CodeEmbedder) ComputeSimilarity(embedding1, embedding2 *CodeEmbedding) float64 {
	if len(embedding1.Vector) != len(embedding2.Vector) {
		return 0.0
	}

	var dotProduct, norm1, norm2 float64
	for i := range embedding1.Vector {
		dotProduct += embedding1.Vector[i] * embedding2.Vector[i]
		norm1 += embedding1.Vector[i] * embedding1.Vector[i]
		norm2 += embedding2.Vector[i] * embedding2.Vector[i]
	}

	if norm1 == 0 || norm2 == 0 {
		return 0.0
	}

	return dotProduct / (math.Sqrt(norm1) * math.Sqrt(norm2))
}

// SerializeEmbedding serializes embedding to JSON
func (ce *CodeEmbedder) SerializeEmbedding(embedding *CodeEmbedding) ([]byte, error) {
	return json.Marshal(embedding)
}

// DeserializeEmbedding deserializes embedding from JSON
func (ce *CodeEmbedder) DeserializeEmbedding(data []byte) (*CodeEmbedding, error) {
	var embedding CodeEmbedding
	err := json.Unmarshal(data, &embedding)
	return &embedding, err
}
