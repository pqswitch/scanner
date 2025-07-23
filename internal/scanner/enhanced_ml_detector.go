package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/pqswitch/scanner/internal/config"
	"github.com/pqswitch/scanner/internal/types"
)

// EnhancedMLDetector combines AST analysis, code embeddings, and ML confidence scoring
type EnhancedMLDetector struct {
	config           *config.Config
	astExtractor     *ASTFeatureExtractor
	codeEmbedder     *CodeEmbedder
	mlScorer         *MLConfidenceScorer
	embeddingSize    int
	enableAST        bool
	enableEmbeddings bool
}

// EnhancedFinding extends the basic finding with advanced ML features
type EnhancedFinding struct {
	types.Finding
	ASTFeatures   *ASTFeatures       `json:"ast_features,omitempty"`
	CodeEmbedding *CodeEmbedding     `json:"code_embedding,omitempty"`
	MLFeatures    map[string]float64 `json:"ml_features,omitempty"`
	EnhancedScore float64            `json:"enhanced_score"`
	FeatureVector []float64          `json:"feature_vector,omitempty"`
}

// NewEnhancedMLDetector creates a new enhanced ML detector
func NewEnhancedMLDetector(cfg *config.Config) *EnhancedMLDetector {
	detector := &EnhancedMLDetector{
		config:           cfg,
		embeddingSize:    256, // Default embedding size
		enableAST:        cfg.Scanner.EnableAST,
		enableEmbeddings: true, // Enable by default
	}

	// Initialize components
	detector.astExtractor = NewASTFeatureExtractor()
	detector.codeEmbedder = NewCodeEmbedder(detector.embeddingSize)
	detector.mlScorer = NewMLConfidenceScorer(cfg)

	return detector
}

// ProcessFindings enhances findings with advanced ML features
func (emd *EnhancedMLDetector) ProcessFindings(findings []types.Finding, fileCtx *FileContext) ([]*EnhancedFinding, error) {
	var enhancedFindings []*EnhancedFinding

	for _, finding := range findings {
		enhanced, err := emd.processSingleFinding(finding, fileCtx)
		if err != nil {
			// Log error but continue processing
			fmt.Printf("Warning: Failed to enhance finding %s: %v\n", finding.ID, err)
			// Create basic enhanced finding
			enhanced = &EnhancedFinding{
				Finding:       finding,
				EnhancedScore: finding.Confidence,
			}
		}

		enhancedFindings = append(enhancedFindings, enhanced)
	}

	// Sort by enhanced score
	enhancedFindings = emd.sortByEnhancedScore(enhancedFindings)

	return enhancedFindings, nil
}

// processSingleFinding processes a single finding with all ML enhancements
func (emd *EnhancedMLDetector) processSingleFinding(finding types.Finding, fileCtx *FileContext) (*EnhancedFinding, error) {
	enhanced := &EnhancedFinding{
		Finding:    finding,
		MLFeatures: make(map[string]float64),
	}

	// Read file content for analysis
	fileContent, err := emd.readFileContent(finding.File)
	if err != nil {
		return nil, fmt.Errorf("failed to read file content: %w", err)
	}

	// Extract AST features if enabled
	if emd.enableAST {
		astFeatures, err := emd.extractASTFeatures(fileContent, finding)
		if err == nil {
			enhanced.ASTFeatures = astFeatures
			emd.addASTFeaturesToML(enhanced, astFeatures)
		}
	}

	// Create code embedding if enabled
	if emd.enableEmbeddings {
		embedding, err := emd.createCodeEmbedding(finding, enhanced.ASTFeatures, fileContent)
		if err == nil {
			enhanced.CodeEmbedding = embedding
			emd.addEmbeddingFeaturesToML(enhanced, embedding)
		}
	}

	// Apply ML confidence scoring with enhanced features
	enhanced = emd.applyEnhancedMLScoring(enhanced, fileCtx)

	// Create comprehensive feature vector
	enhanced.FeatureVector = emd.createFeatureVector(enhanced)

	return enhanced, nil
}

// extractASTFeatures extracts AST-based features
func (emd *EnhancedMLDetector) extractASTFeatures(fileContent []byte, finding types.Finding) (*ASTFeatures, error) {
	return emd.astExtractor.ExtractASTFeatures(fileContent, finding.File, finding)
}

// createCodeEmbedding creates code embedding
func (emd *EnhancedMLDetector) createCodeEmbedding(finding types.Finding, astFeatures *ASTFeatures, fileContent []byte) (*CodeEmbedding, error) {
	return emd.codeEmbedder.CreateEmbedding(finding, astFeatures, fileContent)
}

// addASTFeaturesToML adds AST features to ML feature set
func (emd *EnhancedMLDetector) addASTFeaturesToML(enhanced *EnhancedFinding, astFeatures *ASTFeatures) {
	if astFeatures == nil {
		return
	}

	// Structural features
	enhanced.MLFeatures["ast_function_calls"] = float64(astFeatures.FunctionCallDepth)
	enhanced.MLFeatures["ast_complexity"] = float64(astFeatures.CyclomaticComplexity)
	enhanced.MLFeatures["ast_variables"] = float64(astFeatures.VariableDeclarations)
	enhanced.MLFeatures["ast_functions"] = float64(astFeatures.FunctionDefinitions)
	enhanced.MLFeatures["ast_classes"] = float64(astFeatures.ClassDefinitions)
	enhanced.MLFeatures["ast_imports"] = float64(astFeatures.ImportStatements)
	enhanced.MLFeatures["ast_lines_of_code"] = float64(astFeatures.LinesOfCode)

	// Crypto-specific AST features
	enhanced.MLFeatures["ast_crypto_functions"] = float64(astFeatures.CryptoFunctionCalls)
	enhanced.MLFeatures["ast_crypto_variables"] = float64(astFeatures.CryptoVariables)
	enhanced.MLFeatures["ast_crypto_constants"] = float64(astFeatures.CryptoConstants)
	enhanced.MLFeatures["ast_crypto_methods"] = float64(astFeatures.CryptoClassMethods)

	// Boolean features as 0/1
	enhanced.MLFeatures["ast_has_crypto_loop"] = boolToFloat(astFeatures.HasCryptoLoop)
	enhanced.MLFeatures["ast_has_crypto_conditional"] = boolToFloat(astFeatures.HasCryptoConditional)
	enhanced.MLFeatures["ast_has_crypto_try_catch"] = boolToFloat(astFeatures.HasCryptoTryCatch)
	enhanced.MLFeatures["ast_has_crypto_interface"] = boolToFloat(astFeatures.HasCryptoInterface)
	enhanced.MLFeatures["ast_in_crypto_namespace"] = boolToFloat(astFeatures.InCryptoNamespace)
	enhanced.MLFeatures["ast_in_security_context"] = boolToFloat(astFeatures.InSecurityContext)
	enhanced.MLFeatures["ast_near_crypto_imports"] = boolToFloat(astFeatures.NearCryptoImports)
	enhanced.MLFeatures["ast_has_documentation"] = boolToFloat(astFeatures.HasDocumentation)
	enhanced.MLFeatures["ast_has_error_handling"] = boolToFloat(astFeatures.HasErrorHandling)
	enhanced.MLFeatures["ast_has_generics"] = boolToFloat(astFeatures.HasGenerics)
	enhanced.MLFeatures["ast_has_pointers"] = boolToFloat(astFeatures.HasPointers)
	enhanced.MLFeatures["ast_has_lambdas"] = boolToFloat(astFeatures.HasLambdas)
}

// addEmbeddingFeaturesToML adds embedding features to ML feature set
func (emd *EnhancedMLDetector) addEmbeddingFeaturesToML(enhanced *EnhancedFinding, embedding *CodeEmbedding) {
	if embedding == nil {
		return
	}

	// Add crypto score
	enhanced.MLFeatures["embedding_crypto_score"] = embedding.CryptoScore

	// Add semantic features
	for key, value := range embedding.SemanticFeatures {
		enhanced.MLFeatures[fmt.Sprintf("semantic_%s", key)] = value
	}

	// Add language features (top 10 most important)
	langFeatures := emd.getTopFeatures(embedding.LanguageFeatures, 10)
	for key, value := range langFeatures {
		enhanced.MLFeatures[fmt.Sprintf("lang_%s", key)] = value
	}

	// Add context features
	for key, value := range embedding.ContextFeatures {
		enhanced.MLFeatures[fmt.Sprintf("context_%s", key)] = value
	}

	// Add vector summary statistics
	enhanced.MLFeatures["embedding_vector_mean"] = emd.calculateMean(embedding.Vector)
	enhanced.MLFeatures["embedding_vector_std"] = emd.calculateStd(embedding.Vector)
	enhanced.MLFeatures["embedding_vector_max"] = emd.calculateMax(embedding.Vector)
	enhanced.MLFeatures["embedding_vector_min"] = emd.calculateMin(embedding.Vector)
}

// applyEnhancedMLScoring applies enhanced ML confidence scoring
func (emd *EnhancedMLDetector) applyEnhancedMLScoring(enhanced *EnhancedFinding, fileCtx *FileContext) *EnhancedFinding {
	// Start with original confidence
	baseScore := enhanced.Confidence

	// Apply AST-based adjustments
	astBoost := emd.calculateASTBoost(enhanced)

	// Apply embedding-based adjustments
	embeddingBoost := emd.calculateEmbeddingBoost(enhanced)

	// Apply context-based adjustments
	contextBoost := emd.calculateContextBoost(enhanced, fileCtx)

	// Combine scores with weights
	enhancedScore := baseScore*0.4 + astBoost*0.3 + embeddingBoost*0.2 + contextBoost*0.1

	// Ensure score is in valid range [0, 1]
	enhanced.EnhancedScore = clamp(enhancedScore, 0.0, 1.0)

	// Add individual boost scores to ML features
	enhanced.MLFeatures["ml_base_score"] = baseScore
	enhanced.MLFeatures["ml_ast_boost"] = astBoost
	enhanced.MLFeatures["ml_embedding_boost"] = embeddingBoost
	enhanced.MLFeatures["ml_context_boost"] = contextBoost
	enhanced.MLFeatures["ml_enhanced_score"] = enhanced.EnhancedScore

	return enhanced
}

// calculateASTBoost calculates confidence boost from AST features
func (emd *EnhancedMLDetector) calculateASTBoost(enhanced *EnhancedFinding) float64 {
	if enhanced.ASTFeatures == nil {
		return enhanced.Confidence
	}

	boost := enhanced.Confidence

	// Boost for crypto-specific patterns
	if enhanced.ASTFeatures.CryptoFunctionCalls > 0 {
		boost += 0.2
	}
	if enhanced.ASTFeatures.InCryptoNamespace {
		boost += 0.15
	}
	if enhanced.ASTFeatures.NearCryptoImports {
		boost += 0.1
	}

	// Boost for code quality indicators
	if enhanced.ASTFeatures.HasErrorHandling {
		boost += 0.05
	}
	if enhanced.ASTFeatures.HasDocumentation {
		boost += 0.05
	}

	// Penalty for test context (unless in crypto directory)
	if strings.Contains(strings.ToLower(enhanced.File), "test") && !enhanced.ASTFeatures.InCryptoNamespace {
		boost -= 0.1
	}

	return clamp(boost, 0.0, 1.0)
}

// calculateEmbeddingBoost calculates confidence boost from code embeddings
func (emd *EnhancedMLDetector) calculateEmbeddingBoost(enhanced *EnhancedFinding) float64 {
	if enhanced.CodeEmbedding == nil {
		return enhanced.Confidence
	}

	// Use crypto score from embedding (normalized to 0-1)
	cryptoScore := enhanced.CodeEmbedding.CryptoScore / 10.0

	// Combine with original confidence
	boost := (enhanced.Confidence + cryptoScore) / 2.0

	return clamp(boost, 0.0, 1.0)
}

// calculateContextBoost calculates confidence boost from context
func (emd *EnhancedMLDetector) calculateContextBoost(enhanced *EnhancedFinding, fileCtx *FileContext) float64 {
	boost := enhanced.Confidence

	// File context adjustments
	if fileCtx != nil {
		if fileCtx.IsTest {
			boost -= 0.1
		}
		if fileCtx.IsVendored {
			boost -= 0.05
		}
	}

	// Algorithm-specific adjustments
	algorithm := strings.ToLower(enhanced.Algorithm)
	switch algorithm {
	case "md5", "sha1", "des", "rc4":
		boost += 0.2 // Critical algorithms get high confidence
	case "rsa", "ecdsa", "ecdh":
		boost += 0.15 // Quantum-vulnerable algorithms
	case "aes", "sha256":
		boost += 0.05 // Modern but review-worthy
	}

	return clamp(boost, 0.0, 1.0)
}

// createFeatureVector creates a comprehensive feature vector for ML
func (emd *EnhancedMLDetector) createFeatureVector(enhanced *EnhancedFinding) []float64 {
	// Start with a base feature vector
	features := make([]float64, 50) // 50-dimensional feature vector

	// Basic features (0-9)
	features[0] = enhanced.Confidence
	features[1] = enhanced.EnhancedScore
	features[2] = float64(enhanced.Line)
	features[3] = float64(enhanced.Column)
	features[4] = float64(len(enhanced.Context))
	features[5] = emd.algorithmToFloat(enhanced.Algorithm)
	features[6] = emd.severityToFloat(enhanced.Severity)
	features[7] = emd.cryptoTypeToFloat(enhanced.CryptoType)
	features[8] = boolToFloat(strings.Contains(strings.ToLower(enhanced.File), "test"))
	features[9] = boolToFloat(strings.Contains(strings.ToLower(enhanced.File), "crypto"))

	// AST features (10-29)
	if enhanced.ASTFeatures != nil {
		features[10] = float64(enhanced.ASTFeatures.FunctionCallDepth) / 10.0 // Normalize
		features[11] = float64(enhanced.ASTFeatures.CyclomaticComplexity) / 20.0
		features[12] = float64(enhanced.ASTFeatures.VariableDeclarations) / 10.0
		features[13] = float64(enhanced.ASTFeatures.FunctionDefinitions) / 5.0
		features[14] = float64(enhanced.ASTFeatures.CryptoFunctionCalls) / 5.0
		features[15] = boolToFloat(enhanced.ASTFeatures.HasCryptoLoop)
		features[16] = boolToFloat(enhanced.ASTFeatures.HasCryptoConditional)
		features[17] = boolToFloat(enhanced.ASTFeatures.InCryptoNamespace)
		features[18] = boolToFloat(enhanced.ASTFeatures.NearCryptoImports)
		features[19] = boolToFloat(enhanced.ASTFeatures.HasDocumentation)
	}

	// Embedding features (30-39)
	if enhanced.CodeEmbedding != nil {
		features[30] = enhanced.CodeEmbedding.CryptoScore / 10.0 // Normalize
		features[31] = emd.calculateMean(enhanced.CodeEmbedding.Vector)
		features[32] = emd.calculateStd(enhanced.CodeEmbedding.Vector)
		features[33] = float64(len(enhanced.CodeEmbedding.Tokens)) / 20.0 // Normalize
	}

	// ML features (40-49) - top ML features
	mlFeatureKeys := []string{
		"ml_enhanced_score", "embedding_crypto_score", "ast_complexity",
		"semantic_algorithm_weight", "context_crypto_directory", "ast_crypto_functions",
		"lang_crypto/", "semantic_confidence_score", "ast_in_crypto_namespace",
		"context_function_call",
	}

	for i, key := range mlFeatureKeys {
		if i < 10 && enhanced.MLFeatures != nil {
			if value, exists := enhanced.MLFeatures[key]; exists {
				features[40+i] = value
			}
		}
	}

	return features
}

// Helper functions

func (emd *EnhancedMLDetector) readFileContent(filePath string) ([]byte, error) {
	return os.ReadFile(filePath) //nolint:gosec // Legitimate file reading for scanner functionality
}

func (emd *EnhancedMLDetector) getTopFeatures(features map[string]float64, limit int) map[string]float64 {
	// Sort features by value and return top N
	type featurePair struct {
		key   string
		value float64
	}

	var pairs []featurePair
	for k, v := range features {
		pairs = append(pairs, featurePair{k, v})
	}

	// Simple sort by value (descending)
	for i := 0; i < len(pairs)-1; i++ {
		for j := i + 1; j < len(pairs); j++ {
			if pairs[i].value < pairs[j].value {
				pairs[i], pairs[j] = pairs[j], pairs[i]
			}
		}
	}

	result := make(map[string]float64)
	for i := 0; i < limit && i < len(pairs); i++ {
		result[pairs[i].key] = pairs[i].value
	}

	return result
}

func (emd *EnhancedMLDetector) sortByEnhancedScore(findings []*EnhancedFinding) []*EnhancedFinding {
	// Simple bubble sort by enhanced score (descending)
	for i := 0; i < len(findings)-1; i++ {
		for j := i + 1; j < len(findings); j++ {
			if findings[i].EnhancedScore < findings[j].EnhancedScore {
				findings[i], findings[j] = findings[j], findings[i]
			}
		}
	}
	return findings
}

// Statistical helper functions
func (emd *EnhancedMLDetector) calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func (emd *EnhancedMLDetector) calculateStd(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	mean := emd.calculateMean(values)
	sumSquares := 0.0
	for _, v := range values {
		diff := v - mean
		sumSquares += diff * diff
	}
	return sumSquares / float64(len(values))
}

func (emd *EnhancedMLDetector) calculateMax(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	max := values[0]
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	return max
}

func (emd *EnhancedMLDetector) calculateMin(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	min := values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
	}
	return min
}

// Conversion helper functions
func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

func clamp(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func (emd *EnhancedMLDetector) algorithmToFloat(algorithm string) float64 {
	// Convert algorithm to numerical value for ML
	switch strings.ToLower(algorithm) {
	case "md5":
		return 10.0
	case "sha1":
		return 9.0
	case "des", "rc4":
		return 10.0
	case "rsa", "ecdsa", "ecdh":
		return 8.0
	case "aes":
		return 6.0
	case "sha256", "sha512":
		return 5.0
	default:
		return 3.0
	}
}

func (emd *EnhancedMLDetector) severityToFloat(severity string) float64 {
	switch severity {
	case "critical":
		return 10.0
	case "high":
		return 8.0
	case "medium":
		return 6.0
	case "low":
		return 4.0
	case "info":
		return 2.0
	default:
		return 1.0
	}
}

func (emd *EnhancedMLDetector) cryptoTypeToFloat(cryptoType string) float64 {
	switch cryptoType {
	case "hash":
		return 5.0
	case "encryption":
		return 8.0
	case "signature":
		return 7.0
	case "key_derivation":
		return 6.0
	case "random":
		return 3.0
	default:
		return 2.0
	}
}

// SaveEnhancedFindings saves enhanced findings to JSON
func (emd *EnhancedMLDetector) SaveEnhancedFindings(findings []*EnhancedFinding, outputPath string) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0600)
}
