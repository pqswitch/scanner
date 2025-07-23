//go:build !cgo
// +build !cgo

package scanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pqswitch/scanner/internal/types"
)

// ASTFeatureExtractor extracts advanced features from AST analysis (fallback implementation)
type ASTFeatureExtractor struct{}

// ASTFeatures represents extracted AST-based features
type ASTFeatures struct {
	// Structural features
	FunctionCallDepth    int `json:"function_call_depth"`
	NestedBlockDepth     int `json:"nested_block_depth"`
	VariableDeclarations int `json:"variable_declarations"`
	FunctionDefinitions  int `json:"function_definitions"`
	ClassDefinitions     int `json:"class_definitions"`
	ImportStatements     int `json:"import_statements"`

	// Crypto-specific AST features
	CryptoFunctionCalls int `json:"crypto_function_calls"`
	CryptoVariables     int `json:"crypto_variables"`
	CryptoConstants     int `json:"crypto_constants"`
	CryptoClassMethods  int `json:"crypto_class_methods"`

	// Code complexity
	CyclomaticComplexity int     `json:"cyclomatic_complexity"`
	HalsteadComplexity   float64 `json:"halstead_complexity"`
	LinesOfCode          int     `json:"lines_of_code"`

	// Pattern-specific features
	HasCryptoLoop        bool `json:"has_crypto_loop"`
	HasCryptoConditional bool `json:"has_crypto_conditional"`
	HasCryptoTryCatch    bool `json:"has_crypto_try_catch"`
	HasCryptoInterface   bool `json:"has_crypto_interface"`

	// Language-specific features
	Language    string `json:"language"`
	HasGenerics bool   `json:"has_generics"`
	HasPointers bool   `json:"has_pointers"`
	HasLambdas  bool   `json:"has_lambdas"`

	// Context features
	InCryptoNamespace bool `json:"in_crypto_namespace"`
	InSecurityContext bool `json:"in_security_context"`
	NearCryptoImports bool `json:"near_crypto_imports"`

	// Quality indicators
	HasDocumentation   bool `json:"has_documentation"`
	HasTypeAnnotations bool `json:"has_type_annotations"`
	HasErrorHandling   bool `json:"has_error_handling"`
}

// NewASTFeatureExtractor creates a new AST feature extractor (fallback)
func NewASTFeatureExtractor() *ASTFeatureExtractor {
	return &ASTFeatureExtractor{}
}

// ExtractASTFeatures extracts AST-based features from source code (fallback implementation)
func (afe *ASTFeatureExtractor) ExtractASTFeatures(content []byte, filePath string, finding types.Finding) (*ASTFeatures, error) {
	language := afe.detectLanguage(filePath)

	features := &ASTFeatures{
		Language: language,
	}

	// For Go files, we can still use Go's native AST parser
	if language == "go" {
		if goFeatures := afe.extractGoASTFeatures(content, finding); goFeatures != nil {
			afe.mergeGoFeatures(features, goFeatures)
		}
	}

	// Fallback to text-based analysis for other languages
	return afe.extractTextBasedFeatures(content, filePath, finding), nil
}

// detectLanguage detects programming language from file extension
func (afe *ASTFeatureExtractor) detectLanguage(filePath string) string {
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

// extractGoASTFeatures extracts Go-specific features using Go's native AST parser
func (afe *ASTFeatureExtractor) extractGoASTFeatures(content []byte, finding types.Finding) map[string]interface{} {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "", content, parser.ParseComments)
	if err != nil {
		return nil
	}

	features := make(map[string]interface{})

	// Extract basic Go AST features
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			if val, ok := features["function_definitions"]; ok {
				features["function_definitions"] = val.(int) + 1
			} else {
				features["function_definitions"] = 1
			}
		case *ast.GenDecl:
			if x.Tok == token.VAR {
				if val, ok := features["variable_declarations"]; ok {
					features["variable_declarations"] = val.(int) + 1
				} else {
					features["variable_declarations"] = 1
				}
			}
			if x.Tok == token.IMPORT {
				if val, ok := features["import_statements"]; ok {
					features["import_statements"] = val.(int) + 1
				} else {
					features["import_statements"] = 1
				}
			}
		case *ast.CallExpr:
			if val, ok := features["function_call_depth"]; ok {
				features["function_call_depth"] = val.(int) + 1
			} else {
				features["function_call_depth"] = 1
			}
		}
		return true
	})

	return features
}

// mergeGoFeatures merges Go-specific features into the main features struct
func (afe *ASTFeatureExtractor) mergeGoFeatures(features *ASTFeatures, goFeatures map[string]interface{}) {
	if val, ok := goFeatures["function_definitions"]; ok {
		features.FunctionDefinitions = val.(int)
	}
	if val, ok := goFeatures["variable_declarations"]; ok {
		features.VariableDeclarations = val.(int)
	}
	if val, ok := goFeatures["import_statements"]; ok {
		features.ImportStatements = val.(int)
	}
	if val, ok := goFeatures["function_call_depth"]; ok {
		features.FunctionCallDepth = val.(int)
	}
}

// extractTextBasedFeatures extracts features using simple text analysis
func (afe *ASTFeatureExtractor) extractTextBasedFeatures(content []byte, filePath string, finding types.Finding) *ASTFeatures {
	text := string(content)
	language := afe.detectLanguage(filePath)

	features := &ASTFeatures{
		Language: language,
	}

	// Basic text-based feature extraction
	lines := strings.Split(text, "\n")
	features.LinesOfCode = len(lines)

	// Count basic patterns
	cryptoKeywords := []string{
		"crypto", "cipher", "hash", "encrypt", "decrypt", "sign", "verify",
		"rsa", "ecdsa", "aes", "sha", "md5", "hmac", "ssl", "tls",
		"key", "secret", "password", "salt", "nonce", "iv",
	}

	lowerText := strings.ToLower(text)
	for _, keyword := range cryptoKeywords {
		count := strings.Count(lowerText, keyword)
		features.CryptoFunctionCalls += count
	}

	// Simple complexity estimation
	features.CyclomaticComplexity = 1 +
		strings.Count(text, "if ") +
		strings.Count(text, "for ") +
		strings.Count(text, "while ") +
		strings.Count(text, "switch ") +
		strings.Count(text, "case ")

	// Check for crypto-related patterns
	features.HasCryptoLoop = regexp.MustCompile(`(?i)(for|while).*crypto`).MatchString(text)
	features.HasCryptoConditional = regexp.MustCompile(`(?i)if.*crypto`).MatchString(text)
	features.HasCryptoTryCatch = regexp.MustCompile(`(?i)(try|catch).*crypto`).MatchString(text)

	// Language-specific patterns
	switch language {
	case "go":
		features.HasPointers = strings.Contains(text, "*")
		features.HasGenerics = strings.Contains(text, "[T")
		features.InCryptoNamespace = strings.Contains(text, "package crypto")
	case "java":
		features.HasGenerics = strings.Contains(text, "<") && strings.Contains(text, ">")
		features.InCryptoNamespace = strings.Contains(text, "package") && strings.Contains(lowerText, "crypto")
	}

	return features
}
