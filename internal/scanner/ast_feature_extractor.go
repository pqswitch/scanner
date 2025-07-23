//go:build cgo
// +build cgo

package scanner

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/pqswitch/scanner/internal/types"
	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/c"
	"github.com/smacker/go-tree-sitter/cpp"
	"github.com/smacker/go-tree-sitter/golang"
	"github.com/smacker/go-tree-sitter/java"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/python"
	"github.com/smacker/go-tree-sitter/rust"
)

// ASTFeatureExtractor extracts advanced features from AST analysis
type ASTFeatureExtractor struct {
	languageParsers map[string]*sitter.Language
	goParser        *sitter.Parser
	jsParser        *sitter.Parser
	pythonParser    *sitter.Parser
	cParser         *sitter.Parser
	cppParser       *sitter.Parser
	javaParser      *sitter.Parser
	rustParser      *sitter.Parser
}

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

// NewASTFeatureExtractor creates a new AST feature extractor
func NewASTFeatureExtractor() *ASTFeatureExtractor {
	extractor := &ASTFeatureExtractor{
		languageParsers: make(map[string]*sitter.Language),
	}

	// Initialize language parsers
	extractor.languageParsers["go"] = golang.GetLanguage()
	extractor.languageParsers["javascript"] = javascript.GetLanguage()
	extractor.languageParsers["typescript"] = javascript.GetLanguage()
	extractor.languageParsers["python"] = python.GetLanguage()
	extractor.languageParsers["c"] = c.GetLanguage()
	extractor.languageParsers["cpp"] = cpp.GetLanguage()
	extractor.languageParsers["java"] = java.GetLanguage()
	extractor.languageParsers["rust"] = rust.GetLanguage()

	// Initialize specific parsers
	extractor.goParser = sitter.NewParser()
	extractor.goParser.SetLanguage(golang.GetLanguage())

	extractor.jsParser = sitter.NewParser()
	extractor.jsParser.SetLanguage(javascript.GetLanguage())

	extractor.pythonParser = sitter.NewParser()
	extractor.pythonParser.SetLanguage(python.GetLanguage())

	extractor.cParser = sitter.NewParser()
	extractor.cParser.SetLanguage(c.GetLanguage())

	extractor.cppParser = sitter.NewParser()
	extractor.cppParser.SetLanguage(cpp.GetLanguage())

	extractor.javaParser = sitter.NewParser()
	extractor.javaParser.SetLanguage(java.GetLanguage())

	extractor.rustParser = sitter.NewParser()
	extractor.rustParser.SetLanguage(rust.GetLanguage())

	return extractor
}

// ExtractASTFeatures extracts AST-based features from source code
func (afe *ASTFeatureExtractor) ExtractASTFeatures(content []byte, filePath string, finding types.Finding) (*ASTFeatures, error) {
	language := afe.detectLanguage(filePath)

	features := &ASTFeatures{
		Language: language,
	}

	// Choose appropriate parser based on language
	var parser *sitter.Parser
	switch language {
	case "go":
		parser = afe.goParser
		// Also try Go's native AST parser for additional features
		if goFeatures := afe.extractGoASTFeatures(content, finding); goFeatures != nil {
			afe.mergeGoFeatures(features, goFeatures)
		}
	case "javascript", "typescript":
		parser = afe.jsParser
	case "python":
		parser = afe.pythonParser
	case "c":
		parser = afe.cParser
	case "cpp":
		parser = afe.cppParser
	case "java":
		parser = afe.javaParser
	case "rust":
		parser = afe.rustParser
	default:
		// Fallback to basic text analysis
		return afe.extractTextBasedFeatures(content, filePath, finding), nil
	}

	if parser == nil {
		return afe.extractTextBasedFeatures(content, filePath, finding), nil
	}

	// Parse the source code
	tree, err := parser.ParseCtx(context.Background(), nil, content)
	if err != nil {
		// Fallback to text-based analysis
		return afe.extractTextBasedFeatures(content, filePath, finding), nil
	}
	defer tree.Close()

	rootNode := tree.RootNode()

	// Extract structural features
	afe.extractStructuralFeatures(rootNode, features, language)

	// Extract crypto-specific features
	afe.extractCryptoFeatures(rootNode, features, language, finding)

	// Extract complexity features
	afe.extractComplexityFeatures(rootNode, features, language)

	// Extract context features
	afe.extractContextFeatures(rootNode, features, language, filePath)

	return features, nil
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

// extractStructuralFeatures extracts structural AST features
func (afe *ASTFeatureExtractor) extractStructuralFeatures(node *sitter.Node, features *ASTFeatures, language string) {
	afe.walkAST(node, func(n *sitter.Node) {
		nodeType := n.Type()

		switch language {
		case "go":
			afe.extractGoStructuralFeatures(n, nodeType, features)
		case "javascript", "typescript":
			afe.extractJSStructuralFeatures(n, nodeType, features)
		case "python":
			afe.extractPythonStructuralFeatures(n, nodeType, features)
		case "c", "cpp":
			afe.extractCStructuralFeatures(n, nodeType, features)
		case "java":
			afe.extractJavaStructuralFeatures(n, nodeType, features)
		case "rust":
			afe.extractRustStructuralFeatures(n, nodeType, features)
		}
	})
}

// extractGoStructuralFeatures extracts Go-specific structural features
func (afe *ASTFeatureExtractor) extractGoStructuralFeatures(node *sitter.Node, nodeType string, features *ASTFeatures) {
	switch nodeType {
	case "function_declaration", "method_declaration":
		features.FunctionDefinitions++
	case "var_declaration", "short_var_declaration":
		features.VariableDeclarations++
	case "import_declaration":
		features.ImportStatements++
	case "call_expression":
		features.FunctionCallDepth++
	case "type_declaration":
		if afe.isInterface(node) {
			features.HasCryptoInterface = true
		}
	case "for_statement", "range_clause":
		if afe.containsCryptoContent(node) {
			features.HasCryptoLoop = true
		}
	case "if_statement":
		if afe.containsCryptoContent(node) {
			features.HasCryptoConditional = true
		}
	case "pointer_type":
		features.HasPointers = true
	case "type_parameter_list":
		features.HasGenerics = true
	}
}

// extractJSStructuralFeatures extracts JavaScript/TypeScript-specific features
func (afe *ASTFeatureExtractor) extractJSStructuralFeatures(node *sitter.Node, nodeType string, features *ASTFeatures) {
	switch nodeType {
	case "function_declaration", "method_definition", "arrow_function":
		features.FunctionDefinitions++
	case "variable_declaration", "lexical_declaration":
		features.VariableDeclarations++
	case "import_statement":
		features.ImportStatements++
	case "call_expression":
		features.FunctionCallDepth++
	case "class_declaration":
		features.ClassDefinitions++
	case "for_statement", "for_in_statement", "while_statement":
		if afe.containsCryptoContent(node) {
			features.HasCryptoLoop = true
		}
	case "if_statement":
		if afe.containsCryptoContent(node) {
			features.HasCryptoConditional = true
		}
	case "try_statement":
		if afe.containsCryptoContent(node) {
			features.HasCryptoTryCatch = true
		}
	}
}

// extractPythonStructuralFeatures extracts Python-specific features
func (afe *ASTFeatureExtractor) extractPythonStructuralFeatures(node *sitter.Node, nodeType string, features *ASTFeatures) {
	switch nodeType {
	case "function_definition":
		features.FunctionDefinitions++
	case "assignment":
		features.VariableDeclarations++
	case "import_statement", "import_from_statement":
		features.ImportStatements++
	case "call":
		features.FunctionCallDepth++
	case "class_definition":
		features.ClassDefinitions++
	case "for_statement", "while_statement":
		if afe.containsCryptoContent(node) {
			features.HasCryptoLoop = true
		}
	case "if_statement":
		if afe.containsCryptoContent(node) {
			features.HasCryptoConditional = true
		}
	case "try_statement":
		if afe.containsCryptoContent(node) {
			features.HasCryptoTryCatch = true
		}
	}
}

// extractCStructuralFeatures extracts C/C++-specific features
func (afe *ASTFeatureExtractor) extractCStructuralFeatures(node *sitter.Node, nodeType string, features *ASTFeatures) {
	switch nodeType {
	case "function_definition", "function_declarator":
		features.FunctionDefinitions++
	case "declaration":
		features.VariableDeclarations++
	case "preproc_include":
		features.ImportStatements++
	case "call_expression":
		features.FunctionCallDepth++
	case "struct_specifier", "class_specifier":
		features.ClassDefinitions++
	case "for_statement", "while_statement":
		if afe.containsCryptoContent(node) {
			features.HasCryptoLoop = true
		}
	case "if_statement":
		if afe.containsCryptoContent(node) {
			features.HasCryptoConditional = true
		}
	case "pointer_declarator":
		features.HasPointers = true
	}
}

// extractJavaStructuralFeatures extracts Java-specific features
func (afe *ASTFeatureExtractor) extractJavaStructuralFeatures(node *sitter.Node, nodeType string, features *ASTFeatures) {
	switch nodeType {
	case "method_declaration", "constructor_declaration":
		features.FunctionDefinitions++
	case "variable_declarator":
		features.VariableDeclarations++
	case "import_declaration":
		features.ImportStatements++
	case "method_invocation":
		features.FunctionCallDepth++
	case "class_declaration", "interface_declaration":
		features.ClassDefinitions++
		if nodeType == "interface_declaration" {
			features.HasCryptoInterface = true
		}
	case "for_statement", "enhanced_for_statement", "while_statement":
		if afe.containsCryptoContent(node) {
			features.HasCryptoLoop = true
		}
	case "if_statement":
		if afe.containsCryptoContent(node) {
			features.HasCryptoConditional = true
		}
	case "try_statement":
		if afe.containsCryptoContent(node) {
			features.HasCryptoTryCatch = true
		}
	case "type_parameters":
		features.HasGenerics = true
	}
}

// extractRustStructuralFeatures extracts Rust-specific features
func (afe *ASTFeatureExtractor) extractRustStructuralFeatures(node *sitter.Node, nodeType string, features *ASTFeatures) {
	switch nodeType {
	case "function_item":
		features.FunctionDefinitions++
	case "let_declaration":
		features.VariableDeclarations++
	case "use_declaration":
		features.ImportStatements++
	case "call_expression":
		features.FunctionCallDepth++
	case "struct_item", "impl_item":
		features.ClassDefinitions++
	case "trait_item":
		features.HasCryptoInterface = true
	case "for_expression", "while_expression", "loop_expression":
		if afe.containsCryptoContent(node) {
			features.HasCryptoLoop = true
		}
	case "if_expression":
		if afe.containsCryptoContent(node) {
			features.HasCryptoConditional = true
		}
	case "closure_expression":
		features.HasLambdas = true
	case "generic_type":
		features.HasGenerics = true
	}
}

// extractCryptoFeatures extracts crypto-specific AST features
func (afe *ASTFeatureExtractor) extractCryptoFeatures(node *sitter.Node, features *ASTFeatures, language string, finding types.Finding) {
	cryptoKeywords := []string{
		"crypto", "cipher", "hash", "encrypt", "decrypt", "sign", "verify",
		"rsa", "ecdsa", "aes", "sha", "md5", "hmac", "ssl", "tls",
		"key", "secret", "password", "salt", "nonce", "iv",
	}

	afe.walkAST(node, func(n *sitter.Node) {
		nodeContent := n.Content([]byte(finding.Context))
		nodeContentLower := strings.ToLower(nodeContent)

		// Check for crypto-related content
		for _, keyword := range cryptoKeywords {
			if strings.Contains(nodeContentLower, keyword) {
				switch n.Type() {
				case "call_expression", "method_invocation", "call":
					features.CryptoFunctionCalls++
				case "identifier", "variable_name":
					features.CryptoVariables++
				case "const", "constant", "literal":
					features.CryptoConstants++
				case "method_declaration", "function_declaration":
					features.CryptoClassMethods++
				}
				break
			}
		}
	})
}

// extractComplexityFeatures calculates code complexity metrics
func (afe *ASTFeatureExtractor) extractComplexityFeatures(node *sitter.Node, features *ASTFeatures, language string) {
	// Calculate cyclomatic complexity
	complexity := 1 // Base complexity

	afe.walkAST(node, func(n *sitter.Node) {
		switch n.Type() {
		case "if_statement", "if_expression":
			complexity++
		case "for_statement", "for_expression", "while_statement", "while_expression":
			complexity++
		case "switch_statement", "match_expression":
			complexity++
		case "case_clause", "match_arm":
			complexity++
		case "catch_clause", "except_clause":
			complexity++
		case "conditional_expression", "ternary_expression":
			complexity++
		}

		// Count lines of code
		if n.Type() == "source_file" || n.Type() == "program" {
			features.LinesOfCode = int(n.EndPoint().Row - n.StartPoint().Row + 1)
		}
	})

	features.CyclomaticComplexity = complexity

	// Simple Halstead complexity approximation
	features.HalsteadComplexity = float64(features.FunctionCallDepth) * 1.5
}

// extractContextFeatures extracts context-based features
func (afe *ASTFeatureExtractor) extractContextFeatures(node *sitter.Node, features *ASTFeatures, language string, filePath string) {
	// Check if in crypto namespace/package
	afe.walkAST(node, func(n *sitter.Node) {
		nodeType := n.Type()

		switch language {
		case "go":
			if nodeType == "package_clause" {
				if afe.isCryptoPackage(n) {
					features.InCryptoNamespace = true
				}
			}
		case "java":
			if nodeType == "package_declaration" {
				if afe.isCryptoPackage(n) {
					features.InCryptoNamespace = true
				}
			}
		case "python":
			if nodeType == "import_statement" || nodeType == "import_from_statement" {
				if afe.isCryptoImport(n) {
					features.NearCryptoImports = true
				}
			}
		}

		// Check for documentation
		if nodeType == "comment" || nodeType == "doc_comment" {
			features.HasDocumentation = true
		}

		// Check for error handling
		if nodeType == "try_statement" || nodeType == "error" {
			features.HasErrorHandling = true
		}
	})

	// Check file path for security context
	pathLower := strings.ToLower(filePath)
	if strings.Contains(pathLower, "security") || strings.Contains(pathLower, "crypto") {
		features.InSecurityContext = true
	}
}

// Helper functions

func (afe *ASTFeatureExtractor) walkAST(node *sitter.Node, fn func(*sitter.Node)) {
	fn(node)

	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child != nil {
			afe.walkAST(child, fn)
		}
	}
}

func (afe *ASTFeatureExtractor) containsCryptoContent(node *sitter.Node) bool {
	// This would need access to the source content
	// For now, return false as a placeholder
	return false
}

func (afe *ASTFeatureExtractor) isInterface(node *sitter.Node) bool {
	return strings.Contains(strings.ToLower(node.Type()), "interface")
}

func (afe *ASTFeatureExtractor) isCryptoPackage(node *sitter.Node) bool {
	// This would need to examine the package/namespace name
	return false
}

func (afe *ASTFeatureExtractor) isCryptoImport(node *sitter.Node) bool {
	// This would need to examine the import statement
	return false
}

// extractGoASTFeatures uses Go's native AST parser for additional features
func (afe *ASTFeatureExtractor) extractGoASTFeatures(content []byte, finding types.Finding) map[string]interface{} {
	fset := token.NewFileSet()

	// Try to parse as Go source
	file, err := parser.ParseFile(fset, "", content, parser.ParseComments)
	if err != nil {
		return nil
	}

	features := make(map[string]interface{})

	// Extract Go-specific features using native AST
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.FuncDecl:
			if node.Name != nil {
				features["go_function_names"] = append(
					features["go_function_names"].([]string),
					node.Name.Name,
				)
			}
		case *ast.CallExpr:
			if fun, ok := node.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := fun.X.(*ast.Ident); ok {
					callName := pkg.Name + "." + fun.Sel.Name
					features["go_call_expressions"] = append(
						features["go_call_expressions"].([]string),
						callName,
					)
				}
			}
		case *ast.ImportSpec:
			if node.Path != nil {
				path, _ := strconv.Unquote(node.Path.Value)
				features["go_imports"] = append(
					features["go_imports"].([]string),
					path,
				)
			}
		}
		return true
	})

	return features
}

func (afe *ASTFeatureExtractor) mergeGoFeatures(features *ASTFeatures, goFeatures map[string]interface{}) {
	// Merge Go-specific features into the main features struct
	if imports, ok := goFeatures["go_imports"].([]string); ok {
		for _, imp := range imports {
			if strings.Contains(strings.ToLower(imp), "crypto") {
				features.NearCryptoImports = true
				break
			}
		}
	}
}

// extractTextBasedFeatures provides fallback text-based analysis
func (afe *ASTFeatureExtractor) extractTextBasedFeatures(content []byte, filePath string, finding types.Finding) *ASTFeatures {
	text := string(content)
	lines := strings.Split(text, "\n")

	features := &ASTFeatures{
		Language:    afe.detectLanguage(filePath),
		LinesOfCode: len(lines),
	}

	// Basic pattern matching for fallback
	features.FunctionCallDepth = len(regexp.MustCompile(`\w+\s*\(`).FindAllString(text, -1))
	features.VariableDeclarations = len(regexp.MustCompile(`\b(var|let|const|int|string)\s+\w+`).FindAllString(text, -1))
	features.ImportStatements = len(regexp.MustCompile(`\b(import|include|require|use)\s+`).FindAllString(text, -1))

	// Check for crypto patterns
	cryptoPattern := regexp.MustCompile(`(?i)(crypto|cipher|hash|encrypt|decrypt|rsa|aes|sha|md5)`)
	if cryptoPattern.MatchString(text) {
		features.CryptoFunctionCalls = len(cryptoPattern.FindAllString(text, -1))
	}

	return features
}
