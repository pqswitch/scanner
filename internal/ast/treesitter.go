//go:build cgo
// +build cgo

package ast

import (
	"context"
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/golang"
)

// Node represents an AST node
type Node struct {
	Type     string
	Content  string
	StartPos Position
	EndPos   Position
	Children []*Node
}

// Position represents a location in the source code
type Position struct {
	Line   int
	Column int
}

// TreeSitter provides AST parsing capabilities using tree-sitter
type TreeSitter struct {
	// No fields needed
}

// Match represents a tree-sitter query match
type Match struct {
	Line    int
	Column  int
	Context string
	Node    *sitter.Node
}

// NewTreeSitter creates a new TreeSitter instance
func NewTreeSitter() *TreeSitter {
	return &TreeSitter{}
}

// SupportsLanguage checks if a language is supported
func (ts *TreeSitter) SupportsLanguage(language string) bool {
	supportedLanguages := []string{
		"go", "java", "javascript", "typescript", "python", "c", "cpp", "rust", "kotlin",
	}

	for _, supported := range supportedLanguages {
		if language == supported {
			return true
		}
	}
	return false
}

// ParseToTree parses source code and returns a tree-sitter Tree for querying
// Creates a new parser instance for each call to ensure thread safety
func (ts *TreeSitter) ParseToTree(sourceCode string, language string) (*sitter.Tree, error) {
	parser, err := ts.createParser(language)
	if err != nil {
		return nil, err
	}
	defer parser.Close() // Clean up parser after use

	tree, err := parser.ParseCtx(context.Background(), nil, []byte(sourceCode))
	if err != nil {
		return nil, fmt.Errorf("failed to parse source code: %w", err)
	}
	if tree == nil {
		return nil, fmt.Errorf("failed to parse source code")
	}

	return tree, nil
}

// Parse parses source code using tree-sitter
func Parse(sourceCode string, language *sitter.Language) (*Node, error) {
	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(language)

	tree, err := parser.ParseCtx(context.Background(), nil, []byte(sourceCode))
	if err != nil {
		return nil, fmt.Errorf("failed to parse source code: %w", err)
	}
	if tree == nil {
		return nil, fmt.Errorf("failed to parse source code")
	}
	defer tree.Close()

	rootNode := tree.RootNode()
	return convertNode(rootNode, sourceCode), nil
}

// convertNode converts a tree-sitter node to our Node type
func convertNode(node *sitter.Node, sourceCode string) *Node {
	startByte := node.StartByte()
	endByte := node.EndByte()
	content := sourceCode[startByte:endByte]

	result := &Node{
		Type:    node.Type(),
		Content: content,
		StartPos: Position{
			Line:   int(node.StartPoint().Row),
			Column: int(node.StartPoint().Column),
		},
		EndPos: Position{
			Line:   int(node.EndPoint().Row),
			Column: int(node.EndPoint().Column),
		},
	}

	childCount := node.ChildCount()
	if childCount > 0 {
		result.Children = make([]*Node, 0, childCount)
		for i := 0; i < int(childCount); i++ {
			child := node.Child(i)
			if child != nil {
				result.Children = append(result.Children, convertNode(child, sourceCode))
			}
		}
	}

	return result
}

// FindNodesByType finds all nodes of a specific type
func FindNodesByType(root *Node, nodeType string) []*Node {
	var results []*Node
	if root.Type == nodeType {
		results = append(results, root)
	}
	for _, child := range root.Children {
		results = append(results, FindNodesByType(child, nodeType)...)
	}
	return results
}

// GetNodePath returns the path from root to the given node
func GetNodePath(root, target *Node) []*Node {
	if root == target {
		return []*Node{root}
	}
	for _, child := range root.Children {
		if path := GetNodePath(child, target); path != nil {
			return append([]*Node{root}, path...)
		}
	}
	return nil
}

// GetNodeAtPosition finds the node at the given position
func GetNodeAtPosition(root *Node, line, column int) *Node {
	if line < root.StartPos.Line || line > root.EndPos.Line {
		return nil
	}
	if line == root.StartPos.Line && column < root.StartPos.Column {
		return nil
	}
	if line == root.EndPos.Line && column > root.EndPos.Column {
		return nil
	}

	for _, child := range root.Children {
		if node := GetNodeAtPosition(child, line, column); node != nil {
			return node
		}
	}
	return root
}

// String returns a string representation of the node
func (n *Node) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s (%d:%d-%d:%d)", n.Type,
		n.StartPos.Line, n.StartPos.Column,
		n.EndPos.Line, n.EndPos.Column))
	if len(n.Children) > 0 {
		sb.WriteString(" {")
		for i, child := range n.Children {
			if i > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString(child.String())
		}
		sb.WriteString("}")
	}
	return sb.String()
}

// Query executes a tree-sitter query on the AST
func (ts *TreeSitter) Query(tree *sitter.Tree, pattern string, sourceCode []byte) []Match {
	var matches []Match
	root := tree.RootNode()
	ts.traverseNode(root, pattern, &matches, sourceCode)
	return matches
}

// createParser creates a new parser instance for the specified language
// This ensures thread safety by giving each parsing operation its own parser
func (ts *TreeSitter) createParser(language string) (*sitter.Parser, error) {
	parser := sitter.NewParser()

	// Set language-specific grammar
	switch language {
	case "go":
		parser.SetLanguage(golang.GetLanguage())
	case "java":
		// TODO: Add java language support
		parser.Close()
		return nil, fmt.Errorf("java language not yet supported")
	case "javascript":
		// TODO: Add javascript language support
		parser.Close()
		return nil, fmt.Errorf("javascript language not yet supported")
	case "typescript":
		// TODO: Add typescript language support
		parser.Close()
		return nil, fmt.Errorf("typescript language not yet supported")
	case "python":
		// TODO: Add python language support
		parser.Close()
		return nil, fmt.Errorf("python language not yet supported")
	case "c":
		// TODO: Add c language support
		parser.Close()
		return nil, fmt.Errorf("c language not yet supported")
	case "cpp":
		// TODO: Add cpp language support
		parser.Close()
		return nil, fmt.Errorf("cpp language not yet supported")
	case "rust":
		// TODO: Add rust language support
		parser.Close()
		return nil, fmt.Errorf("rust language not yet supported")
	case "kotlin":
		// TODO: Add kotlin language support
		parser.Close()
		return nil, fmt.Errorf("kotlin language not yet supported")
	default:
		parser.Close()
		return nil, fmt.Errorf("unsupported language: %s", language)
	}

	return parser, nil
}

// traverseNode recursively traverses AST nodes looking for patterns
func (ts *TreeSitter) traverseNode(node *sitter.Node, pattern string, matches *[]Match, sourceCode []byte) {
	if node == nil {
		return
	}

	nodeType := node.Type()
	nodeText := node.Content(sourceCode)

	if ts.matchesPattern(nodeType, nodeText, pattern) {
		startPoint := node.StartPoint()
		match := Match{
			Line:    int(startPoint.Row) + 1,
			Column:  int(startPoint.Column) + 1,
			Context: ts.extractNodeContext(node, sourceCode),
			Node:    node,
		}
		*matches = append(*matches, match)
	}

	childCount := node.ChildCount()
	for i := 0; i < int(childCount); i++ {
		child := node.Child(i)
		ts.traverseNode(child, pattern, matches, sourceCode)
	}
}

// matchesPattern checks if a node matches the given pattern
func (ts *TreeSitter) matchesPattern(nodeType, nodeText, pattern string) bool {
	cryptoPatterns := map[string][]string{
		"function_call": {
			"GenerateKey", "generateKey", "newKey", "createKey",
			"RSA_generate_key", "EC_KEY_generate_key", "EVP_PKEY_keygen",
		},
		"import_statement": {
			"crypto/rsa", "crypto/ecdsa", "crypto/md5", "crypto/sha1",
		},
		"method_invocation": {
			"getInstance", "generateKeyPair", "newInstance",
		},
		"identifier": {
			"RSA", "ECDSA", "MD5", "SHA1", "DES", "3DES", "RC4",
		},
	}

	if patterns, exists := cryptoPatterns[nodeType]; exists {
		for _, p := range patterns {
			if strings.Contains(nodeText, p) {
				return true
			}
		}
	}

	return strings.Contains(nodeText, pattern) || strings.Contains(nodeType, pattern)
}

// extractNodeContext extracts context around a node
func (ts *TreeSitter) extractNodeContext(node *sitter.Node, sourceCode []byte) string {
	if node == nil {
		return ""
	}

	parent := node.Parent()
	if parent != nil {
		return parent.Content(sourceCode)
	}

	return node.Content(sourceCode)
}

// GetNodeInfo returns detailed information about a node
func (ts *TreeSitter) GetNodeInfo(node *sitter.Node, sourceCode []byte) map[string]interface{} {
	if node == nil {
		return nil
	}

	startPoint := node.StartPoint()
	endPoint := node.EndPoint()

	return map[string]interface{}{
		"type":         node.Type(),
		"content":      node.Content(sourceCode),
		"start_line":   startPoint.Row + 1,
		"start_column": startPoint.Column + 1,
		"end_line":     endPoint.Row + 1,
		"end_column":   endPoint.Column + 1,
		"child_count":  node.ChildCount(),
		"is_named":     node.IsNamed(),
	}
}

// FindFunctionCalls finds function calls in the AST
func (ts *TreeSitter) FindFunctionCalls(tree *sitter.Tree, functionNames []string, sourceCode []byte) []Match {
	var matches []Match
	root := tree.RootNode()
	ts.findFunctionCallsRecursive(root, functionNames, &matches, sourceCode)
	return matches
}

// findFunctionCallsRecursive recursively finds function calls
func (ts *TreeSitter) findFunctionCallsRecursive(node *sitter.Node, functionNames []string, matches *[]Match, sourceCode []byte) {
	if node == nil {
		return
	}

	nodeType := node.Type()
	nodeText := node.Content(sourceCode)

	if strings.Contains(nodeType, "call") || strings.Contains(nodeType, "invocation") {
		for _, funcName := range functionNames {
			if strings.Contains(nodeText, funcName) {
				startPoint := node.StartPoint()
				match := Match{
					Line:    int(startPoint.Row) + 1,
					Column:  int(startPoint.Column) + 1,
					Context: ts.extractNodeContext(node, sourceCode),
					Node:    node,
				}
				*matches = append(*matches, match)
				break
			}
		}
	}

	childCount := node.ChildCount()
	for i := 0; i < int(childCount); i++ {
		child := node.Child(i)
		ts.findFunctionCallsRecursive(child, functionNames, matches, sourceCode)
	}
}

// FindImports finds import statements in the AST
func (ts *TreeSitter) FindImports(tree *sitter.Tree, importPatterns []string, sourceCode []byte) []Match {
	var matches []Match
	root := tree.RootNode()
	ts.findImportsRecursive(root, importPatterns, &matches, sourceCode)
	return matches
}

// findImportsRecursive recursively finds import statements
func (ts *TreeSitter) findImportsRecursive(node *sitter.Node, importPatterns []string, matches *[]Match, sourceCode []byte) {
	if node == nil {
		return
	}

	nodeType := node.Type()
	nodeText := node.Content(sourceCode)

	if strings.Contains(nodeType, "import") {
		for _, pattern := range importPatterns {
			if strings.Contains(nodeText, pattern) {
				startPoint := node.StartPoint()
				match := Match{
					Line:    int(startPoint.Row) + 1,
					Column:  int(startPoint.Column) + 1,
					Context: ts.extractNodeContext(node, sourceCode),
					Node:    node,
				}
				*matches = append(*matches, match)
				break
			}
		}
	}

	childCount := node.ChildCount()
	for i := 0; i < int(childCount); i++ {
		child := node.Child(i)
		ts.findImportsRecursive(child, importPatterns, matches, sourceCode)
	}
}

// GetSupportedLanguages returns a list of supported languages
func (ts *TreeSitter) GetSupportedLanguages() []string {
	return []string{
		"go", "java", "javascript", "typescript", "python", "c", "cpp", "rust", "kotlin",
	}
}

// Cleanup cleans up resources - no longer needed since we don't store parsers
func (ts *TreeSitter) Cleanup() {
	// No shared parsers to clean up anymore
}
