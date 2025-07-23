//go:build !cgo
// +build !cgo

package ast

import (
	"fmt"
)

// Node represents an AST node (fallback implementation)
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

// TreeSitter provides AST parsing capabilities (fallback implementation)
type TreeSitter struct{}

// Match represents a tree-sitter query match (fallback implementation)
type Match struct {
	Line    int
	Column  int
	Context string
}

// NewTreeSitter creates a new TreeSitter instance (fallback)
func NewTreeSitter() *TreeSitter {
	return &TreeSitter{}
}

// SupportsLanguage always returns false when CGO is disabled
func (ts *TreeSitter) SupportsLanguage(language string) bool {
	return false
}

// ParseToTree returns an error when CGO is disabled
func (ts *TreeSitter) ParseToTree(sourceCode string, language string) (interface{}, error) {
	return nil, fmt.Errorf("AST parsing not available: CGO disabled")
}

// Parse returns an error when CGO is disabled
func Parse(sourceCode string, language interface{}) (*Node, error) {
	return nil, fmt.Errorf("AST parsing not available: CGO disabled")
}

// Query returns empty results when CGO is disabled
func (ts *TreeSitter) Query(tree interface{}, pattern string, sourceCode []byte) []Match {
	return []Match{}
}

// FindFunctionCalls returns empty results when CGO is disabled
func (ts *TreeSitter) FindFunctionCalls(tree interface{}, functionNames []string, sourceCode []byte) []Match {
	return []Match{}
}

// FindImports returns empty results when CGO is disabled
func (ts *TreeSitter) FindImports(tree interface{}, importPatterns []string, sourceCode []byte) []Match {
	return []Match{}
}

// GetSupportedLanguages returns empty list when CGO is disabled
func (ts *TreeSitter) GetSupportedLanguages() []string {
	return []string{}
}

// Cleanup does nothing when CGO is disabled
func (ts *TreeSitter) Cleanup() {
}

// GetNodeInfo returns nil when CGO is disabled
func (ts *TreeSitter) GetNodeInfo(node interface{}, sourceCode []byte) map[string]interface{} {
	return nil
}
