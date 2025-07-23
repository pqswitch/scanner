package patch

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	"github.com/pqswitch/scanner/internal/config"
	"github.com/pqswitch/scanner/internal/types"
)

// Engine handles patch generation using templates
type Engine struct {
	config    *config.Config
	templates map[string]*template.Template
	cueCtx    *cue.Context
}

// PatchRequest represents a request to generate a patch
type PatchRequest struct {
	Finding    types.Finding          `json:"finding"`
	TargetFile string                 `json:"target_file"`
	Language   string                 `json:"language"`
	PatchType  string                 `json:"patch_type"`
	Variables  map[string]interface{} `json:"variables"`
}

// PatchResult represents the result of patch generation
type PatchResult struct {
	Success     bool   `json:"success"`
	PatchData   string `json:"patch_data"`
	Description string `json:"description"`
	Error       string `json:"error,omitempty"`
}

// PatchTemplate represents a patch template
type PatchTemplate struct {
	Name        string            `json:"name"`
	Language    string            `json:"language"`
	CryptoType  string            `json:"crypto_type"`
	Algorithm   string            `json:"algorithm"`
	Template    string            `json:"template"`
	Variables   map[string]string `json:"variables"`
	Description string            `json:"description"`
}

// NewEngine creates a new patch engine
func NewEngine(cfg *config.Config) *Engine {
	return &Engine{
		config:    cfg,
		templates: make(map[string]*template.Template),
		cueCtx:    cuecontext.New(),
	}
}

// LoadTemplates loads patch templates from the templates directory
func (e *Engine) LoadTemplates() error {
	templatesPath := e.config.Patch.TemplatesPath
	if templatesPath == "" {
		templatesPath = "internal/patch/templates"
	}

	return filepath.Walk(templatesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".tpl" || ext == ".tmpl" {
			return e.loadTemplate(path)
		}

		return nil
	})
}

// loadTemplate loads a single template file
func (e *Engine) loadTemplate(templatePath string) error {
	content, err := os.ReadFile(templatePath) //nolint:gosec // Legitimate template file reading
	if err != nil {
		return err
	}

	templateName := strings.TrimSuffix(filepath.Base(templatePath), filepath.Ext(templatePath))

	tmpl, err := template.New(templateName).Parse(string(content))
	if err != nil {
		return fmt.Errorf("failed to parse template %s: %w", templatePath, err)
	}

	e.templates[templateName] = tmpl
	return nil
}

// GeneratePatch generates a patch for the given finding
func (e *Engine) GeneratePatch(request PatchRequest) PatchResult {
	// Determine the appropriate template
	templateName := e.selectTemplate(request)
	if templateName == "" {
		return PatchResult{
			Success: false,
			Error:   "No suitable template found for the given finding",
		}
	}

	tmpl, exists := e.templates[templateName]
	if !exists {
		return PatchResult{
			Success: false,
			Error:   fmt.Sprintf("Template %s not found", templateName),
		}
	}

	// Prepare template variables
	variables := e.prepareVariables(request)

	// Generate patch
	var patchData strings.Builder
	if err := tmpl.Execute(&patchData, variables); err != nil {
		return PatchResult{
			Success: false,
			Error:   fmt.Sprintf("Failed to execute template: %v", err),
		}
	}

	return PatchResult{
		Success:     true,
		PatchData:   patchData.String(),
		Description: fmt.Sprintf("Generated patch for %s in %s", request.Finding.Algorithm, request.Language),
	}
}

// selectTemplate selects the appropriate template for a finding
func (e *Engine) selectTemplate(request PatchRequest) string {
	// Template naming convention: {language}_{crypto_type}_{algorithm}
	candidates := []string{
		fmt.Sprintf("%s_%s_%s", request.Language, request.Finding.CryptoType, strings.ToLower(request.Finding.Algorithm)),
		fmt.Sprintf("%s_%s", request.Language, request.Finding.CryptoType),
		fmt.Sprintf("%s_generic", request.Language),
		"generic",
	}

	for _, candidate := range candidates {
		if _, exists := e.templates[candidate]; exists {
			return candidate
		}
	}

	return ""
}

// prepareVariables prepares template variables
func (e *Engine) prepareVariables(request PatchRequest) map[string]interface{} {
	variables := make(map[string]interface{})

	// Copy request variables
	for k, v := range request.Variables {
		variables[k] = v
	}

	// Add finding information
	variables["Finding"] = request.Finding
	variables["File"] = request.TargetFile
	variables["Language"] = request.Language
	variables["Algorithm"] = request.Finding.Algorithm
	variables["CryptoType"] = request.Finding.CryptoType
	variables["Line"] = request.Finding.Line
	variables["Column"] = request.Finding.Column

	// Add migration suggestions based on algorithm
	variables["PQAlternative"] = e.getPQAlternative(request.Finding.Algorithm)
	variables["MigrationStrategy"] = e.getMigrationStrategy(request.Finding.Algorithm, request.Language)

	// Add configuration variables
	for k, v := range e.config.Patch.Variables {
		if _, exists := variables[k]; !exists {
			variables[k] = v
		}
	}

	return variables
}

// getPQAlternative returns the post-quantum alternative for an algorithm
func (e *Engine) getPQAlternative(algorithm string) string {
	algorithmUpper := strings.ToUpper(algorithm)

	alternatives := map[string]string{
		"RSA":   "ML-KEM",
		"ECDSA": "ML-DSA",
		"ECDH":  "ML-KEM",
		"DSA":   "ML-DSA",
		"DH":    "ML-KEM",
		"MD5":   "SHA-256",
		"SHA1":  "SHA-256",
		"DES":   "AES-256",
		"3DES":  "AES-256",
		"RC4":   "ChaCha20-Poly1305",
	}

	if alt, exists := alternatives[algorithmUpper]; exists {
		return alt
	}

	return "Post-Quantum Alternative"
}

// getMigrationStrategy returns the migration strategy for an algorithm and language
func (e *Engine) getMigrationStrategy(algorithm, language string) string {
	algorithmUpper := strings.ToUpper(algorithm)

	strategies := map[string]map[string]string{
		"RSA": {
			"go":         "Replace crypto/rsa with liboqs-go ML-KEM implementation",
			"java":       "Use Bouncy Castle PQC provider with ML-KEM",
			"javascript": "Implement hybrid RSA+ML-KEM using node-oqs",
			"python":     "Use liboqs-python for ML-KEM key encapsulation",
			"c":          "Replace with liboqs OQS_KEM_new() and ML-KEM",
			"cpp":        "Use liboqs C++ wrapper for ML-KEM",
		},
		"ECDSA": {
			"go":         "Replace crypto/ecdsa with liboqs-go ML-DSA signatures",
			"java":       "Use Bouncy Castle PQC provider with ML-DSA",
			"javascript": "Implement hybrid ECDSA+ML-DSA signatures",
			"python":     "Use liboqs-python for ML-DSA signatures",
			"c":          "Replace with liboqs OQS_SIG_new() and ML-DSA",
			"cpp":        "Use liboqs C++ wrapper for ML-DSA",
		},
	}

	if langStrategies, exists := strategies[algorithmUpper]; exists {
		if strategy, exists := langStrategies[language]; exists {
			return strategy
		}
	}

	return fmt.Sprintf("Migrate %s to post-quantum alternative", algorithm)
}

// GeneratePullRequest generates a pull request with patches for multiple findings
func (e *Engine) GeneratePullRequest(findings []types.Finding, repoPath string) error {
	// This would integrate with Git to create actual pull requests
	// For now, we'll generate patch files

	patchDir := filepath.Join(repoPath, ".pqswitch", "patches")
	if err := os.MkdirAll(patchDir, 0750); err != nil {
		return err
	}

	for i, finding := range findings {
		request := PatchRequest{
			Finding:    finding,
			TargetFile: finding.File,
			Language:   e.detectLanguage(finding.File),
			PatchType:  "migration",
			Variables:  make(map[string]interface{}),
		}

		result := e.GeneratePatch(request)
		if result.Success {
			patchFile := filepath.Join(patchDir, fmt.Sprintf("patch_%d_%s.patch", i+1, strings.ToLower(finding.Algorithm)))
			if err := os.WriteFile(patchFile, []byte(result.PatchData), 0600); err != nil {
				return err
			}
		}
	}

	return nil
}

// detectLanguage detects programming language from file extension
func (e *Engine) detectLanguage(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))

	languageMap := map[string]string{
		".go":   "go",
		".java": "java",
		".js":   "javascript",
		".ts":   "typescript",
		".py":   "python",
		".c":    "c",
		".cpp":  "cpp",
		".cc":   "cpp",
		".cxx":  "cpp",
		".rs":   "rust",
		".kt":   "kotlin",
		".kts":  "kotlin",
	}

	return languageMap[ext]
}

// GetAvailableTemplates returns a list of available templates
func (e *Engine) GetAvailableTemplates() []string {
	var templates []string
	for name := range e.templates {
		templates = append(templates, name)
	}
	return templates
}

// ValidateTemplate validates a template
func (e *Engine) ValidateTemplate(templateName string) error {
	tmpl, exists := e.templates[templateName]
	if !exists {
		return fmt.Errorf("template %s not found", templateName)
	}

	// Try to execute with dummy data
	dummyData := map[string]interface{}{
		"Finding": types.Finding{
			Algorithm:  "RSA",
			CryptoType: "asymmetric",
			File:       "test.go",
			Line:       1,
			Column:     1,
		},
		"Language":          "go",
		"PQAlternative":     "ML-KEM",
		"MigrationStrategy": "test strategy",
	}

	var buf strings.Builder
	return tmpl.Execute(&buf, dummyData)
}

// CreateCustomTemplate creates a custom template
func (e *Engine) CreateCustomTemplate(name, content string) error {
	tmpl, err := template.New(name).Parse(content)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	e.templates[name] = tmpl
	return nil
}

// ExportTemplate exports a template to a file
func (e *Engine) ExportTemplate(templateName, outputPath string) error {
	_, exists := e.templates[templateName]
	if !exists {
		return fmt.Errorf("template %s not found", templateName)
	}

	// Get the template content (this is a simplified approach)
	// In a real implementation, you'd need to store the original template content
	content := fmt.Sprintf("# Template: %s\n# This is a generated template export\n", templateName)

	return os.WriteFile(outputPath, []byte(content), 0600)
}

// GetTemplateInfo returns information about a template
func (e *Engine) GetTemplateInfo(templateName string) (map[string]interface{}, error) {
	if _, exists := e.templates[templateName]; !exists {
		return nil, fmt.Errorf("template %s not found", templateName)
	}

	info := map[string]interface{}{
		"name":        templateName,
		"description": fmt.Sprintf("Template for %s", templateName),
		"variables":   []string{"Finding", "Language", "PQAlternative", "MigrationStrategy"},
	}

	return info, nil
}
