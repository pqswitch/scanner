package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pqswitch/scanner/internal/types"
)

// Vulnerability represents a security vulnerability in a dependency
type Vulnerability struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	CVSS        float64  `json:"cvss,omitempty"`
	CVE         []string `json:"cve,omitempty"`
	CWE         []string `json:"cwe,omitempty"`
	References  []string `json:"references,omitempty"`
	Package     string   `json:"package"`
	Version     string   `json:"version"`
	FixedIn     string   `json:"fixed_in,omitempty"`
}

// DependencyInfo represents information about a dependency
type DependencyInfo struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	License         string          `json:"license,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	IsDevDependency bool            `json:"is_dev_dependency"`
}

// DependencyScanResult contains the results of dependency scanning
type DependencyScanResult struct {
	PackageManager    string           `json:"package_manager"`
	TotalDependencies int              `json:"total_dependencies"`
	Dependencies      []DependencyInfo `json:"dependencies"`
	Vulnerabilities   []Vulnerability  `json:"vulnerabilities"`
	ScanTime          time.Time        `json:"scan_time"`
	ScanDuration      time.Duration    `json:"scan_duration"`
}

// DependencyScanner interface for different package managers
type DependencyScanner interface {
	Name() string
	CanScan(projectPath string) bool
	Scan(ctx context.Context, projectPath string) (*DependencyScanResult, error)
	RequiresExternal() bool // Whether this scanner needs external tools
}

// DependencyScannerManager manages multiple dependency scanners
type DependencyScannerManager struct {
	scanners []DependencyScanner
	config   *DependencyScanConfig
}

// DependencyScanConfig configuration for dependency scanning
type DependencyScanConfig struct {
	UseExternalTools bool   `json:"use_external_tools"`
	SnykToken        string `json:"snyk_token,omitempty"`
	TimeoutMinutes   int    `json:"timeout_minutes"`
	ScanDevDeps      bool   `json:"scan_dev_deps"`
}

// NewDependencyScannerManager creates a new dependency scanner manager
func NewDependencyScannerManager(config *DependencyScanConfig) *DependencyScannerManager {
	if config == nil {
		config = &DependencyScanConfig{
			UseExternalTools: false,
			TimeoutMinutes:   5,
			ScanDevDeps:      false,
		}
	}

	manager := &DependencyScannerManager{
		config: config,
	}

	// Register built-in scanners (no external tools required)
	manager.registerBuiltinScanners()

	// Register external tool scanners if enabled
	if config.UseExternalTools {
		manager.registerExternalScanners()
	}

	return manager
}

// registerBuiltinScanners registers scanners that don't require external tools
func (dsm *DependencyScannerManager) registerBuiltinScanners() {
	dsm.scanners = append(dsm.scanners,
		&NPMAuditScanner{},
		&GoVulnScanner{},
		&PipSafetyScanner{},
		&CargoAuditScanner{},
	)
}

// registerExternalScanners registers scanners that require external tools
func (dsm *DependencyScannerManager) registerExternalScanners() {
	if dsm.config.SnykToken != "" {
		dsm.scanners = append(dsm.scanners, &SnykScanner{token: dsm.config.SnykToken})
	}
}

// ScanProject scans a project for dependency vulnerabilities
func (dsm *DependencyScannerManager) ScanProject(ctx context.Context, projectPath string) ([]*DependencyScanResult, error) {
	results := make([]*DependencyScanResult, 0)

	for _, scanner := range dsm.scanners {
		if scanner.CanScan(projectPath) {
			// Skip external scanners if not enabled
			if scanner.RequiresExternal() && !dsm.config.UseExternalTools {
				continue
			}

			// Set timeout
			scanCtx, cancel := context.WithTimeout(ctx, time.Duration(dsm.config.TimeoutMinutes)*time.Minute)
			defer cancel()

			result, err := scanner.Scan(scanCtx, projectPath)
			if err != nil {
				// Log error but continue with other scanners
				fmt.Printf("Warning: %s scan failed: %v\n", scanner.Name(), err)
				continue
			}

			if result != nil {
				results = append(results, result)
			}
		}
	}

	return results, nil
}

// NPMAuditScanner scans Node.js projects using npm audit
type NPMAuditScanner struct{}

func (s *NPMAuditScanner) Name() string { return "npm-audit" }

func (s *NPMAuditScanner) RequiresExternal() bool { return false }

func (s *NPMAuditScanner) CanScan(projectPath string) bool {
	packageJSON := filepath.Join(projectPath, "package.json")
	_, err := os.Stat(packageJSON)
	return err == nil
}

func (s *NPMAuditScanner) Scan(ctx context.Context, projectPath string) (*DependencyScanResult, error) {
	start := time.Now()

	// Check if npm is available
	if _, err := exec.LookPath("npm"); err != nil {
		return nil, fmt.Errorf("npm not found: %w", err)
	}

	cmd := exec.CommandContext(ctx, "npm", "audit", "--json", "--audit-level=low")
	cmd.Dir = projectPath

	output, err := cmd.Output()
	if err != nil {
		// npm audit returns non-zero exit code when vulnerabilities found
		if exitErr, ok := err.(*exec.ExitError); ok {
			output = exitErr.Stderr
			if len(output) == 0 {
				// Try to get stdout if stderr is empty
				output, _ = cmd.Output()
			}
		} else {
			return nil, fmt.Errorf("npm audit failed: %w", err)
		}
	}

	// Parse npm audit output
	var auditResult struct {
		Vulnerabilities map[string]struct {
			Severity string        `json:"severity"`
			Title    string        `json:"title"`
			CVE      []string      `json:"cves"`
			Via      []interface{} `json:"via"`
		} `json:"vulnerabilities"`
		Metadata struct {
			Vulnerabilities struct {
				Total int `json:"total"`
			} `json:"vulnerabilities"`
		} `json:"metadata"`
	}

	if err := json.Unmarshal(output, &auditResult); err != nil {
		return nil, fmt.Errorf("failed to parse npm audit output: %w", err)
	}

	result := &DependencyScanResult{
		PackageManager:  "npm",
		ScanTime:        start,
		ScanDuration:    time.Since(start),
		Vulnerabilities: make([]Vulnerability, 0),
	}

	// Convert npm audit format to our format
	for pkg, vuln := range auditResult.Vulnerabilities {
		vulnerability := Vulnerability{
			ID:       fmt.Sprintf("npm-%s", pkg),
			Title:    vuln.Title,
			Severity: vuln.Severity,
			CVE:      vuln.CVE,
			Package:  pkg,
		}
		result.Vulnerabilities = append(result.Vulnerabilities, vulnerability)
	}

	return result, nil
}

// GoVulnScanner scans Go projects using govulncheck
type GoVulnScanner struct{}

func (s *GoVulnScanner) Name() string { return "govulncheck" }

func (s *GoVulnScanner) RequiresExternal() bool { return false }

func (s *GoVulnScanner) CanScan(projectPath string) bool {
	goMod := filepath.Join(projectPath, "go.mod")
	_, err := os.Stat(goMod)
	return err == nil
}

func (s *GoVulnScanner) Scan(ctx context.Context, projectPath string) (*DependencyScanResult, error) {
	start := time.Now()

	// Check if govulncheck is available
	if _, err := exec.LookPath("govulncheck"); err != nil {
		return nil, fmt.Errorf("govulncheck not found: %w", err)
	}

	cmd := exec.CommandContext(ctx, "govulncheck", "-json", "./...")
	cmd.Dir = projectPath

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("govulncheck failed: %w", err)
	}

	// Parse govulncheck output (simplified)
	lines := strings.Split(string(output), "\n")
	result := &DependencyScanResult{
		PackageManager:  "go",
		ScanTime:        start,
		ScanDuration:    time.Since(start),
		Vulnerabilities: make([]Vulnerability, 0),
	}

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var entry struct {
			Type string `json:"type"`
			Vuln struct {
				ID      string `json:"id"`
				Details string `json:"details"`
			} `json:"vuln,omitempty"`
		}

		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		if entry.Type == "vuln" {
			vulnerability := Vulnerability{
				ID:          entry.Vuln.ID,
				Description: entry.Vuln.Details,
				Severity:    "unknown", // govulncheck doesn't provide severity
			}
			result.Vulnerabilities = append(result.Vulnerabilities, vulnerability)
		}
	}

	return result, nil
}

// PipSafetyScanner scans Python projects using safety
type PipSafetyScanner struct{}

func (s *PipSafetyScanner) Name() string { return "pip-safety" }

func (s *PipSafetyScanner) RequiresExternal() bool { return false }

func (s *PipSafetyScanner) CanScan(projectPath string) bool {
	files := []string{"requirements.txt", "setup.py", "pyproject.toml", "Pipfile"}
	for _, file := range files {
		if _, err := os.Stat(filepath.Join(projectPath, file)); err == nil {
			return true
		}
	}
	return false
}

func (s *PipSafetyScanner) Scan(ctx context.Context, projectPath string) (*DependencyScanResult, error) {
	start := time.Now()

	// This would require safety to be installed
	// For now, return a placeholder implementation
	result := &DependencyScanResult{
		PackageManager:  "pip",
		ScanTime:        start,
		ScanDuration:    time.Since(start),
		Vulnerabilities: make([]Vulnerability, 0),
	}

	return result, nil
}

// CargoAuditScanner scans Rust projects using cargo audit
type CargoAuditScanner struct{}

func (s *CargoAuditScanner) Name() string { return "cargo-audit" }

func (s *CargoAuditScanner) RequiresExternal() bool { return false }

func (s *CargoAuditScanner) CanScan(projectPath string) bool {
	cargoToml := filepath.Join(projectPath, "Cargo.toml")
	_, err := os.Stat(cargoToml)
	return err == nil
}

func (s *CargoAuditScanner) Scan(ctx context.Context, projectPath string) (*DependencyScanResult, error) {
	start := time.Now()

	// This would require cargo-audit to be installed
	// For now, return a placeholder implementation
	result := &DependencyScanResult{
		PackageManager:  "cargo",
		ScanTime:        start,
		ScanDuration:    time.Since(start),
		Vulnerabilities: make([]Vulnerability, 0),
	}

	return result, nil
}

// SnykScanner scans using Snyk API (external tool)
type SnykScanner struct {
	token string
}

func (s *SnykScanner) Name() string { return "snyk" }

func (s *SnykScanner) RequiresExternal() bool { return true }

func (s *SnykScanner) CanScan(projectPath string) bool {
	// Snyk can scan most project types
	return true
}

func (s *SnykScanner) Scan(ctx context.Context, projectPath string) (*DependencyScanResult, error) {
	start := time.Now()

	// Check if snyk CLI is available
	if _, err := exec.LookPath("snyk"); err != nil {
		return nil, fmt.Errorf("snyk CLI not found: %w", err)
	}

	cmd := exec.CommandContext(ctx, "snyk", "test", "--json")
	cmd.Dir = projectPath
	cmd.Env = append(os.Environ(), fmt.Sprintf("SNYK_TOKEN=%s", s.token))

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("snyk test failed: %w", err)
	}

	// Parse Snyk output (simplified)
	result := &DependencyScanResult{
		PackageManager:  "snyk",
		ScanTime:        start,
		ScanDuration:    time.Since(start),
		Vulnerabilities: make([]Vulnerability, 0),
	}

	// TODO: Implement full Snyk JSON parsing
	_ = output

	return result, nil
}

// Enhanced scanning command that integrates both crypto and dependency scanning
func (d *Detector) EnhancedScan(scanConfig *Config) (*EnhancedScanResult, error) {
	start := time.Now()

	// Step 1: Detect project structure
	sourceDetector := NewSourceDetector(scanConfig.Path)
	projectInfo, err := sourceDetector.DetectProject()
	if err != nil {
		return nil, fmt.Errorf("failed to detect project structure: %w", err)
	}

	// Step 2: Enhanced crypto scanning with intelligent exclusions
	enhancedConfig := *scanConfig
	enhancedConfig.Path = scanConfig.Path

	// Override ignore patterns with detected ones
	// This would require modifying the scanning logic to use enhanced ignore patterns
	// For now, we'll use the default patterns and let the source detector handle exclusions

	// Step 3: Crypto scanning
	cryptoFindings, cryptoErrors := d.ScanFiles([]string{scanConfig.Path}, scanConfig.Verbose)

	// Step 4: Dependency scanning (if enabled)
	var dependencyResults []*DependencyScanResult
	depConfig := &DependencyScanConfig{
		UseExternalTools: false, // Default to built-in only
		TimeoutMinutes:   3,
		ScanDevDeps:      false,
	}

	depManager := NewDependencyScannerManager(depConfig)
	ctx := context.Background()
	dependencyResults, err = depManager.ScanProject(ctx, scanConfig.Path)
	if err != nil {
		fmt.Printf("Warning: Dependency scanning failed: %v\n", err)
	}

	// Step 5: Combine results
	result := &EnhancedScanResult{
		ProjectInfo:       projectInfo,
		CryptoFindings:    cryptoFindings,
		CryptoErrors:      cryptoErrors,
		DependencyResults: dependencyResults,
		ScanTime:          start,
		Duration:          time.Since(start),
	}

	return result, nil
}

// EnhancedScanResult contains results from both crypto and dependency scanning
type EnhancedScanResult struct {
	ProjectInfo       *ProjectInfo            `json:"project_info"`
	CryptoFindings    []types.Finding         `json:"crypto_findings"`
	CryptoErrors      []string                `json:"crypto_errors,omitempty"`
	DependencyResults []*DependencyScanResult `json:"dependency_results,omitempty"`
	ScanTime          time.Time               `json:"scan_time"`
	Duration          time.Duration           `json:"duration"`
}

// GetVulnerabilitySummary returns a summary of all vulnerabilities found
func (esr *EnhancedScanResult) GetVulnerabilitySummary() map[string]int {
	summary := map[string]int{
		"crypto_critical": 0,
		"crypto_high":     0,
		"crypto_medium":   0,
		"crypto_low":      0,
		"dep_critical":    0,
		"dep_high":        0,
		"dep_medium":      0,
		"dep_low":         0,
	}

	// Count crypto findings
	for _, finding := range esr.CryptoFindings {
		switch strings.ToLower(finding.Severity) {
		case "critical":
			summary["crypto_critical"]++
		case "high":
			summary["crypto_high"]++
		case "medium":
			summary["crypto_medium"]++
		case "low":
			summary["crypto_low"]++
		}
	}

	// Count dependency vulnerabilities
	for _, result := range esr.DependencyResults {
		for _, vuln := range result.Vulnerabilities {
			switch strings.ToLower(vuln.Severity) {
			case "critical":
				summary["dep_critical"]++
			case "high":
				summary["dep_high"]++
			case "medium":
				summary["dep_medium"]++
			case "low":
				summary["dep_low"]++
			}
		}
	}

	return summary
}
