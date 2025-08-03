package scanner

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pqswitch/scanner/internal/ast"
	"github.com/pqswitch/scanner/internal/config"
	"github.com/pqswitch/scanner/internal/types"
)

// LayeredDetector implements a multi-stage crypto detection pipeline
type LayeredDetector struct {
	config     *config.Config
	rules      *RuleEngine
	ast        *ast.TreeSitter
	l0Filter   *RegexPreFilter
	l1AST      *StructuredAnalyzer
	l2DataFlow *DataFlowAnalyzer
	mlScorer   *MLConfidenceScorer
	benchmark  *DetectionBenchmark
}

// DetectionStage represents the analysis pipeline stages
type DetectionStage int

const (
	StageL0Regex    DetectionStage = iota // Fast regex pre-filter
	StageL1AST                            // Structured AST analysis
	StageL2DataFlow                       // Data flow & taint analysis
)

// LayeredResult contains results from all detection stages
type LayeredResult struct {
	Stage                 DetectionStage  `json:"stage"`
	Findings              []types.Finding `json:"findings"`
	ConfidenceScore       float64         `json:"confidence_score"`
	ProcessingTimeSeconds float64         `json:"processing_time_seconds"`
	Metadata              map[string]any  `json:"metadata"`
	Suppressions          []string        `json:"suppressions,omitempty"`
}

// FileContext provides rich context for multi-stage analysis
type FileContext struct {
	FilePath       string
	Content        []byte
	Language       string
	IsVendored     bool
	IsGenerated    bool
	IsTest         bool
	ProjectContext *ProjectContext
	Suppressions   []Suppression
	CryptoHotspots []CryptoHotspot
}

// ProjectContext provides project-wide analysis context
type ProjectContext struct {
	RootPath        string
	Language        string
	Dependencies    []Dependency
	CryptoLibraries []string
	SecurityLevel   string
}

// CryptoHotspot represents a potential crypto usage area
type CryptoHotspot struct {
	Location   types.Location
	Type       string // "key_generation", "signing", "encryption", etc.
	Confidence float64
	Variables  []Variable
	DataFlows  []DataFlow
}

// Variable tracks crypto-relevant variables through analysis
type Variable struct {
	Name          string
	Type          string
	Scope         string
	Location      types.Location
	CryptoContext map[string]any
}

// DataFlow represents data flow between crypto operations
type DataFlow struct {
	Source     types.Location
	Sink       types.Location
	TaintLevel string
	FlowType   string
	Confidence float64
}

// Suppression represents inline code suppressions
type Suppression struct {
	RuleID   string
	Location types.Location
	Reason   string
	Scope    string // "line", "block", "file"
}

// Dependency represents project dependencies for context
type Dependency struct {
	Name    string
	Version string
	Type    string // "crypto", "utility", "framework"
}

// NewLayeredDetector creates a new layered detection system
func NewLayeredDetector(cfg *config.Config) *LayeredDetector {
	return &LayeredDetector{
		config:     cfg,
		rules:      NewRuleEngine(cfg),
		ast:        ast.NewTreeSitter(),
		l0Filter:   NewRegexPreFilter(cfg),
		l1AST:      NewStructuredAnalyzer(cfg),
		l2DataFlow: NewDataFlowAnalyzer(cfg),
		mlScorer:   NewMLConfidenceScorer(cfg),
		benchmark:  NewDetectionBenchmark(),
	}
}

// LoadRules loads crypto detection rules into the layered detector
func (ld *LayeredDetector) LoadRules(rulesPath string) error {
	// Load rules into the rule engine - components get rules from the engine
	if err := ld.rules.LoadRules(rulesPath); err != nil {
		return err
	}

	// Load rules into the L0 regex prefilter
	if err := ld.l0Filter.LoadRules(rulesPath); err != nil {
		return fmt.Errorf("failed to load rules into L0 filter: %w", err)
	}

	return nil
}

// AnalyzeFile performs layered analysis on a single file
func (ld *LayeredDetector) AnalyzeFile(ctx context.Context, fileCtx *FileContext) (*LayeredResult, error) {
	startTime := time.Now()

	// Early filtering for non-relevant files
	if ld.shouldSkipFile(fileCtx) {
		return &LayeredResult{
			Stage:                 StageL0Regex,
			Findings:              []types.Finding{},
			ProcessingTimeSeconds: time.Since(startTime).Seconds(),
			Metadata:              map[string]any{"skipped": true, "reason": "non-relevant"},
		}, nil
	}

	var allFindings []types.Finding
	var stageResults []LayeredResult

	// L0: Regex Pre-filter (blazing fast)
	l0Result, err := ld.runL0Analysis(ctx, fileCtx)
	if err != nil {
		return nil, fmt.Errorf("L0 analysis failed: %w", err)
	}
	stageResults = append(stageResults, *l0Result)

	// Add L0 findings to allFindings - they are valid results
	allFindings = append(allFindings, l0Result.Findings...)

	// Only proceed to L1 if L0 found potential crypto
	if len(l0Result.Findings) > 0 {
		// L1: Structured AST Analysis
		l1Result, err := ld.runL1Analysis(ctx, fileCtx, l0Result.Findings)
		if err != nil {
			// L1 failure shouldn't block L0 results
			fmt.Printf("Warning: L1 analysis failed for %s: %v\n", fileCtx.FilePath, err)
		} else {
			stageResults = append(stageResults, *l1Result)
			allFindings = append(allFindings, l1Result.Findings...)
		}

		// L2: Data Flow Analysis (optional, for high-confidence L1 findings)
		if ld.config.Scanner.EnableDataFlow && ld.hasHighConfidenceFindings(l1Result.Findings) {
			l2Result, err := ld.runL2Analysis(ctx, fileCtx, l1Result.Findings)
			if err != nil {
				fmt.Printf("Warning: L2 analysis failed for %s: %v\n", fileCtx.FilePath, err)
			} else {
				stageResults = append(stageResults, *l2Result)
				allFindings = append(allFindings, l2Result.Findings...)
			}
		}
	}

	// Apply ML confidence scoring
	ld.mlScorer.AutoDetectLibraryAnalysisMode(fileCtx)
	scoredFindings := ld.mlScorer.ScoreFindings(allFindings, fileCtx)

	// Apply suppressions
	finalFindings := ld.applySuppressions(scoredFindings, fileCtx.Suppressions)

	// Record benchmark data
	ld.benchmark.RecordAnalysis(fileCtx.FilePath, stageResults, finalFindings)

	return &LayeredResult{
		Stage:                 ld.determineHighestStage(stageResults),
		Findings:              finalFindings,
		ConfidenceScore:       ld.calculateOverallConfidence(finalFindings),
		ProcessingTimeSeconds: time.Since(startTime).Seconds(),
		Metadata: map[string]any{
			"stages_completed": len(stageResults),
			"l0_hits":          len(l0Result.Findings),
			"file_size":        len(fileCtx.Content),
			"language":         fileCtx.Language,
		},
		Suppressions: ld.extractSuppressionIDs(fileCtx.Suppressions),
	}, nil
}

// runL0Analysis performs fast regex-based pre-filtering
func (ld *LayeredDetector) runL0Analysis(ctx context.Context, fileCtx *FileContext) (*LayeredResult, error) {
	startTime := time.Now()

	findings := ld.l0Filter.ScanContent(fileCtx.Content, fileCtx.FilePath, fileCtx.Language)

	return &LayeredResult{
		Stage:                 StageL0Regex,
		Findings:              findings,
		ProcessingTimeSeconds: time.Since(startTime).Seconds(),
		Metadata: map[string]any{
			"regex_patterns_matched": len(findings),
			"stage":                  "L0_regex_prefilter",
		},
	}, nil
}

// runL1Analysis performs structured AST-based analysis
func (ld *LayeredDetector) runL1Analysis(ctx context.Context, fileCtx *FileContext, l0Findings []types.Finding) (*LayeredResult, error) {
	startTime := time.Now()

	// Focus AST analysis on regions flagged by L0
	hotspots := ld.l1AST.IdentifyHotspots(fileCtx, l0Findings)
	findings := ld.l1AST.AnalyzeHotspots(fileCtx, hotspots)

	return &LayeredResult{
		Stage:                 StageL1AST,
		Findings:              findings,
		ProcessingTimeSeconds: time.Since(startTime).Seconds(),
		Metadata: map[string]any{
			"hotspots_analyzed":    len(hotspots),
			"ast_patterns_matched": len(findings),
			"stage":                "L1_structured_ast",
		},
	}, nil
}

// runL2Analysis performs data flow and taint analysis
func (ld *LayeredDetector) runL2Analysis(ctx context.Context, fileCtx *FileContext, l1Findings []types.Finding) (*LayeredResult, error) {
	startTime := time.Now()

	// Perform inter-procedural analysis on high-confidence findings
	dataFlows := ld.l2DataFlow.TraceDataFlows(fileCtx, l1Findings)
	findings := ld.l2DataFlow.AnalyzeFlows(dataFlows, fileCtx)

	return &LayeredResult{
		Stage:                 StageL2DataFlow,
		Findings:              findings,
		ProcessingTimeSeconds: time.Since(startTime).Seconds(),
		Metadata: map[string]any{
			"data_flows_traced": len(dataFlows),
			"taint_violations":  len(findings),
			"stage":             "L2_dataflow_taint",
		},
	}, nil
}

// shouldSkipFile determines if a file should be skipped entirely
func (ld *LayeredDetector) shouldSkipFile(fileCtx *FileContext) bool {
	// Check if this looks like a crypto library - if so, don't skip vendor code
	filePath := strings.ToLower(fileCtx.FilePath)

	// Known crypto library patterns
	cryptoLibraryPatterns := []string{
		"botan/", "/botan/", "openssl/", "/openssl/", "libsodium/", "/libsodium/",
		"cryptopp/", "/cryptopp/", "mbedtls/", "/mbedtls/",
		"src/lib/", "crypto/", "/crypto/", "crypt/", "/crypt/",
		"algorithm/", "cipher/", "hash/", "signature/", "pubkey/",
	}

	isLikelyCryptoLibrary := false
	for _, pattern := range cryptoLibraryPatterns {
		if strings.Contains(filePath, pattern) {
			isLikelyCryptoLibrary = true
			break
		}
	}

	// Only skip vendor/generated code if we're NOT analyzing a crypto library
	if !isLikelyCryptoLibrary && (fileCtx.IsVendored || fileCtx.IsGenerated) {
		return true
	}

	// Skip non-crypto-relevant file types
	if ld.isNonCryptoRelevant(fileCtx.FilePath) {
		return true
	}

	// Skip if file explicitly suppressed
	for _, suppression := range fileCtx.Suppressions {
		if suppression.Scope == "file" && suppression.RuleID == "*" {
			return true
		}
	}

	return false
}

// isNonCryptoRelevant checks if file is unlikely to contain crypto code
func (ld *LayeredDetector) isNonCryptoRelevant(filePath string) bool {
	irrelevantExtensions := []string{
		".md", ".txt", ".json", ".yaml", ".yml", ".xml", ".html", ".css",
		".png", ".jpg", ".gif", ".ico", ".svg", ".woff", ".ttf",
		".lock", ".log", ".tmp", ".cache",
	}

	for _, ext := range irrelevantExtensions {
		if strings.HasSuffix(strings.ToLower(filePath), ext) {
			return true
		}
	}

	// Skip common non-crypto directories
	irrelevantPaths := []string{
		"/docs/", "/documentation/", "/examples/", "/demo/",
		"/test/fixtures/", "/testdata/", "/.git/", "/node_modules/",
		"/vendor/", "/third_party/", "/external/",
	}

	for _, path := range irrelevantPaths {
		if strings.Contains(filePath, path) {
			return true
		}
	}

	return false
}

// hasHighConfidenceFindings checks if L1 findings warrant L2 analysis
func (ld *LayeredDetector) hasHighConfidenceFindings(findings []types.Finding) bool {
	highConfidenceCount := 0
	for _, finding := range findings {
		if finding.Severity == "critical" || finding.Severity == "high" {
			// Use the Confidence field from the Finding struct
			if finding.Confidence > 0.8 {
				highConfidenceCount++
			}
		}
	}
	return highConfidenceCount >= 2 // At least 2 high-confidence findings
}

// applySuppressions filters out suppressed findings
func (ld *LayeredDetector) applySuppressions(findings []types.Finding, suppressions []Suppression) []types.Finding {
	var filtered []types.Finding

	for _, finding := range findings {
		suppressed := false
		for _, suppression := range suppressions {
			if ld.matchesSuppression(finding, suppression) {
				suppressed = true
				break
			}
		}
		if !suppressed {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

// matchesSuppression checks if a finding matches a suppression rule
func (ld *LayeredDetector) matchesSuppression(finding types.Finding, suppression Suppression) bool {
	// Rule ID match (wildcard supported)
	if suppression.RuleID != "*" && suppression.RuleID != finding.RuleID {
		return false
	}

	// Location-based suppression
	switch suppression.Scope {
	case "line":
		return finding.Line == suppression.Location.Line
	case "block":
		return finding.Line >= suppression.Location.Line &&
			finding.Line <= suppression.Location.Line+10 // 10-line block
	case "file":
		return true // Already handled in shouldSkipFile
	}

	return false
}

// Helper functions
func (ld *LayeredDetector) determineHighestStage(results []LayeredResult) DetectionStage {
	highest := StageL0Regex
	for _, result := range results {
		if result.Stage > highest {
			highest = result.Stage
		}
	}
	return highest
}

func (ld *LayeredDetector) calculateOverallConfidence(findings []types.Finding) float64 {
	if len(findings) == 0 {
		return 0.0
	}

	totalConfidence := 0.0
	for _, finding := range findings {
		// Use the Confidence field directly from the Finding struct
		totalConfidence += finding.Confidence
	}

	return totalConfidence / float64(len(findings))
}

func (ld *LayeredDetector) extractSuppressionIDs(suppressions []Suppression) []string {
	var ids []string
	for _, s := range suppressions {
		ids = append(ids, s.RuleID)
	}
	return ids
}
