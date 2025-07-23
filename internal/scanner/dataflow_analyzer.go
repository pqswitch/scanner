package scanner

import (
	"fmt"
	"strings"
	"time"

	"github.com/pqswitch/scanner/internal/config"
	"github.com/pqswitch/scanner/internal/types"
)

// DataFlowAnalyzer implements L2 stage - data flow and taint analysis
type DataFlowAnalyzer struct {
	config       *config.Config
	taintSources map[string]TaintSource
	taintSinks   map[string]TaintSink
	flowRules    []FlowRule
	sanitizers   map[string]Sanitizer
}

// TaintSource represents a source of potentially unsafe data
type TaintSource struct {
	ID          string
	Pattern     string
	TaintLevel  string // "high", "medium", "low"
	Description string
	Languages   []string
}

// TaintSink represents a sensitive operation that should not receive tainted data
type TaintSink struct {
	ID          string
	Pattern     string
	Severity    string
	Description string
	Languages   []string
}

// FlowRule defines data flow security rules
type FlowRule struct {
	ID          string
	SourceType  string
	SinkType    string
	Severity    string
	Message     string
	Description string
}

// Sanitizer represents data sanitization operations
type Sanitizer struct {
	ID            string
	Pattern       string
	Effectiveness float64 // 0.0 to 1.0
	Description   string
}

// NewDataFlowAnalyzer creates a new L2 data flow analyzer
func NewDataFlowAnalyzer(cfg *config.Config) *DataFlowAnalyzer {
	analyzer := &DataFlowAnalyzer{
		config:       cfg,
		taintSources: make(map[string]TaintSource),
		taintSinks:   make(map[string]TaintSink),
		flowRules:    []FlowRule{},
		sanitizers:   make(map[string]Sanitizer),
	}

	analyzer.initializeFlowRules()
	return analyzer
}

// initializeFlowRules sets up data flow and taint analysis rules
func (da *DataFlowAnalyzer) initializeFlowRules() {
	// Define taint sources (where unsafe data originates)
	sources := []TaintSource{
		{
			ID:          "user-input",
			Pattern:     `(?:request\.|input\.|argv\[|stdin\.|os\.Args|user_input|form\.|query\.)`,
			TaintLevel:  "high",
			Description: "User-controlled input data",
			Languages:   []string{"*"},
		},
		{
			ID:          "network-data",
			Pattern:     `(?:http\.|fetch\(|xhr\.|socket\.|conn\.Read|recv\(|readFromNetwork)`,
			TaintLevel:  "high",
			Description: "Data received from network",
			Languages:   []string{"*"},
		},
		{
			ID:          "file-data",
			Pattern:     `(?:readFile|Read\(|fread\(|open\(|file\.read|io\.read)`,
			TaintLevel:  "medium",
			Description: "Data read from files",
			Languages:   []string{"*"},
		},
		{
			ID:          "environment-data",
			Pattern:     `(?:os\.Getenv|getenv\(|process\.env|ENV\[|environment\.)`,
			TaintLevel:  "medium",
			Description: "Environment variable data",
			Languages:   []string{"*"},
		},
	}

	// Define taint sinks (sensitive crypto operations)
	sinks := []TaintSink{
		{
			ID:          "crypto-key-material",
			Pattern:     `(?:GenerateKey|PrivateKey|SecretKey|keyMaterial|cryptoKey)`,
			Severity:    "critical",
			Description: "Cryptographic key material creation",
			Languages:   []string{"*"},
		},
		{
			ID:          "crypto-seed",
			Pattern:     `(?:seed|entropy|random\.seed|srand\(|SecureRandom)`,
			Severity:    "critical",
			Description: "Cryptographic randomness seeding",
			Languages:   []string{"*"},
		},
		{
			ID:          "hash-input",
			Pattern:     `(?:\.hash\(|\.update\(|Hash\.write|hashlib\.)`,
			Severity:    "high",
			Description: "Hash function input",
			Languages:   []string{"*"},
		},
		{
			ID:          "encryption-input",
			Pattern:     `(?:encrypt\(|cipher\.|AES\.|encrypt|seal\()`,
			Severity:    "high",
			Description: "Encryption operation input",
			Languages:   []string{"*"},
		},
	}

	// Define flow rules (what flows are problematic)
	rules := []FlowRule{
		{
			ID:          "user-input-to-crypto-key",
			SourceType:  "user-input",
			SinkType:    "crypto-key-material",
			Severity:    "critical",
			Message:     "User-controlled input flows directly to crypto key generation",
			Description: "Direct user input to cryptographic key material is extremely dangerous",
		},
		{
			ID:          "network-data-to-crypto-seed",
			SourceType:  "network-data",
			SinkType:    "crypto-seed",
			Severity:    "critical",
			Message:     "Network data flows to cryptographic randomness seed",
			Description: "Using network data as entropy source compromises randomness",
		},
		{
			ID:          "user-input-to-hash",
			SourceType:  "user-input",
			SinkType:    "hash-input",
			Severity:    "medium",
			Message:     "User input flows directly to hash function",
			Description: "Direct user input to hash functions may enable hash collision attacks",
		},
		{
			ID:          "file-data-to-crypto-key",
			SourceType:  "file-data",
			SinkType:    "crypto-key-material",
			Severity:    "high",
			Message:     "File data flows to crypto key generation without validation",
			Description: "File content used for key generation should be validated",
		},
	}

	// Define sanitizers (operations that clean tainted data)
	sanitizers := []Sanitizer{
		{
			ID:            "crypto-hash",
			Pattern:       `(?:sha256|sha3|blake2|pbkdf2|scrypt|argon2)`,
			Effectiveness: 0.9,
			Description:   "Cryptographic hash function sanitization",
		},
		{
			ID:            "input-validation",
			Pattern:       `(?:validate|sanitize|filter|escape|clean)`,
			Effectiveness: 0.7,
			Description:   "Input validation and sanitization",
		},
		{
			ID:            "length-check",
			Pattern:       `(?:len\(|length|size.*check|bounds.*check)`,
			Effectiveness: 0.5,
			Description:   "Length and bounds checking",
		},
	}

	// Store all rules
	for _, source := range sources {
		da.taintSources[source.ID] = source
	}
	for _, sink := range sinks {
		da.taintSinks[sink.ID] = sink
	}
	da.flowRules = rules
	for _, sanitizer := range sanitizers {
		da.sanitizers[sanitizer.ID] = sanitizer
	}
}

// TraceDataFlows traces data flows from L1 findings
func (da *DataFlowAnalyzer) TraceDataFlows(fileCtx *FileContext, l1Findings []types.Finding) []DataFlow {
	var dataFlows []DataFlow

	content := string(fileCtx.Content)

	// Identify potential sources and sinks in the file
	sources := da.identifyTaintSources(content, fileCtx.Language)
	sinks := da.identifyCryptoSinks(content, l1Findings)

	// Trace flows between sources and sinks
	for _, source := range sources {
		for _, sink := range sinks {
			if da.hasDataFlow(content, source, sink) {
				flow := DataFlow{
					Source:     source.Location,
					Sink:       sink.Location,
					TaintLevel: source.TaintLevel,
					FlowType:   da.determineFlowType(source, sink),
					Confidence: da.calculateFlowConfidence(content, source, sink),
				}
				dataFlows = append(dataFlows, flow)
			}
		}
	}

	return dataFlows
}

// AnalyzeFlows analyzes data flows for security violations
func (da *DataFlowAnalyzer) AnalyzeFlows(dataFlows []DataFlow, fileCtx *FileContext) []types.Finding {
	var findings []types.Finding

	for _, flow := range dataFlows {
		// Check if this flow violates any security rules
		for _, rule := range da.flowRules {
			if da.flowMatchesRule(flow, rule) {
				finding := da.createFlowViolationFinding(flow, rule, fileCtx)
				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// identifyTaintSources finds potential taint sources in content
func (da *DataFlowAnalyzer) identifyTaintSources(content, language string) []TaintSourceInstance {
	var sources []TaintSourceInstance

	lines := strings.Split(content, "\n")

	for lineNum, line := range lines {
		for _, source := range da.taintSources {
			if da.languageMatches(source.Languages, language) {
				if strings.Contains(line, extractPatternKeyword(source.Pattern)) {
					instance := TaintSourceInstance{
						Source: source,
						Location: types.Location{
							Line:    lineNum + 1,
							Column:  strings.Index(line, extractPatternKeyword(source.Pattern)),
							Content: line,
						},
						TaintLevel: source.TaintLevel,
					}
					sources = append(sources, instance)
				}
			}
		}
	}

	return sources
}

// identifyCryptoSinks finds crypto-related sinks from L1 findings
func (da *DataFlowAnalyzer) identifyCryptoSinks(content string, l1Findings []types.Finding) []CryptoSinkInstance {
	var sinks []CryptoSinkInstance

	for _, finding := range l1Findings {
		// Convert L1 findings to crypto sinks for flow analysis
		sink := CryptoSinkInstance{
			Finding: finding,
			Location: types.Location{
				Line:    finding.Line,
				Column:  finding.Column,
				Content: finding.Context,
			},
			SinkType: da.determineSinkType(finding),
		}
		sinks = append(sinks, sink)
	}

	return sinks
}

// hasDataFlow determines if there's a data flow between source and sink
func (da *DataFlowAnalyzer) hasDataFlow(content string, source TaintSourceInstance, sink CryptoSinkInstance) bool {
	// Simplified data flow analysis
	// In practice, this would use sophisticated control and data flow analysis

	// Basic heuristic: if source and sink are in the same function or within close proximity
	lineDistance := absInt(source.Location.Line - sink.Location.Line)

	// If they're within 50 lines, consider potential flow
	if lineDistance <= 50 {
		return true
	}

	// Look for variable names that might connect them
	sourceVars := extractVariableNames(source.Location.Content)
	sinkVars := extractVariableNames(sink.Location.Content)

	for _, srcVar := range sourceVars {
		for _, sinkVar := range sinkVars {
			if srcVar == sinkVar && len(srcVar) > 2 {
				return true
			}
		}
	}

	return false
}

// createFlowViolationFinding creates a finding for flow rule violation
func (da *DataFlowAnalyzer) createFlowViolationFinding(flow DataFlow, rule FlowRule, fileCtx *FileContext) types.Finding {
	return types.Finding{
		ID:         generateFindingID(),
		RuleID:     rule.ID,
		File:       fileCtx.FilePath,
		Line:       flow.Sink.Line,
		Column:     flow.Sink.Column,
		Message:    rule.Message,
		Severity:   rule.Severity,
		CryptoType: "data_flow",
		Algorithm:  "TAINT_ANALYSIS",
		Context:    fmt.Sprintf("Flow: %s -> %s", flow.Source.Content, flow.Sink.Content),
		Metadata: map[string]string{
			"stage":         "L2",
			"flow_type":     flow.FlowType,
			"taint_level":   flow.TaintLevel,
			"confidence":    fmt.Sprintf("%.2f", flow.Confidence),
			"source_line":   fmt.Sprintf("%d", flow.Source.Line),
			"sink_line":     fmt.Sprintf("%d", flow.Sink.Line),
			"rule_id":       rule.ID,
			"analysis_type": "dataflow_taint",
		},
		Timestamp: time.Now(),
	}
}

// Helper types and functions

type TaintSourceInstance struct {
	Source     TaintSource
	Location   types.Location
	TaintLevel string
}

type CryptoSinkInstance struct {
	Finding  types.Finding
	Location types.Location
	SinkType string
}

func (da *DataFlowAnalyzer) languageMatches(languages []string, fileLanguage string) bool {
	for _, lang := range languages {
		if lang == "*" || strings.EqualFold(lang, fileLanguage) {
			return true
		}
	}
	return false
}

func (da *DataFlowAnalyzer) determineFlowType(source TaintSourceInstance, sink CryptoSinkInstance) string {
	return fmt.Sprintf("%s_to_%s", source.Source.ID, sink.SinkType)
}

func (da *DataFlowAnalyzer) calculateFlowConfidence(content string, source TaintSourceInstance, sink CryptoSinkInstance) float64 {
	// Base confidence for L2 analysis
	confidence := 0.6

	// Increase confidence based on proximity
	lineDistance := absInt(source.Location.Line - sink.Location.Line)
	if lineDistance <= 10 {
		confidence += 0.3
	} else if lineDistance <= 25 {
		confidence += 0.2
	}

	// Increase confidence if variables are shared
	sourceVars := extractVariableNames(source.Location.Content)
	sinkVars := extractVariableNames(sink.Location.Content)
	if hasCommonVariable(sourceVars, sinkVars) {
		confidence += 0.2
	}

	return minFloat(confidence, 1.0)
}

func (da *DataFlowAnalyzer) flowMatchesRule(flow DataFlow, rule FlowRule) bool {
	// Simple matching based on flow type
	return strings.Contains(flow.FlowType, rule.SourceType) && strings.Contains(flow.FlowType, rule.SinkType)
}

func (da *DataFlowAnalyzer) determineSinkType(finding types.Finding) string {
	// Map finding types to sink types
	switch finding.CryptoType {
	case "key_generation":
		return "crypto-key-material"
	case "hash_usage":
		return "hash-input"
	case "encryption":
		return "encryption-input"
	default:
		return "crypto-operation"
	}
}

// Utility functions
func extractPatternKeyword(pattern string) string {
	// Extract a simple keyword from regex pattern for basic matching
	// This is simplified - in practice would be more sophisticated
	cleaned := strings.ReplaceAll(pattern, `(?:`, "")
	cleaned = strings.ReplaceAll(cleaned, `\.|`, "")
	cleaned = strings.ReplaceAll(cleaned, `\\`, "")
	parts := strings.Split(cleaned, "|")
	if len(parts) > 0 {
		return strings.Trim(parts[0], "()")
	}
	return ""
}

func extractVariableNames(content string) []string {
	// Simple variable extraction - would be more sophisticated in practice
	var vars []string
	words := strings.Fields(content)
	for _, word := range words {
		if len(word) > 2 && !strings.ContainsAny(word, "(){}[]<>") {
			vars = append(vars, word)
		}
	}
	return vars
}

func hasCommonVariable(vars1, vars2 []string) bool {
	for _, v1 := range vars1 {
		for _, v2 := range vars2 {
			if v1 == v2 {
				return true
			}
		}
	}
	return false
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
