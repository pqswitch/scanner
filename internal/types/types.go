package types

import "time"

// Finding represents a detected cryptographic usage
type Finding struct {
	ID         string            `json:"id"`
	RuleID     string            `json:"rule_id"`
	File       string            `json:"file"`
	Line       int               `json:"line"`
	Column     int               `json:"column"`
	Message    string            `json:"message"`
	Severity   string            `json:"severity"`
	Confidence float64           `json:"confidence"`
	CryptoType string            `json:"crypto_type"`
	Algorithm  string            `json:"algorithm"`
	KeySize    int               `json:"key_size,omitempty"`
	Context    string            `json:"context"`
	Suggestion string            `json:"suggestion"`
	References []string          `json:"references,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Timestamp  time.Time         `json:"timestamp"`
}

// Location represents where a finding was detected
type Location struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Content string `json:"content"`
}

// ScanResult represents the complete scan results
type ScanResult struct {
	Summary  ScanSummary  `json:"summary"`
	Findings []Finding    `json:"findings"`
	Errors   []string     `json:"errors,omitempty"`
	Metadata ScanMetadata `json:"metadata"`
}

// ScanSummary provides high-level scan statistics
type ScanSummary struct {
	TotalFiles         int            `json:"total_files"`
	ScannedFiles       int            `json:"scanned_files"`
	TotalFindings      int            `json:"total_findings"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	FindingsByType     map[string]int `json:"findings_by_type"`
	RiskScore          float64        `json:"risk_score"`
	Duration           time.Duration  `json:"duration"`
}

// ScanMetadata holds scan execution metadata
type ScanMetadata struct {
	Version     string                 `json:"version"`
	ScanPath    string                 `json:"scan_path"`
	StartTime   time.Time              `json:"start_time"`
	EndTime     time.Time              `json:"end_time"`
	RulesLoaded int                    `json:"rules_loaded"`
	Config      map[string]interface{} `json:"config"`
}

// Report represents the output of a scan
type Report struct {
	Findings []Finding `json:"findings"`
}
