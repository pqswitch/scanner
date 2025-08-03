package scanner

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pqswitch/scanner/internal/types"
)

// DetectionBenchmark tracks performance and accuracy metrics
type DetectionBenchmark struct {
	metrics       map[string]*PerformanceMetric
	accuracyStats map[string]*AccuracyStats
	mu            sync.RWMutex
	startTime     time.Time
}

// PerformanceMetric tracks timing and resource usage
type PerformanceMetric struct {
	TotalCalls        int64
	TotalDurationSecs float64
	MinDurationSecs   float64
	MaxDurationSecs   float64
	AvgDurationSecs   float64
	FilesProcessed    int64
	BytesProcessed    int64
	ErrorCount        int64
	StageMetrics      map[DetectionStage]*StageMetric
}

// StageMetric tracks metrics for each detection stage
type StageMetric struct {
	CallCount       int64
	DurationSeconds float64
	FindingsCount   int64
	SuccessRate     float64
}

// AccuracyStats tracks detection accuracy over time
type AccuracyStats struct {
	TruePositives  int64
	FalsePositives int64
	TrueNegatives  int64
	FalseNegatives int64
	Precision      float64
	Recall         float64
	F1Score        float64
	Confidence     float64
}

// BenchmarkReport provides comprehensive performance analysis
type BenchmarkReport struct {
	OverallMetrics  *PerformanceMetric        `json:"overall_metrics"`
	StageBreakdown  map[string]*StageMetric   `json:"stage_breakdown"`
	AccuracyMetrics map[string]*AccuracyStats `json:"accuracy_metrics"`
	Recommendations []string                  `json:"recommendations"`
	GeneratedAt     time.Time                 `json:"generated_at"`
	DurationSeconds float64                   `json:"total_duration_seconds"`
}

// NewDetectionBenchmark creates a new benchmarking system
func NewDetectionBenchmark() *DetectionBenchmark {
	return &DetectionBenchmark{
		metrics:       make(map[string]*PerformanceMetric),
		accuracyStats: make(map[string]*AccuracyStats),
		startTime:     time.Now(),
	}
}

// RecordAnalysis records analysis performance and results
func (db *DetectionBenchmark) RecordAnalysis(filePath string, stageResults []LayeredResult, finalFindings []types.Finding) {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Record overall metrics
	overallKey := "overall"
	if db.metrics[overallKey] == nil {
		db.metrics[overallKey] = &PerformanceMetric{
			StageMetrics: make(map[DetectionStage]*StageMetric),
		}
	}

	metric := db.metrics[overallKey]
	metric.TotalCalls++
	metric.FilesProcessed++

	// Calculate total processing time
	totalDuration := float64(0)
	for _, result := range stageResults {
		totalDuration += result.ProcessingTimeSeconds
		db.recordStageMetric(metric, result)
	}

	// Update duration statistics
	metric.TotalDurationSecs += totalDuration
	if metric.MinDurationSecs == 0 || totalDuration < metric.MinDurationSecs {
		metric.MinDurationSecs = totalDuration
	}
	if totalDuration > metric.MaxDurationSecs {
		metric.MaxDurationSecs = totalDuration
	}
	metric.AvgDurationSecs = metric.TotalDurationSecs / float64(metric.TotalCalls)

	// Record file-specific metrics
	fileKey := db.categorizeFile(filePath)
	if db.metrics[fileKey] == nil {
		db.metrics[fileKey] = &PerformanceMetric{
			StageMetrics: make(map[DetectionStage]*StageMetric),
		}
	}
	db.updateFileMetrics(db.metrics[fileKey], stageResults, finalFindings)

	// Update accuracy statistics
	db.updateAccuracyStats(finalFindings, filePath)
}

// recordStageMetric records metrics for individual stages
func (db *DetectionBenchmark) recordStageMetric(metric *PerformanceMetric, result LayeredResult) {
	stage := result.Stage
	if metric.StageMetrics[stage] == nil {
		metric.StageMetrics[stage] = &StageMetric{}
	}

	stageMet := metric.StageMetrics[stage]
	stageMet.CallCount++
	stageMet.DurationSeconds += result.ProcessingTimeSeconds
	stageMet.FindingsCount += int64(len(result.Findings))

	// Calculate success rate (findings found / attempts)
	if stageMet.CallCount > 0 {
		stageMet.SuccessRate = float64(stageMet.FindingsCount) / float64(stageMet.CallCount)
	}
}

// updateFileMetrics updates metrics for specific file types
func (db *DetectionBenchmark) updateFileMetrics(metric *PerformanceMetric, results []LayeredResult, findings []types.Finding) {
	metric.TotalCalls++

	totalDuration := float64(0)
	for _, result := range results {
		totalDuration += result.ProcessingTimeSeconds
	}

	metric.TotalDurationSecs += totalDuration
	metric.AvgDurationSecs = metric.TotalDurationSecs / float64(metric.TotalCalls)
}

// updateAccuracyStats updates accuracy statistics
func (db *DetectionBenchmark) updateAccuracyStats(findings []types.Finding, filePath string) {
	// Categorize findings for accuracy tracking
	category := db.categorizeFile(filePath)

	if db.accuracyStats[category] == nil {
		db.accuracyStats[category] = &AccuracyStats{}
	}

	stats := db.accuracyStats[category]

	// Analyze findings for accuracy metrics
	for _, finding := range findings {
		confidence := finding.Confidence

		// Simple heuristics for TP/FP classification
		// In practice, this would use ground truth data
		if db.isLikelyTruePositive(finding, filePath) {
			stats.TruePositives++
		} else {
			stats.FalsePositives++
		}

		// Update confidence running average
		totalSamples := stats.TruePositives + stats.FalsePositives
		stats.Confidence = (stats.Confidence*float64(totalSamples-1) + confidence) / float64(totalSamples)
	}

	// Calculate precision, recall, F1
	db.calculateAccuracyMetrics(stats)
}

// isLikelyTruePositive uses heuristics to classify findings
func (db *DetectionBenchmark) isLikelyTruePositive(finding types.Finding, filePath string) bool {
	// High confidence findings are likely true positives
	if finding.Confidence >= 0.8 {
		return true
	}

	// Known vulnerable patterns are likely true positives
	vulnerablePatterns := []string{"MD5", "SHA1", "RSA-1024", "RSA-512"}
	for _, pattern := range vulnerablePatterns {
		if finding.Algorithm == pattern {
			return true
		}
	}

	// L2 (dataflow) findings are likely true positives
	if stage, ok := finding.Metadata["stage"]; ok && stage == "L2" {
		return true
	}

	// Test files are more likely false positives
	if isTestFile(filePath) {
		return finding.Confidence >= 0.9 // Higher threshold for test files
	}

	// Vendor files are more likely false positives
	if isVendorFile(filePath) {
		return finding.Confidence >= 0.95 // Very high threshold for vendor files
	}

	return finding.Confidence >= 0.7
}

// calculateAccuracyMetrics computes precision, recall, and F1 score
func (db *DetectionBenchmark) calculateAccuracyMetrics(stats *AccuracyStats) {
	tp := float64(stats.TruePositives)
	fp := float64(stats.FalsePositives)
	fn := float64(stats.FalseNegatives)

	// Precision = TP / (TP + FP)
	if tp+fp > 0 {
		stats.Precision = tp / (tp + fp)
	}

	// Recall = TP / (TP + FN)
	if tp+fn > 0 {
		stats.Recall = tp / (tp + fn)
	}

	// F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
	if stats.Precision+stats.Recall > 0 {
		stats.F1Score = 2 * (stats.Precision * stats.Recall) / (stats.Precision + stats.Recall)
	}
}

// GenerateReport creates a comprehensive benchmark report
func (db *DetectionBenchmark) GenerateReport() *BenchmarkReport {
	db.mu.RLock()
	defer db.mu.RUnlock()

	report := &BenchmarkReport{
		OverallMetrics:  db.metrics["overall"],
		StageBreakdown:  make(map[string]*StageMetric),
		AccuracyMetrics: db.accuracyStats,
		GeneratedAt:     time.Now(),
		DurationSeconds: time.Since(db.startTime).Seconds(),
	}

	// Extract stage breakdown from overall metrics
	if overall := db.metrics["overall"]; overall != nil {
		for stage, metric := range overall.StageMetrics {
			stageName := db.stageToString(stage)
			report.StageBreakdown[stageName] = metric
		}
	}

	// Generate recommendations
	report.Recommendations = db.generateRecommendations()

	return report
}

// generateRecommendations provides performance improvement suggestions
func (db *DetectionBenchmark) generateRecommendations() []string {
	var recommendations []string

	overall := db.metrics["overall"]
	if overall == nil {
		return recommendations
	}

	// Performance recommendations
	if overall.AvgDurationSecs > 5 {
		recommendations = append(recommendations,
			"Consider increasing parallelism - average file processing time is high")
	}

	// Stage-specific recommendations
	for stage, metric := range overall.StageMetrics {
		stageName := db.stageToString(stage)

		if metric.DurationSeconds > overall.TotalDurationSecs/2 {
			recommendations = append(recommendations,
				fmt.Sprintf("%s stage is consuming >50%% of processing time - consider optimization", stageName))
		}

		if metric.SuccessRate < 0.1 {
			recommendations = append(recommendations,
				fmt.Sprintf("%s stage has low success rate (%.1f%%) - review rules effectiveness",
					stageName, metric.SuccessRate*100))
		}
	}

	// Accuracy recommendations
	for category, stats := range db.accuracyStats {
		if stats.Precision < 0.8 {
			recommendations = append(recommendations,
				fmt.Sprintf("Low precision (%.1f%%) for %s files - tune rules to reduce false positives",
					stats.Precision*100, category))
		}

		if stats.Recall < 0.6 {
			recommendations = append(recommendations,
				fmt.Sprintf("Low recall (%.1f%%) for %s files - add more detection rules",
					stats.Recall*100, category))
		}
	}

	// General recommendations
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "Performance and accuracy metrics look good!")
	}

	return recommendations
}

// GetTopPerformers returns files/categories with best performance
func (db *DetectionBenchmark) GetTopPerformers(limit int) []string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	type performer struct {
		category string
		score    float64
	}

	var performers []performer

	for category, metric := range db.metrics {
		if category == "overall" {
			continue
		}

		// Calculate performance score (findings per second)
		score := 0.0
		if metric.AvgDurationSecs > 0 {
			score = float64(metric.FilesProcessed) / metric.AvgDurationSecs
		}

		performers = append(performers, performer{category, score})
	}

	// Sort by score (highest first)
	sort.Slice(performers, func(i, j int) bool {
		return performers[i].score > performers[j].score
	})

	// Return top performers
	var result []string
	for i, p := range performers {
		if i >= limit {
			break
		}
		result = append(result, p.category)
	}

	return result
}

// GetBottlenecks identifies performance bottlenecks
func (db *DetectionBenchmark) GetBottlenecks() map[string]string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	bottlenecks := make(map[string]string)

	overall := db.metrics["overall"]
	if overall == nil {
		return bottlenecks
	}

	// Find slowest stage
	var slowestStage DetectionStage
	var slowestDuration float64

	for stage, metric := range overall.StageMetrics {
		avgDuration := metric.DurationSeconds / float64(metric.CallCount)
		if avgDuration > slowestDuration {
			slowestDuration = avgDuration
			slowestStage = stage
		}
	}

	if slowestDuration > 0 {
		bottlenecks["slowest_stage"] = fmt.Sprintf("%s (avg: %.2f seconds)",
			db.stageToString(slowestStage), slowestDuration)
	}

	// Find categories with high error rates
	for category, metric := range db.metrics {
		if metric.TotalCalls > 0 {
			errorRate := float64(metric.ErrorCount) / float64(metric.TotalCalls)
			if errorRate > 0.1 { // >10% error rate
				bottlenecks[category+"_errors"] = fmt.Sprintf("High error rate: %.1f%%", errorRate*100)
			}
		}
	}

	return bottlenecks
}

// Helper functions

func (db *DetectionBenchmark) categorizeFile(filePath string) string {
	if isTestFile(filePath) {
		return "test_files"
	}
	if isVendorFile(filePath) {
		return "vendor_files"
	}
	if isConfigFile(filePath) {
		return "config_files"
	}
	if isDocumentationFile(filePath) {
		return "doc_files"
	}
	return "source_files"
}

func (db *DetectionBenchmark) stageToString(stage DetectionStage) string {
	switch stage {
	case StageL0Regex:
		return "L0_Regex"
	case StageL1AST:
		return "L1_AST"
	case StageL2DataFlow:
		return "L2_DataFlow"
	default:
		return "Unknown"
	}
}

func isTestFile(filePath string) bool {
	filePathLower := strings.ToLower(filePath)

	// Strong test file indicators - these are definitely test files
	strongTestPatterns := []string{
		"_test.go", "_test.py", "_test.js", "_test.ts", "_test.java",
		".test.js", ".test.ts", ".test.py", ".spec.js", ".spec.ts",
		"test.go", "test.py", "test.js", "test.ts", "test.java",
		"spec.rb", "spec.py", "_spec.rb", "_spec.py",
		"tests/", "spec/", "__tests__/", "test/", "testing/",
		"unittest", "testcase", "phpunit", "pytest", "jest", "mocha",
	}

	for _, pattern := range strongTestPatterns {
		if strings.Contains(filePathLower, pattern) {
			return true
		}
	}

	// Files in test directories are test files, regardless of content
	testDirectories := []string{"test/", "tests/", "spec/", "__tests__/", "testing/"}
	for _, testDir := range testDirectories {
		if strings.Contains(filePathLower, testDir) {
			return true
		}
	}

	// For files that just have "test" in the name (like sha1_test.c),
	// check if they actually contain test framework code
	if strings.Contains(filePathLower, "test") {
		// These are NOT test files - they're crypto implementations with "test" in the name
		cryptoImplementationPatterns := []string{
			"_test.c", "_test.cpp", "_test.h", // C/C++ crypto implementations
			"test.c", "test.cpp", "test.h", // C/C++ crypto implementations
		}

		for _, pattern := range cryptoImplementationPatterns {
			if strings.HasSuffix(filePathLower, pattern) {
				return false // These are crypto implementations, not test files
			}
		}

		return true // Generic "test" pattern without crypto context
	}

	return false
}

func isVendorFile(filePath string) bool {
	vendorPatterns := []string{"vendor/", "node_modules/", "third_party/", ".git/"}
	for _, pattern := range vendorPatterns {
		if strings.Contains(filePath, pattern) {
			return true
		}
	}
	return false
}

func isConfigFile(filePath string) bool {
	configPatterns := []string{".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"}
	for _, pattern := range configPatterns {
		if strings.HasSuffix(strings.ToLower(filePath), pattern) {
			return true
		}
	}
	return false
}

func isDocumentationFile(filePath string) bool {
	docPatterns := []string{".md", ".txt", ".rst", "README", "CHANGELOG", "LICENSE"}
	filePathLower := strings.ToLower(filePath)
	for _, pattern := range docPatterns {
		if strings.Contains(filePathLower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}
