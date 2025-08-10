package main

import (
	"sort"
	"strings"

	"github.com/pqswitch/scanner/internal/types"
)

// prioritizeFindings sorts findings by priority and returns top N findings
func prioritizeFindings(findings []types.Finding, maxCount int) []types.Finding {
	// Sort by priority: 1) Severity, 2) Confidence, 3) Algorithm criticality
	sort.Slice(findings, func(i, j int) bool {
		// Priority 1: Severity (Critical > High > Medium > Low)
		severityI := getSeverityWeight(findings[i].Severity)
		severityJ := getSeverityWeight(findings[j].Severity)
		if severityI != severityJ {
			return severityI > severityJ
		}

		// Priority 2: Confidence (higher is better)
		if findings[i].Confidence != findings[j].Confidence {
			return findings[i].Confidence > findings[j].Confidence
		}

		// Priority 3: Algorithm criticality (post-quantum vulnerable algorithms first)
		criticalityI := getAlgorithmCriticality(findings[i].Algorithm)
		criticalityJ := getAlgorithmCriticality(findings[j].Algorithm)
		if criticalityI != criticalityJ {
			return criticalityI > criticalityJ
		}

		// Priority 4: Line number (earlier in file for consistency)
		return findings[i].Line < findings[j].Line
	})

	// Return top findings
	if len(findings) > maxCount {
		return findings[:maxCount]
	}
	return findings
}

// getSeverityWeight returns numeric weight for severity-based sorting
func getSeverityWeight(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// getAlgorithmCriticality returns criticality score for post-quantum migration priority
func getAlgorithmCriticality(algorithm string) int {
	alg := strings.ToLower(algorithm)

	// Highest priority: Asymmetric crypto that's quantum-vulnerable
	if strings.Contains(alg, "rsa") || strings.Contains(alg, "ecdsa") ||
		strings.Contains(alg, "ecdh") || strings.Contains(alg, "dh") ||
		strings.Contains(alg, "elliptic") || strings.Contains(alg, "curve25519") {
		return 10
	}

	// High priority: Weak symmetric crypto
	if strings.Contains(alg, "des") || strings.Contains(alg, "3des") ||
		strings.Contains(alg, "rc4") || strings.Contains(alg, "md5") ||
		strings.Contains(alg, "sha1") {
		return 8
	}

	// Medium priority: Signature algorithms
	if strings.Contains(alg, "signature") || strings.Contains(alg, "sign") ||
		strings.Contains(alg, "verify") {
		return 6
	}

	// Lower priority: Hash functions (still important but less urgent)
	if strings.Contains(alg, "sha") || strings.Contains(alg, "hash") ||
		strings.Contains(alg, "digest") {
		return 4
	}

	// Lowest priority: Other crypto
	return 2
}
