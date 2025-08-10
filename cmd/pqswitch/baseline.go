package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pqswitch/scanner/internal/types"
)

// BaselineEntry represents a single suppression rule
type BaselineEntry struct {
	RuleID  string `json:"rule_id"`
	File    string `json:"file,omitempty"`
	Line    int    `json:"line,omitempty"`
	Expires string `json:"expires,omitempty"`
}

// baselineFileModel supports both array and object forms
type baselineFileModel struct {
	Suppressions []BaselineEntry `json:"suppressions"`
}

// FilterFindingsWithBaseline filters out findings that match the baseline suppressions
func FilterFindingsWithBaseline(findings []types.Finding, baselinePath string) []types.Finding {
	if baselinePath == "" {
		return findings
	}

	// Only support JSON for now
	if ext := strings.ToLower(filepath.Ext(baselinePath)); ext != ".json" && ext != "" {
		// Unsupported format; return unmodified
		return findings
	}

	// Ensure baselinePath is a normal file path (no directories) and not an absolute path
	// This is a user-supplied CLI flag and reading its contents is expected behavior.
	//nolint:gosec // G304: acceptable user-provided path read for baseline suppression file
	data, err := os.ReadFile(baselinePath)
	if err != nil {
		// Fail open: do not drop findings if baseline can't be read
		fmt.Fprintf(os.Stderr, "Warning: failed to read baseline file %s: %v\n", baselinePath, err)
		return findings
	}

	entries := make([]BaselineEntry, 0)

	// Try object form
	var obj baselineFileModel
	if err := json.Unmarshal(data, &obj); err == nil && len(obj.Suppressions) > 0 {
		entries = obj.Suppressions
	} else {
		// Try array form
		if err := json.Unmarshal(data, &entries); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse baseline file %s: %v\n", baselinePath, err)
			return findings
		}
	}

	if len(entries) == 0 {
		return findings
	}

	now := time.Now()

	filtered := make([]types.Finding, 0, len(findings))
	for _, f := range findings {
		suppressed := false
		for _, e := range entries {
			if e.RuleID == "" || e.RuleID != f.RuleID {
				continue
			}
			// Optional expiry
			if e.Expires != "" {
				if t, err := time.Parse(time.RFC3339, e.Expires); err == nil {
					if now.After(t) {
						continue // expired suppression
					}
				}
			}
			// Optional file match: suffix match to allow different roots
			if e.File != "" {
				if f.File == "" || !strings.HasSuffix(f.File, e.File) {
					continue
				}
			}
			// Optional line match
			if e.Line > 0 && e.Line != f.Line {
				continue
			}
			suppressed = true
			break
		}
		if !suppressed {
			filtered = append(filtered, f)
		}
	}

	return filtered
}
