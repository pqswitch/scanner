package helpers

import (
	"fmt"
	"testing"

	"github.com/pqswitch/scanner/internal/types"
	"github.com/stretchr/testify/assert"
)

// Contains checks if a string is present in a slice of strings.
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// HasPrefix checks if a string starts with a given prefix.
func HasPrefix(str, prefix string) bool {
	return len(str) >= len(prefix) && str[:len(prefix)] == prefix
}

// AssertRule is a helper to check for a rule's presence and severity.
func AssertRule(t *testing.T, findings []types.Finding, ruleID, expectedSev string, expectPresent bool) {
	t.Helper()
	found := false
	for _, f := range findings {
		if f.RuleID == ruleID {
			found = true
			assert.Equal(t, expectedSev, f.Severity, fmt.Sprintf("Rule %s has incorrect severity", ruleID))
			break
		}
	}

	if expectPresent {
		assert.True(t, found, fmt.Sprintf("Rule %s was not found", ruleID))
	} else {
		assert.False(t, found, fmt.Sprintf("Rule %s was found but not expected", ruleID))
	}
}
