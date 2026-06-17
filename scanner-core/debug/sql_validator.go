package debug

import (
	"fmt"
	"strings"
)

// ValidateQuery validates that a SQL query is safe to execute.
// It returns true if the query is valid, false otherwise, along with an error
// describing any validation failure.
//
// Validation rules:
//  1. Query must not be empty
//  2. A single trailing semicolon is allowed, but multiple statements are prevented
//
// WARNING: This allows all SQL statements including INSERT, UPDATE, DELETE, DROP, etc.
// Only enable debug mode in development/testing environments.
func ValidateQuery(sql string) (bool, error) {
	// Trim whitespace
	trimmed := strings.TrimSpace(sql)

	if trimmed == "" {
		return false, fmt.Errorf("empty query")
	}

	// Allow a single trailing semicolon but strip it for validation
	// This prevents multiple statements while allowing standard SQL convention
	if strings.HasSuffix(trimmed, ";") {
		trimmed = strings.TrimSpace(trimmed[:len(trimmed)-1])
	}

	// Check for semicolons after stripping trailing one (prevents multiple statements)
	if strings.Contains(trimmed, ";") {
		return false, fmt.Errorf("multiple statements not allowed")
	}

	return true, nil
}

// IsSelectQuery is an alias for ValidateQuery for backward compatibility.
// Deprecated: Use ValidateQuery instead.
func IsSelectQuery(sql string) (bool, error) {
	return ValidateQuery(sql)
}
