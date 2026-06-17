package handlers

import (
	"fmt"
	"strings"
)

// escapeSQL escapes a string for safe SQL interpolation
func escapeSQL(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// buildINClause builds a SQL IN clause from a slice of strings
// Returns empty string if values is empty
// Example: buildINClause("namespace", []string{"default", "kube-system"})
// Returns: "namespace IN ('default','kube-system')"
func buildINClause(columnName string, values []string) string {
	if len(values) == 0 {
		return ""
	}
	escaped := make([]string, len(values))
	for i, v := range values {
		escaped[i] = "'" + escapeSQL(v) + "'"
	}
	return columnName + " IN (" + strings.Join(escaped, ",") + ")"
}

// buildLikeCondition builds a SQL LIKE condition for substring matching
// Returns empty string if pattern is empty
// Example: buildLikeCondition("name", "nginx")
// Returns: "name LIKE '%nginx%'"
func buildLikeCondition(columnName, pattern string) string {
	if pattern == "" {
		return ""
	}
	return fmt.Sprintf("%s LIKE '%%%s%%'", columnName, escapeSQL(pattern))
}

// appendCondition appends a condition to the conditions slice if it's non-empty
func appendCondition(conditions []string, condition string) []string {
	if condition != "" {
		return append(conditions, condition)
	}
	return conditions
}

// buildWhereClause combines conditions with AND
// Returns empty string if no conditions
func buildWhereClause(conditions []string) string {
	if len(conditions) == 0 {
		return ""
	}
	return " AND " + strings.Join(conditions, " AND ")
}

// buildPackageTypeFilter builds a WHERE clause for filtering by package type
// Returns empty string if packageTypes is empty
func buildPackageTypeFilter(packageTypes []string) string {
	clause := buildINClause("type", packageTypes)
	if clause == "" {
		return ""
	}
	return "WHERE " + clause
}

// buildVulnerabilityFilter builds a WHERE clause for vulnerability filtering
// combining fix_status and package_type filters
func buildVulnerabilityFilter(vulnStatuses, packageTypes []string) string {
	var filters []string

	if clause := buildINClause("fix_status", vulnStatuses); clause != "" {
		filters = append(filters, clause)
	}

	if clause := buildINClause("package_type", packageTypes); clause != "" {
		filters = append(filters, clause)
	}

	if len(filters) == 0 {
		return ""
	}
	return "WHERE " + strings.Join(filters, " AND ")
}
