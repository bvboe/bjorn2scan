package handlers

import (
	"strings"
	"testing"
)

// TestVulnerabilitiesSorting verifies that vulnerability table uses proper multi-level sorting
func TestVulnerabilitiesSorting(t *testing.T) {
	tests := []struct {
		name             string
		sortBy           string
		sortOrder        string
		expectedContains []string
		shouldNotContain string
	}{
		{
			name:      "Default: severity CASE, vulnerability",
			sortBy:    "",
			sortOrder: "ASC",
			expectedContains: []string{
				"ORDER BY",
				"CASE v.severity",
				"WHEN 'Critical' THEN 1",
				"END ASC",
				"v.cve_id ASC",
			},
		},
		{
			name:      "Click Status: status, severity, vulnerability",
			sortBy:    "vulnerability_fix_state",
			sortOrder: "ASC",
			expectedContains: []string{
				"v.fix_status ASC",
				"CASE v.severity",
				"v.cve_id ASC",
			},
		},
		{
			name:      "Click Risk DESC: risk, severity, vulnerability",
			sortBy:    "vulnerability_risk",
			sortOrder: "DESC",
			expectedContains: []string{
				"v.risk DESC",
				"CASE v.severity",
				"END ASC",
				"v.cve_id ASC",
			},
		},
		{
			name:      "Click Severity DESC: severity DESC, vulnerability",
			sortBy:    "vulnerability_severity",
			sortOrder: "DESC",
			expectedContains: []string{
				"CASE v.severity",
				"END DESC",
				"v.cve_id ASC",
			},
			shouldNotContain: "v.cve_id DESC",
		},
		{
			name:      "Click Vulnerability DESC: vulnerability DESC, severity",
			sortBy:    "vulnerability_id",
			sortOrder: "DESC",
			expectedContains: []string{
				"v.cve_id DESC",
				"CASE v.severity",
				"END ASC",
			},
			shouldNotContain: "v.cve_id ASC",
		},
		{
			name:      "Click Package Name: name, severity, vulnerability",
			sortBy:    "artifact_name",
			sortOrder: "ASC",
			expectedContains: []string{
				"v.package_name ASC",
				"CASE v.severity",
				"v.cve_id ASC",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build query with dummy image digest
			query, _ := buildImageVulnerabilitiesQuery("test-digest", nil, nil, nil, tt.sortBy, tt.sortOrder, 100, 0)

			// Check all expected strings are present
			for _, expected := range tt.expectedContains {
				if !strings.Contains(query, expected) {
					t.Errorf("Expected query to contain %q\nGot query: %s", expected, query)
				}
			}

			// Check for strings that should NOT be present
			if tt.shouldNotContain != "" && strings.Contains(query, tt.shouldNotContain) {
				t.Errorf("Query should NOT contain %q\nGot query: %s", tt.shouldNotContain, query)
			}

			// Verify ORDER BY exists
			if !strings.Contains(query, "ORDER BY") {
				t.Error("Query missing ORDER BY clause")
			}

			// Verify severity CASE is always present
			if !strings.Contains(query, "CASE v.severity") {
				t.Error("Query missing severity CASE statement")
			}
		})
	}
}

// TestVulnerabilitiesSortingOrder verifies the order of sort columns
func TestVulnerabilitiesSortingOrder(t *testing.T) {
	tests := []struct {
		name          string
		sortBy        string
		sortOrder     string
		firstColumn   string
		secondColumn  string
		thirdColumn   string
	}{
		{
			name:         "Default ordering",
			sortBy:       "",
			sortOrder:    "ASC",
			firstColumn:  "CASE v.severity",
			secondColumn: "v.cve_id",
			thirdColumn:  "",
		},
		{
			name:         "Status first, then severity, then vulnerability",
			sortBy:       "vulnerability_fix_state",
			sortOrder:    "ASC",
			firstColumn:  "v.fix_status",
			secondColumn: "CASE v.severity",
			thirdColumn:  "v.cve_id",
		},
		{
			name:         "Severity DESC, then vulnerability",
			sortBy:       "vulnerability_severity",
			sortOrder:    "DESC",
			firstColumn:  "CASE v.severity",
			secondColumn: "v.cve_id",
			thirdColumn:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, _ := buildImageVulnerabilitiesQuery("test-digest", nil, nil, nil, tt.sortBy, tt.sortOrder, 100, 0)

			// Find ORDER BY clause
			orderByIndex := strings.Index(query, "ORDER BY")
			if orderByIndex == -1 {
				t.Fatal("Query missing ORDER BY clause")
			}

			orderBySection := query[orderByIndex:]

			// Check order of columns
			firstIndex := strings.Index(orderBySection, tt.firstColumn)
			secondIndex := strings.Index(orderBySection, tt.secondColumn)

			if firstIndex == -1 {
				t.Errorf("First column %q not found in ORDER BY", tt.firstColumn)
			}
			if secondIndex == -1 {
				t.Errorf("Second column %q not found in ORDER BY", tt.secondColumn)
			}
			if firstIndex >= secondIndex {
				t.Errorf("Column order wrong: %q should come before %q\nGot: %s",
					tt.firstColumn, tt.secondColumn, orderBySection[:200])
			}

			if tt.thirdColumn != "" {
				thirdIndex := strings.Index(orderBySection, tt.thirdColumn)
				if thirdIndex == -1 {
					t.Errorf("Third column %q not found in ORDER BY", tt.thirdColumn)
				}
				if secondIndex >= thirdIndex {
					t.Errorf("Column order wrong: %q should come before %q", tt.secondColumn, tt.thirdColumn)
				}
			}
		})
	}
}
