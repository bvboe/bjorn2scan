package handlers

import (
	"strings"
	"testing"
)

// TestNamespaceSecondarySorting verifies that namespace sorting includes secondary sort
func TestNamespaceSecondarySorting(t *testing.T) {
	tests := []struct {
		name              string
		sortBy            string
		sortOrder         string
		expectedOrderBy   string
		shouldNotContain  string
	}{
		{
			name:             "Sort by container_count includes namespace secondary",
			sortBy:           "container_count",
			sortOrder:        "DESC",
			expectedOrderBy:  "ORDER BY container_count DESC, namespace ASC",
			shouldNotContain: "",
		},
		{
			name:             "Sort by avg_critical includes namespace secondary",
			sortBy:           "avg_critical",
			sortOrder:        "ASC",
			expectedOrderBy:  "ORDER BY avg_critical ASC, namespace ASC",
			shouldNotContain: "",
		},
		{
			name:             "Sort by namespace does NOT include duplicate secondary",
			sortBy:           "namespace",
			sortOrder:        "DESC",
			expectedOrderBy:  "ORDER BY namespace DESC",
			shouldNotContain: "namespace DESC, namespace ASC",
		},
		{
			name:             "Default sort is namespace ASC",
			sortBy:           "",
			sortOrder:        "ASC",
			expectedOrderBy:  "ORDER BY namespace ASC",
			shouldNotContain: "namespace ASC, namespace ASC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build query
			query, _ := buildNamespaceSummaryQuery(nil, nil, nil, nil, tt.sortBy, tt.sortOrder, 100, 0)

			// Check expected ORDER BY clause
			if !strings.Contains(query, tt.expectedOrderBy) {
				t.Errorf("Expected query to contain %q\nGot query: %s", tt.expectedOrderBy, query)
			}

			// Check for strings that should NOT be present
			if tt.shouldNotContain != "" && strings.Contains(query, tt.shouldNotContain) {
				t.Errorf("Query should NOT contain %q\nGot query: %s", tt.shouldNotContain, query)
			}
		})
	}
}

// TestDistributionSecondarySorting verifies that distribution sorting includes secondary sort
func TestDistributionSecondarySorting(t *testing.T) {
	tests := []struct {
		name              string
		sortBy            string
		sortOrder         string
		expectedOrderBy   string
		shouldNotContain  string
	}{
		{
			name:             "Sort by container_count includes os_name secondary",
			sortBy:           "container_count",
			sortOrder:        "DESC",
			expectedOrderBy:  "ORDER BY container_count DESC, os_name ASC",
			shouldNotContain: "",
		},
		{
			name:             "Sort by avg_risk includes os_name secondary",
			sortBy:           "avg_risk",
			sortOrder:        "ASC",
			expectedOrderBy:  "ORDER BY avg_risk ASC, os_name ASC",
			shouldNotContain: "",
		},
		{
			name:             "Sort by os_name does NOT include duplicate secondary",
			sortBy:           "os_name",
			sortOrder:        "DESC",
			expectedOrderBy:  "ORDER BY os_name DESC",
			shouldNotContain: "os_name DESC, os_name ASC",
		},
		{
			name:             "Default sort is os_name ASC",
			sortBy:           "",
			sortOrder:        "ASC",
			expectedOrderBy:  "ORDER BY os_name ASC",
			shouldNotContain: "os_name ASC, os_name ASC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build query
			query, _ := buildDistributionSummaryQuery(nil, nil, nil, nil, tt.sortBy, tt.sortOrder, 100, 0)

			// Check expected ORDER BY clause
			if !strings.Contains(query, tt.expectedOrderBy) {
				t.Errorf("Expected query to contain %q\nGot query: %s", tt.expectedOrderBy, query)
			}

			// Check for strings that should NOT be present
			if tt.shouldNotContain != "" && strings.Contains(query, tt.shouldNotContain) {
				t.Errorf("Query should NOT contain %q\nGot query: %s", tt.shouldNotContain, query)
			}
		})
	}
}
