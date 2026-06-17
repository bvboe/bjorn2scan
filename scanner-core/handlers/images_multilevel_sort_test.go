package handlers

import (
	"strings"
	"testing"
)

// TestImagesMultiLevelSorting verifies that images table uses multi-level sorting
func TestImagesMultiLevelSorting(t *testing.T) {
	tests := []struct {
		name             string
		sortBy           string
		sortOrder        string
		expectedOrderBy  string
		shouldNotContain string
	}{
		{
			name:            "Default sort: sort_order, image",
			sortBy:          "",
			sortOrder:       "ASC",
			expectedOrderBy: "ORDER BY status.sort_order ASC, image ASC",
		},
		{
			name:            "Sort by container_count: sort_order, container_count, image",
			sortBy:          "container_count",
			sortOrder:       "DESC",
			expectedOrderBy: "ORDER BY status.sort_order ASC, container_count DESC, image ASC",
		},
		{
			name:            "Sort by critical_count: sort_order, critical_count, image",
			sortBy:          "critical_count",
			sortOrder:       "DESC",
			expectedOrderBy: "ORDER BY status.sort_order ASC, critical_count DESC, image ASC",
		},
		{
			name:            "Sort by image: sort_order, image (no duplicate)",
			sortBy:          "image",
			sortOrder:       "DESC",
			expectedOrderBy: "ORDER BY status.sort_order ASC, image DESC",
			shouldNotContain: "image DESC, image ASC",
		},
		{
			name:            "Sort by total_risk: sort_order, total_risk, image",
			sortBy:          "total_risk",
			sortOrder:       "ASC",
			expectedOrderBy: "ORDER BY status.sort_order ASC, total_risk ASC, image ASC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build query
			query, _ := buildImagesQuery("", nil, nil, nil, nil, tt.sortBy, tt.sortOrder, 50, 0)

			// Check expected ORDER BY clause
			if !strings.Contains(query, tt.expectedOrderBy) {
				t.Errorf("Expected query to contain %q\nGot query: %s", tt.expectedOrderBy, query)
			}

			// Check for strings that should NOT be present
			if tt.shouldNotContain != "" && strings.Contains(query, tt.shouldNotContain) {
				t.Errorf("Query should NOT contain %q\nGot query: %s", tt.shouldNotContain, query)
			}

			// Verify sort_order is always first
			orderByIndex := strings.Index(query, "ORDER BY")
			if orderByIndex == -1 {
				t.Error("Query missing ORDER BY clause")
			} else {
				orderByClause := query[orderByIndex:]
				if !strings.HasPrefix(orderByClause, "ORDER BY status.sort_order ASC") {
					t.Errorf("Query should always start with 'ORDER BY status.sort_order ASC'\nGot: %s", orderByClause[:50])
				}
			}
		})
	}
}

// TestContainersMultiLevelSorting verifies that containers table uses multi-level sorting without duplicates
func TestContainersMultiLevelSorting(t *testing.T) {
	tests := []struct {
		name             string
		sortBy           string
		sortOrder        string
		expectedOrderBy  string
		shouldNotContain string
	}{
		{
			name:            "Default sort: sort_order, namespace, pod, container",
			sortBy:          "",
			sortOrder:       "ASC",
			expectedOrderBy: "ORDER BY status.sort_order ASC, instances.namespace ASC, instances.pod ASC, instances.name ASC",
		},
		{
			name:            "Sort by critical_count: includes all tie-breakers",
			sortBy:          "critical_count",
			sortOrder:       "DESC",
			expectedOrderBy: "ORDER BY status.sort_order ASC, critical_count DESC, instances.namespace ASC, instances.pod ASC, instances.name ASC",
		},
		{
			name:             "Sort by namespace: no duplicate namespace",
			sortBy:           "namespace",
			sortOrder:        "DESC",
			expectedOrderBy:  "ORDER BY status.sort_order ASC, namespace DESC, instances.pod ASC, instances.name ASC",
			shouldNotContain: "namespace DESC, instances.namespace ASC",
		},
		{
			name:             "Sort by pod: no duplicate pod",
			sortBy:           "pod",
			sortOrder:        "ASC",
			expectedOrderBy:  "ORDER BY status.sort_order ASC, pod ASC, instances.namespace ASC, instances.name ASC",
			shouldNotContain: "pod ASC, instances.pod ASC",
		},
		{
			name:             "Sort by name: no duplicate name",
			sortBy:           "name",
			sortOrder:        "DESC",
			expectedOrderBy:  "ORDER BY status.sort_order ASC, name DESC, instances.namespace ASC, instances.pod ASC",
			shouldNotContain: "name DESC, instances.name ASC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build query
			query, _ := buildContainersQuery("", nil, nil, nil, nil, tt.sortBy, tt.sortOrder, 50, 0)

			// Check expected ORDER BY clause
			if !strings.Contains(query, tt.expectedOrderBy) {
				t.Errorf("Expected query to contain %q\nGot query: %s", tt.expectedOrderBy, query)
			}

			// Check for strings that should NOT be present
			if tt.shouldNotContain != "" && strings.Contains(query, tt.shouldNotContain) {
				t.Errorf("Query should NOT contain duplicate: %q\nGot query: %s", tt.shouldNotContain, query)
			}

			// Verify sort_order is always first
			orderByIndex := strings.Index(query, "ORDER BY")
			if orderByIndex == -1 {
				t.Error("Query missing ORDER BY clause")
			} else {
				orderByClause := query[orderByIndex:]
				if !strings.HasPrefix(orderByClause, "ORDER BY status.sort_order ASC") {
					t.Errorf("Query should always start with 'ORDER BY status.sort_order ASC'\nGot: %s", orderByClause[:50])
				}
			}
		})
	}
}

// TestPackagesMultiLevelSorting verifies that packages (SBOM) table uses multi-level sorting without duplicates
func TestPackagesMultiLevelSorting(t *testing.T) {
	tests := []struct {
		name             string
		sortBy           string
		sortOrder        string
		expectedOrderBy  string
		shouldNotContain string
	}{
		{
			name:            "Default sort: name, version, type",
			sortBy:          "",
			sortOrder:       "ASC",
			expectedOrderBy: "ORDER BY p.name ASC, p.version ASC, p.type ASC",
		},
		{
			name:            "Sort by count: count, name, version, type",
			sortBy:          "count",
			sortOrder:       "DESC",
			expectedOrderBy: "ORDER BY p.number_of_instances DESC, p.name ASC, p.version ASC, p.type ASC",
		},
		{
			name:             "Sort by name: no duplicate name",
			sortBy:           "name",
			sortOrder:        "DESC",
			expectedOrderBy:  "ORDER BY p.name DESC, p.version ASC, p.type ASC",
			shouldNotContain: "p.name DESC, p.name ASC",
		},
		{
			name:             "Sort by version: no duplicate version",
			sortBy:           "version",
			sortOrder:        "ASC",
			expectedOrderBy:  "ORDER BY p.version ASC, p.name ASC, p.type ASC",
			shouldNotContain: "p.version ASC, p.version ASC",
		},
		{
			name:             "Sort by type: no duplicate type",
			sortBy:           "type",
			sortOrder:        "DESC",
			expectedOrderBy:  "ORDER BY p.type DESC, p.name ASC, p.version ASC",
			shouldNotContain: "p.type DESC, p.type ASC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build query
			query, _ := buildImagePackagesQuery("test-digest", nil, tt.sortBy, tt.sortOrder, 50, 0)

			// Check expected ORDER BY clause
			if !strings.Contains(query, tt.expectedOrderBy) {
				t.Errorf("Expected query to contain %q\nGot query: %s", tt.expectedOrderBy, query)
			}

			// Check for strings that should NOT be present
			if tt.shouldNotContain != "" && strings.Contains(query, tt.shouldNotContain) {
				t.Errorf("Query should NOT contain duplicate: %q\nGot query: %s", tt.shouldNotContain, query)
			}
		})
	}
}
