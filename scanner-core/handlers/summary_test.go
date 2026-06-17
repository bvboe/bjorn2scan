package handlers

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

func TestDeploymentMetricsHandler(t *testing.T) {
	tests := []struct {
		name          string
		mockResult    *database.QueryResult
		expectedCode  int
		check         func(t *testing.T, body string)
	}{
		{
			name: "returns all metrics",
			mockResult: &database.QueryResult{
				Columns: []string{
					"container_instances", "images_scanned", "total_cves",
					"unique_cves", "total_exploits", "images_pending", "images_failed",
				},
				Rows: []map[string]interface{}{
					{
						"container_instances": int64(150),
						"images_scanned":      int64(45),
						"total_cves":          int64(23450),
						"unique_cves":         int64(312),
						"total_exploits":      int64(89),
						"images_pending":      int64(3),
						"images_failed":       int64(1),
					},
				},
			},
			expectedCode: http.StatusOK,
			check: func(t *testing.T, body string) {
				var m struct {
					ContainerInstances int64 `json:"container_instances"`
					ImagesScanned      int64 `json:"images_scanned"`
					TotalCVEs          int64 `json:"total_cves"`
					UniqueCVEs         int64 `json:"unique_cves"`
					TotalExploits      int64 `json:"total_exploits"`
					ImagesPending      int64 `json:"images_pending"`
					ImagesFailed       int64 `json:"images_failed"`
				}
				if err := json.Unmarshal([]byte(body), &m); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				if m.ContainerInstances != 150 {
					t.Errorf("container_instances: want 150, got %d", m.ContainerInstances)
				}
				if m.ImagesScanned != 45 {
					t.Errorf("images_scanned: want 45, got %d", m.ImagesScanned)
				}
				if m.TotalCVEs != 23450 {
					t.Errorf("total_cves: want 23450, got %d", m.TotalCVEs)
				}
				if m.UniqueCVEs != 312 {
					t.Errorf("unique_cves: want 312, got %d", m.UniqueCVEs)
				}
				if m.TotalExploits != 89 {
					t.Errorf("total_exploits: want 89, got %d", m.TotalExploits)
				}
				if m.ImagesPending != 3 {
					t.Errorf("images_pending: want 3, got %d", m.ImagesPending)
				}
				if m.ImagesFailed != 1 {
					t.Errorf("images_failed: want 1, got %d", m.ImagesFailed)
				}
			},
		},
		{
			name: "omits pending and failed when zero",
			mockResult: &database.QueryResult{
				Columns: []string{
					"container_instances", "images_scanned", "total_cves",
					"unique_cves", "total_exploits", "images_pending", "images_failed",
				},
				Rows: []map[string]interface{}{
					{
						"container_instances": int64(50),
						"images_scanned":      int64(10),
						"total_cves":          int64(500),
						"unique_cves":         int64(80),
						"total_exploits":      int64(5),
						"images_pending":      int64(0),
						"images_failed":       int64(0),
					},
				},
			},
			expectedCode: http.StatusOK,
			check: func(t *testing.T, body string) {
				// omitempty means zero values are absent from JSON
				if strings.Contains(body, "images_pending") {
					t.Error("images_pending should be omitted when zero")
				}
				if strings.Contains(body, "images_failed") {
					t.Error("images_failed should be omitted when zero")
				}
			},
		},
		{
			name: "returns zeros when no data",
			mockResult: &database.QueryResult{
				Columns: []string{},
				Rows:    []map[string]interface{}{},
			},
			expectedCode: http.StatusOK,
			check: func(t *testing.T, body string) {
				var m map[string]interface{}
				if err := json.Unmarshal([]byte(body), &m); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				if m["container_instances"].(float64) != 0 {
					t.Errorf("Expected container_instances=0 for empty result")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockQueryProvider{
				queryFunc: func(_ string) (*database.QueryResult, error) {
					return tt.mockResult, nil
				},
			}
			handler := DeploymentMetricsHandler(provider)
			req := httptest.NewRequest(http.MethodGet, "/api/summary/deployment-metrics", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.expectedCode {
				t.Errorf("Expected status %d, got %d", tt.expectedCode, rec.Code)
			}
			if tt.check != nil {
				tt.check(t, rec.Body.String())
			}
		})
	}
}

func TestNodeMetricsSummaryHandler(t *testing.T) {
	tests := []struct {
		name         string
		mockResult   *database.QueryResult
		expectedCode int
		check        func(t *testing.T, body string)
	}{
		{
			name: "returns all metrics",
			mockResult: &database.QueryResult{
				Columns: []string{"total_nodes", "total_cves", "unique_cves", "total_exploits", "nodes_pending", "nodes_failed"},
				Rows: []map[string]interface{}{
					{
						"total_nodes":    int64(8),
						"total_cves":     int64(4200),
						"unique_cves":    int64(180),
						"total_exploits": int64(12),
						"nodes_pending":  int64(2),
						"nodes_failed":   int64(1),
					},
				},
			},
			expectedCode: http.StatusOK,
			check: func(t *testing.T, body string) {
				var m struct {
					TotalNodes    int64 `json:"total_nodes"`
					TotalCVEs     int64 `json:"total_cves"`
					UniqueCVEs    int64 `json:"unique_cves"`
					TotalExploits int64 `json:"total_exploits"`
					NodesPending  int64 `json:"nodes_pending"`
					NodesFailed   int64 `json:"nodes_failed"`
				}
				if err := json.Unmarshal([]byte(body), &m); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				if m.TotalNodes != 8 {
					t.Errorf("total_nodes: want 8, got %d", m.TotalNodes)
				}
				if m.TotalCVEs != 4200 {
					t.Errorf("total_cves: want 4200, got %d", m.TotalCVEs)
				}
				if m.UniqueCVEs != 180 {
					t.Errorf("unique_cves: want 180, got %d", m.UniqueCVEs)
				}
				if m.TotalExploits != 12 {
					t.Errorf("total_exploits: want 12, got %d", m.TotalExploits)
				}
				if m.NodesPending != 2 {
					t.Errorf("nodes_pending: want 2, got %d", m.NodesPending)
				}
				if m.NodesFailed != 1 {
					t.Errorf("nodes_failed: want 1, got %d", m.NodesFailed)
				}
			},
		},
		{
			name: "omits pending and failed when zero",
			mockResult: &database.QueryResult{
				Columns: []string{"total_nodes", "total_cves", "unique_cves", "total_exploits", "nodes_pending", "nodes_failed"},
				Rows: []map[string]interface{}{
					{
						"total_nodes":    int64(5),
						"total_cves":     int64(100),
						"unique_cves":    int64(30),
						"total_exploits": int64(2),
						"nodes_pending":  int64(0),
						"nodes_failed":   int64(0),
					},
				},
			},
			expectedCode: http.StatusOK,
			check: func(t *testing.T, body string) {
				if strings.Contains(body, "nodes_pending") {
					t.Error("nodes_pending should be omitted when zero")
				}
				if strings.Contains(body, "nodes_failed") {
					t.Error("nodes_failed should be omitted when zero")
				}
			},
		},
		{
			name: "returns zeros when no data",
			mockResult: &database.QueryResult{
				Columns: []string{},
				Rows:    []map[string]interface{}{},
			},
			expectedCode: http.StatusOK,
			check: func(t *testing.T, body string) {
				var m map[string]interface{}
				if err := json.Unmarshal([]byte(body), &m); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				if m["total_nodes"].(float64) != 0 {
					t.Errorf("Expected total_nodes=0 for empty result")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockQueryProvider{
				queryFunc: func(_ string) (*database.QueryResult, error) {
					return tt.mockResult, nil
				},
			}
			handler := NodeMetricsSummaryHandler(provider)
			req := httptest.NewRequest(http.MethodGet, "/api/summary/node-metrics", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tt.expectedCode {
				t.Errorf("Expected status %d, got %d", tt.expectedCode, rec.Code)
			}
			if tt.check != nil {
				tt.check(t, rec.Body.String())
			}
		})
	}
}

func TestNamespaceSummaryHandler(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		mockFunc       func(query string) (*database.QueryResult, error)
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name:        "returns namespace summaries",
			queryParams: "page=1&pageSize=10",
			mockFunc: func(query string) (*database.QueryResult, error) {
				// Check if this is the count query (starts with SELECT COUNT)
				trimmed := strings.TrimSpace(query)
				if strings.HasPrefix(trimmed, "SELECT COUNT(*)") {
					return &database.QueryResult{
						Columns: []string{"COUNT(*)"},
						Rows:    []map[string]interface{}{{"COUNT(*)": int64(3)}},
					}, nil
				}
				// Otherwise return data query result
				return &database.QueryResult{
					Columns: []string{"namespace", "container_count", "avg_critical", "avg_high", "avg_medium", "avg_low", "avg_negligible", "avg_unknown", "avg_risk", "avg_exploits", "avg_packages"},
					Rows: []map[string]interface{}{
						{
							"namespace":      "default",
							"container_count": int64(10),
							"avg_critical":   float64(5.5),
							"avg_high":       float64(10.2),
							"avg_medium":     float64(20.8),
							"avg_low":        float64(15.3),
							"avg_negligible": float64(5.0),
							"avg_unknown":    float64(1.0),
							"avg_risk":       float64(100.5),
							"avg_exploits":   float64(2.0),
							"avg_packages":   float64(150.0),
						},
						{
							"namespace":      "kube-system",
							"container_count": int64(5),
							"avg_critical":   float64(0.0),
							"avg_high":       float64(2.1),
							"avg_medium":     float64(5.5),
							"avg_low":        float64(3.0),
							"avg_negligible": float64(1.0),
							"avg_unknown":    float64(0.0),
							"avg_risk":       float64(25.5),
							"avg_exploits":   float64(0.0),
							"avg_packages":   float64(75.0),
						},
					},
				}, nil
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var response map[string]interface{}
				if err := json.Unmarshal([]byte(body), &response); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				namespaces := response["namespaces"].([]interface{})
				if len(namespaces) != 2 {
					t.Errorf("Expected 2 namespaces, got %d. Full response: %+v", len(namespaces), response)
				}
				if len(namespaces) > 0 {
					first := namespaces[0].(map[string]interface{})
					if first["namespace"] != "default" {
						t.Errorf("Expected namespace 'default', got %v. Full first item: %+v", first["namespace"], first)
					}
					// Check that averages are rounded to 1 decimal
					if first["avg_critical"].(float64) != 5.5 {
						t.Errorf("Expected avg_critical 5.5, got %v", first["avg_critical"])
					}
				}
			},
		},
		{
			name:        "CSV export",
			queryParams: "format=csv",
			mockFunc: func(query string) (*database.QueryResult, error) {
				trimmed := strings.TrimSpace(query)
				if strings.HasPrefix(trimmed, "SELECT COUNT(*)") {
					return &database.QueryResult{
						Columns: []string{"COUNT(*)"},
						Rows:    []map[string]interface{}{{"COUNT(*)": int64(1)}},
					}, nil
				}
				return &database.QueryResult{
					Columns: []string{"namespace", "container_count", "avg_critical", "avg_high", "avg_medium", "avg_low", "avg_negligible", "avg_unknown", "avg_risk", "avg_exploits", "avg_packages"},
					Rows: []map[string]interface{}{
						{
							"namespace":       "default",
							"container_count":  int64(10),
							"avg_critical":    float64(5.5),
							"avg_high":        float64(10.2),
							"avg_medium":      float64(20.8),
							"avg_low":         float64(30.1),
							"avg_negligible":  float64(5.0),
							"avg_unknown":     float64(1.0),
							"avg_risk":        float64(123.4),
							"avg_exploits":    float64(2.0),
							"avg_packages":    float64(150.5),
						},
					},
				}, nil
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				reader := csv.NewReader(strings.NewReader(body))
				records, err := reader.ReadAll()
				if err != nil {
					t.Fatalf("Failed to parse CSV: %v", err)
				}
				if len(records) != 2 { // Header + 1 data row
					t.Errorf("Expected 2 CSV rows, got %d", len(records))
				}
				if records[0][0] != "Namespace" {
					t.Errorf("Expected first column header to be 'Namespace', got '%s'", records[0][0])
				}
				if records[1][0] != "default" {
					t.Errorf("Expected first data row to be 'default', got '%s'", records[1][0])
				}
			},
		},
		{
			name:        "with filters",
			queryParams: "namespaces=default&vulnStatuses=fixed&packageTypes=apk",
			mockFunc: func(query string) (*database.QueryResult, error) {
				// Check that filters are applied in subqueries
				if !strings.Contains(query, "fix_status IN ('fixed')") {
					t.Error("Expected vulnerability status filter in query")
				}
				if !strings.Contains(query, "type IN ('apk')") {
					t.Error("Expected package type filter in query")
				}
				if !strings.Contains(query, "instances.namespace IN ('default')") {
					t.Error("Expected namespace filter in query")
				}
				trimmed := strings.TrimSpace(query)
				if strings.HasPrefix(trimmed, "SELECT COUNT(*)") {
					return &database.QueryResult{
						Columns: []string{"COUNT(*)"},
						Rows:    []map[string]interface{}{{"COUNT(*)": int64(1)}},
					}, nil
				}
				return &database.QueryResult{
					Columns: []string{"namespace", "container_count", "avg_critical", "avg_high", "avg_medium", "avg_low", "avg_negligible", "avg_unknown", "avg_risk", "avg_exploits", "avg_packages"},
					Rows: []map[string]interface{}{
						{
							"namespace":      "default",
							"container_count": int64(5),
							"avg_critical":   float64(2.0),
							"avg_high":       float64(5.0),
							"avg_medium":     float64(10.0),
							"avg_low":        float64(8.0),
							"avg_negligible": float64(2.0),
							"avg_unknown":    float64(0.0),
							"avg_risk":       float64(50.0),
							"avg_exploits":   float64(1.0),
							"avg_packages":   float64(80.0),
						},
					},
				}, nil
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:        "with sorting",
			queryParams: "sortBy=avg_critical&sortOrder=DESC",
			mockFunc: func(query string) (*database.QueryResult, error) {
				trimmed := strings.TrimSpace(query)
				// Only check sorting in the data query, not the count query
				if !strings.HasPrefix(trimmed, "SELECT COUNT(*)") {
					if !strings.Contains(query, "ORDER BY avg_critical DESC") {
						t.Errorf("Expected ORDER BY avg_critical DESC in data query, got: %s", query)
					}
				}
				if strings.HasPrefix(trimmed, "SELECT COUNT(*)") {
					return &database.QueryResult{
						Columns: []string{"COUNT(*)"},
						Rows:    []map[string]interface{}{{"COUNT(*)": int64(0)}},
					}, nil
				}
				return &database.QueryResult{
					Columns: []string{"namespace", "container_count", "avg_critical", "avg_high", "avg_medium", "avg_low", "avg_negligible", "avg_unknown", "avg_risk", "avg_exploits", "avg_packages"},
					Rows:    []map[string]interface{}{},
				}, nil
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockQueryProvider{
				queryFunc: tt.mockFunc,
			}

			handler := NamespaceSummaryHandler(provider)
			req := httptest.NewRequest(http.MethodGet, "/api/summary/by-namespace?"+tt.queryParams, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, rec.Body.String())
			}
		})
	}
}

func TestDistributionSummaryHandler(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		mockFunc       func(query string) (*database.QueryResult, error)
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name:        "returns distribution summaries",
			queryParams: "page=1&pageSize=10",
			mockFunc: func(query string) (*database.QueryResult, error) {
				trimmed := strings.TrimSpace(query)
				if strings.HasPrefix(trimmed, "SELECT COUNT(*)") {
					return &database.QueryResult{
						Columns: []string{"COUNT(*)"},
						Rows:    []map[string]interface{}{{"COUNT(*)": int64(2)}},
					}, nil
				}
				return &database.QueryResult{
					Columns: []string{"os_name", "container_count", "avg_critical", "avg_high", "avg_medium", "avg_low", "avg_negligible", "avg_unknown", "avg_risk", "avg_exploits", "avg_packages"},
					Rows: []map[string]interface{}{
						{
							"os_name":        "alpine:3.18",
							"container_count": int64(15),
							"avg_critical":   float64(3.2),
							"avg_high":       float64(8.5),
							"avg_medium":     float64(12.0),
							"avg_low":        float64(20.0),
							"avg_negligible": float64(5.0),
							"avg_unknown":    float64(1.0),
							"avg_risk":       float64(85.5),
							"avg_exploits":   float64(1.5),
							"avg_packages":   float64(120.0),
						},
						{
							"os_name":        "ubuntu:22.04",
							"container_count": int64(10),
							"avg_critical":   float64(1.0),
							"avg_high":       float64(5.0),
							"avg_medium":     float64(8.0),
							"avg_low":        float64(15.0),
							"avg_negligible": float64(3.0),
							"avg_unknown":    float64(0.0),
							"avg_risk":       float64(45.0),
							"avg_exploits":   float64(0.5),
							"avg_packages":   float64(90.0),
						},
					},
				}, nil
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var response map[string]interface{}
				if err := json.Unmarshal([]byte(body), &response); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				distributions := response["distributions"].([]interface{})
				if len(distributions) != 2 {
					t.Errorf("Expected 2 distributions, got %d", len(distributions))
				}
				first := distributions[0].(map[string]interface{})
				if first["os_name"] != "alpine:3.18" {
					t.Errorf("Expected os_name 'alpine:3.18', got %v", first["os_name"])
				}
			},
		},
		{
			name:        "CSV export",
			queryParams: "format=csv",
			mockFunc: func(query string) (*database.QueryResult, error) {
				if strings.Contains(query, "COUNT(*)") {
					return &database.QueryResult{
						Columns: []string{"COUNT(*)"},
						Rows:    []map[string]interface{}{{"COUNT(*)": int64(1)}},
					}, nil
				}
				return &database.QueryResult{
					Columns: []string{"os_name", "container_count", "avg_critical", "avg_high", "avg_medium", "avg_low", "avg_negligible", "avg_unknown", "avg_risk", "avg_exploits", "avg_packages"},
					Rows: []map[string]interface{}{
						{
							"os_name":        "alpine:3.18",
							"container_count": int64(15),
							"avg_critical":   float64(3.2),
							"avg_high":       float64(8.5),
							"avg_medium":     float64(15.0),
							"avg_low":        float64(25.0),
							"avg_negligible": float64(10.0),
							"avg_unknown":    float64(2.0),
							"avg_risk":       float64(89.5),
							"avg_exploits":   float64(1.5),
							"avg_packages":   float64(120.0),
						},
					},
				}, nil
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				reader := csv.NewReader(strings.NewReader(body))
				records, err := reader.ReadAll()
				if err != nil {
					t.Fatalf("Failed to parse CSV: %v", err)
				}
				if len(records) != 2 {
					t.Errorf("Expected 2 CSV rows, got %d", len(records))
				}
				if records[0][0] != "OS Distribution" {
					t.Errorf("Expected first column header to be 'OS Distribution', got '%s'", records[0][0])
				}
			},
		},
		{
			name:        "filters out null OS names",
			queryParams: "",
			mockFunc: func(query string) (*database.QueryResult, error) {
				if !strings.Contains(query, "images.os_name IS NOT NULL") {
					t.Error("Expected NULL filter for os_name in query")
				}
				if !strings.Contains(query, "images.os_name != ''") {
					t.Error("Expected empty string filter for os_name in query")
				}
				if strings.Contains(query, "COUNT(*)") {
					return &database.QueryResult{
						Columns: []string{"COUNT(*)"},
						Rows:    []map[string]interface{}{{"COUNT(*)": int64(0)}},
					}, nil
				}
				return &database.QueryResult{
					Columns: []string{"os_name"},
					Rows:    []map[string]interface{}{},
				}, nil
			},
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockQueryProvider{
				queryFunc: tt.mockFunc,
			}

			handler := DistributionSummaryHandler(provider)
			req := httptest.NewRequest(http.MethodGet, "/api/summary/by-distribution?"+tt.queryParams, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, rec.Body.String())
			}
		})
	}
}


func TestBuildNamespaceSummaryQuery(t *testing.T) {
	tests := []struct {
		name            string
		namespaces      []string
		vulnStatuses    []string
		packageTypes    []string
		osNames         []string
		sortBy          string
		sortOrder       string
		expectedInQuery []string
	}{
		{
			name: "basic query",
			expectedInQuery: []string{
				"SELECT",
				"instances.namespace",
				"AVG(COALESCE(vuln_counts.critical_count, 0)) as avg_critical",
				"GROUP BY instances.namespace",
				"status.status = 'completed'",
			},
		},
		{
			name:       "with namespace filter",
			namespaces: []string{"default", "kube-system"},
			expectedInQuery: []string{
				"instances.namespace IN ('default','kube-system')",
			},
		},
		{
			name:         "with vulnerability status filter",
			vulnStatuses: []string{"fixed"},
			expectedInQuery: []string{
				"fix_status IN ('fixed')",
			},
		},
		{
			name:         "with package type filter",
			packageTypes: []string{"apk", "deb"},
			expectedInQuery: []string{
				"type IN ('apk','deb')",
			},
		},
		{
			name:      "with sorting",
			sortBy:    "avg_risk",
			sortOrder: "DESC",
			expectedInQuery: []string{
				"ORDER BY avg_risk DESC",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mainQuery, countQuery := buildNamespaceSummaryQuery(
				tt.namespaces,
				tt.vulnStatuses,
				tt.packageTypes,
				tt.osNames,
				tt.sortBy,
				tt.sortOrder,
				50,
				0,
			)

			for _, expected := range tt.expectedInQuery {
				found := strings.Contains(mainQuery, expected) || strings.Contains(countQuery, expected)
				if !found {
					t.Errorf("Expected query to contain '%s'\nMain: %s\nCount: %s",
						expected, mainQuery, countQuery)
				}
			}

			// Check pagination
			if !strings.Contains(mainQuery, "LIMIT 50") {
				t.Error("Expected LIMIT 50 in main query")
			}
			if !strings.Contains(countQuery, "COUNT(*)") {
				t.Error("Expected COUNT(*) in count query")
			}
		})
	}
}

func TestHelperFunctions(t *testing.T) {
	t.Run("getStringValue", func(t *testing.T) {
		row := map[string]interface{}{
			"name":   "test",
			"number": int64(123),
		}
		if getStringValue(row, "name") != "test" {
			t.Error("Expected 'test'")
		}
		if getStringValue(row, "number") != "" {
			t.Error("Expected empty string for non-string value")
		}
		if getStringValue(row, "missing") != "" {
			t.Error("Expected empty string for missing key")
		}
	})

	t.Run("getIntValue", func(t *testing.T) {
		row := map[string]interface{}{
			"count": int64(42),
			"name":  "test",
		}
		if getIntValue(row, "count") != 42 {
			t.Error("Expected 42")
		}
		if getIntValue(row, "name") != 0 {
			t.Error("Expected 0 for non-int value")
		}
		if getIntValue(row, "missing") != 0 {
			t.Error("Expected 0 for missing key")
		}
	})

	t.Run("getFloatValue", func(t *testing.T) {
		row := map[string]interface{}{
			"float":  float64(3.14),
			"int":    int64(42),
			"string": "test",
		}
		if getFloatValue(row, "float") != 3.14 {
			t.Error("Expected 3.14")
		}
		if getFloatValue(row, "int") != 42.0 {
			t.Error("Expected 42.0 for int64")
		}
		if getFloatValue(row, "string") != 0.0 {
			t.Error("Expected 0.0 for non-numeric value")
		}
	})

	t.Run("roundToOne", func(t *testing.T) {
		tests := []struct {
			input    float64
			expected float64
		}{
			{3.14159, 3.1},
			{5.55, 5.6},
			{10.04, 10.0},
			{0.0, 0.0},
			{-2.67, -2.7},
		}
		for _, tt := range tests {
			result := roundToOne(tt.input)
			if result != tt.expected {
				t.Errorf("roundToOne(%f) = %f, expected %f", tt.input, result, tt.expected)
			}
		}
	})
}

// TestSummaryRiskAndExploitCalculation verifies that summary queries
// calculate total_risk and exploit_count by multiplying by vulnerability count
func TestSummaryRiskAndExploitCalculation(t *testing.T) {
	t.Run("namespace summary query multiplies risk by count", func(t *testing.T) {
		query, _ := buildNamespaceSummaryQuery(
			nil, nil, nil, nil, "", "ASC", 50, 0,
		)

		// Verify risk calculation uses count multiplier
		if !strings.Contains(query, "SUM(risk * count) as total_risk") {
			t.Error("Expected namespace summary query to calculate total_risk as SUM(risk * count)")
		}

		// Verify exploit calculation uses count multiplier
		if !strings.Contains(query, "SUM(known_exploited * count) as exploit_count") {
			t.Error("Expected namespace summary query to calculate exploit_count as SUM(known_exploited * count)")
		}
	})

	t.Run("distribution summary query multiplies risk by count", func(t *testing.T) {
		query, _ := buildDistributionSummaryQuery(
			nil, nil, nil, nil, "", "ASC", 50, 0,
		)

		// Verify risk calculation uses count multiplier
		if !strings.Contains(query, "SUM(risk * count) as total_risk") {
			t.Error("Expected distribution summary query to calculate total_risk as SUM(risk * count)")
		}

		// Verify exploit calculation uses count multiplier
		if !strings.Contains(query, "SUM(known_exploited * count) as exploit_count") {
			t.Error("Expected distribution summary query to calculate exploit_count as SUM(known_exploited * count)")
		}
	})
}
