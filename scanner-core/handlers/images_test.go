package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

// mockQueryProvider implements ImageQueryProvider for testing
type mockQueryProvider struct {
	queryFunc func(query string) (*database.QueryResult, error)
}

func (m *mockQueryProvider) ExecuteReadOnlyQuery(query string) (*database.QueryResult, error) {
	if m.queryFunc != nil {
		return m.queryFunc(query)
	}
	return &database.QueryResult{
		Columns: []string{},
		Rows:    []map[string]interface{}{},
	}, nil
}

func (m *mockQueryProvider) GetSBOM(digest string) ([]byte, error) {
	return nil, fmt.Errorf("SBOM not available")
}

func (m *mockQueryProvider) GetVulnerabilities(digest string) ([]byte, error) {
	return nil, fmt.Errorf("vulnerabilities not available")
}


// mockFilterOptionsProvider implements FilterOptionsProvider for testing
type mockFilterOptionsProvider struct {
	opts *database.FilterOptions
	err  error
}

func (m *mockFilterOptionsProvider) GetFilterOptions() (*database.FilterOptions, error) {
	return m.opts, m.err
}

func TestFilterOptionsHandler(t *testing.T) {
	tests := []struct {
		name           string
		opts           *database.FilterOptions
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name: "returns filter options successfully",
			opts: &database.FilterOptions{
				Namespaces:   []string{"default", "kube-system"},
				OSNames:      []string{"alpine:3.18", "ubuntu:22.04"},
				VulnStatuses: []string{},
				PackageTypes: []string{},
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var response map[string][]string
				if err := json.Unmarshal([]byte(body), &response); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				if len(response["namespaces"]) != 2 {
					t.Errorf("Expected 2 namespaces, got %d", len(response["namespaces"]))
				}
				if len(response["osNames"]) != 2 {
					t.Errorf("Expected 2 OS names, got %d", len(response["osNames"]))
				}
			},
		},
		{
			name: "handles empty results",
			opts: &database.FilterOptions{
				Namespaces:   []string{},
				OSNames:      []string{},
				VulnStatuses: []string{},
				PackageTypes: []string{},
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var response map[string][]string
				if err := json.Unmarshal([]byte(body), &response); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				// Empty results should still return empty arrays, not nil
				if response["namespaces"] == nil {
					t.Error("Expected empty array for namespaces, got nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockFilterOptionsProvider{opts: tt.opts}

			handler := FilterOptionsHandler(provider)
			req := httptest.NewRequest(http.MethodGet, "/api/filter-options", nil)
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

func TestImagesHandler(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		mockCountFunc  func(query string) (*database.QueryResult, error)
		mockDataFunc   func(query string) (*database.QueryResult, error)
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name:        "basic pagination",
			queryParams: "page=1&pageSize=10",
			mockCountFunc: func(query string) (*database.QueryResult, error) {
				return &database.QueryResult{
					Columns: []string{"COUNT(*)"},
					Rows: []map[string]interface{}{
						{"COUNT(*)": int64(25)},
					},
				}, nil
			},
			mockDataFunc: func(query string) (*database.QueryResult, error) {
				return &database.QueryResult{
					Columns: []string{"image", "digest", "container_count"},
					Rows: []map[string]interface{}{
						{
							"image":          "nginx:latest",
							"digest":         "sha256:abc123",
							"container_count": int64(3),
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
				if response["totalCount"] != float64(25) {
					t.Errorf("Expected totalCount 25, got %v", response["totalCount"])
				}
				if response["totalPages"] != float64(3) {
					t.Errorf("Expected totalPages 3, got %v", response["totalPages"])
				}
			},
		},
		{
			name:        "with search filter",
			queryParams: "search=nginx&page=1&pageSize=50",
			mockCountFunc: func(query string) (*database.QueryResult, error) {
				if !strings.Contains(query, "nginx") {
					t.Error("Expected search term 'nginx' in query")
				}
				return &database.QueryResult{
					Columns: []string{"COUNT(*)"},
					Rows: []map[string]interface{}{
						{"COUNT(*)": int64(5)},
					},
				}, nil
			},
			mockDataFunc: func(query string) (*database.QueryResult, error) {
				if !strings.Contains(query, "nginx") {
					t.Error("Expected search term 'nginx' in query")
				}
				return &database.QueryResult{
					Columns: []string{"image"},
					Rows: []map[string]interface{}{
						{"image": "nginx:latest"},
						{"image": "nginx:1.21"},
					},
				}, nil
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:        "with namespace filter",
			queryParams: "namespaces=default,kube-system",
			mockCountFunc: func(query string) (*database.QueryResult, error) {
				if !strings.Contains(query, "IN ('default','kube-system')") {
					t.Error("Expected namespace filter in query")
				}
				return &database.QueryResult{
					Columns: []string{"COUNT(*)"},
					Rows:    []map[string]interface{}{{"COUNT(*)": int64(10)}},
				}, nil
			},
			mockDataFunc: func(query string) (*database.QueryResult, error) {
				return &database.QueryResult{
					Columns: []string{"image"},
					Rows:    []map[string]interface{}{{"image": "nginx:latest"}},
				}, nil
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:        "CSV export format",
			queryParams: "format=csv&page=1&pageSize=10",
			mockCountFunc: func(query string) (*database.QueryResult, error) {
				return &database.QueryResult{
					Columns: []string{"COUNT(*)"},
					Rows:    []map[string]interface{}{{"COUNT(*)": int64(1)}},
				}, nil
			},
			mockDataFunc: func(query string) (*database.QueryResult, error) {
				// Return data query result, not count
				return &database.QueryResult{
					Columns: []string{"image", "digest", "critical_count"},
					Rows: []map[string]interface{}{
						{
							"image":          "nginx:latest",
							"digest":         "sha256:abc123",
							"critical_count": int64(5),
						},
					},
				}, nil
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				// Parse CSV
				reader := csv.NewReader(strings.NewReader(body))
				records, err := reader.ReadAll()
				if err != nil {
					t.Fatalf("Failed to parse CSV: %v", err)
				}
				if len(records) < 2 { // Header + data rows
					t.Errorf("Expected at least 2 CSV rows, got %d", len(records))
				}
				// Check header - first column should be 'image'
				if len(records[0]) > 0 && records[0][0] != "image" {
					t.Errorf("Expected first column header to be 'image', got '%s'", records[0][0])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callCount := 0
			provider := &mockQueryProvider{
				queryFunc: func(query string) (*database.QueryResult, error) {
					callCount++
					// Check if this is a count query (starts with SELECT COUNT)
					trimmed := strings.TrimSpace(query)
					if strings.HasPrefix(trimmed, "SELECT COUNT(*)") {
						return tt.mockCountFunc(query)
					}
					return tt.mockDataFunc(query)
				},
			}

			handler := ImagesHandler(provider)
			req := httptest.NewRequest(http.MethodGet, "/api/images?"+tt.queryParams, nil)
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

func TestContainersHandler(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		expectedStatus int
		checkQuery     func(t *testing.T, query string)
	}{
		{
			name:           "basic request",
			queryParams:    "page=1&pageSize=20",
			expectedStatus: http.StatusOK,
			checkQuery: func(t *testing.T, query string) {
				if !strings.Contains(query, "LIMIT 20") {
					t.Error("Expected LIMIT 20 in query")
				}
			},
		},
		{
			name:           "with pod search",
			queryParams:    "search=nginx-pod",
			expectedStatus: http.StatusOK,
			checkQuery: func(t *testing.T, query string) {
				if !strings.Contains(query, "nginx-pod") {
					t.Error("Expected pod search term in query")
				}
			},
		},
		{
			name:           "CSV export",
			queryParams:    "format=csv",
			expectedStatus: http.StatusOK,
			checkQuery: func(t *testing.T, query string) {
				// Just check that we get a valid query
				if len(query) == 0 {
					t.Error("Expected non-empty query")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedQuery string
			provider := &mockQueryProvider{
				queryFunc: func(query string) (*database.QueryResult, error) {
					capturedQuery = query
					if strings.Contains(query, "COUNT(*)") {
						return &database.QueryResult{
							Columns: []string{"COUNT(*)"},
							Rows:    []map[string]interface{}{{"COUNT(*)": int64(10)}},
						}, nil
					}
					return &database.QueryResult{
						Columns: []string{"namespace", "pod", "container"},
						Rows: []map[string]interface{}{
							{
								"namespace": "default",
								"pod":       "nginx-pod",
								"container": "nginx",
							},
						},
					}, nil
				},
			}

			handler := ContainersHandler(provider)
			req := httptest.NewRequest(http.MethodGet, "/api/containers?"+tt.queryParams, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			if tt.checkQuery != nil {
				tt.checkQuery(t, capturedQuery)
			}
		})
	}
}

func TestImageDetailFullHandler(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		mockFunc       func(query string) (*database.QueryResult, error)
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name: "successful image detail retrieval",
			path: "/api/images/sha256:abc123",
			mockFunc: func(query string) (*database.QueryResult, error) {
				if strings.Contains(query, "FROM images") {
					// Image query
					return &database.QueryResult{
						Columns: []string{"id", "image_id", "scan_status", "distro_display_name", "status_description"},
						Rows: []map[string]interface{}{
							{
								"id":                  int64(1),
								"image_id":            "sha256:abc123",
								"scan_status":         "completed",
								"distro_display_name": "alpine:3.18",
								"status_description":  "Scan completed",
							},
						},
					}, nil
				} else if strings.Contains(query, "reference") {
					// References query
					return &database.QueryResult{
						Columns: []string{"ref"},
						Rows: []map[string]interface{}{
							{"ref": "nginx:latest"},
							{"ref": "nginx:1.21"},
						},
					}, nil
				} else {
					// Containers query
					return &database.QueryResult{
						Columns: []string{"container"},
						Rows: []map[string]interface{}{
							{"container": "default.nginx-pod.nginx"},
						},
					}, nil
				}
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var response map[string]interface{}
				if err := json.Unmarshal([]byte(body), &response); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				if response["image_id"] != "sha256:abc123" {
					t.Errorf("Expected image_id 'sha256:abc123', got %v", response["image_id"])
				}
				references := response["references"].([]interface{})
				if len(references) != 2 {
					t.Errorf("Expected 2 references, got %d", len(references))
				}
			},
		},
		{
			name: "image not found",
			path: "/api/images/sha256:notfound",
			mockFunc: func(query string) (*database.QueryResult, error) {
				return &database.QueryResult{
					Columns: []string{},
					Rows:    []map[string]interface{}{},
				}, nil
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "missing digest",
			path:           "/api/images/",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockQueryProvider{
				queryFunc: tt.mockFunc,
			}

			handler := ImageDetailFullHandler(provider)
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
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

// TestImageDetailFullHandler_UniqueCVEsDedupedByCVEID verifies that the vuln stats
// query dedupes by cve_id alone — a single CVE affecting multiple (package, version)
// rows in the same image counts as one unique CVE. The same applies to unique_exploits.
func TestImageDetailFullHandler_UniqueCVEsDedupedByCVEID(t *testing.T) {
	var capturedQueries []string
	provider := &mockQueryProvider{
		queryFunc: func(query string) (*database.QueryResult, error) {
			capturedQueries = append(capturedQueries, query)
			switch {
			case strings.Contains(query, "FROM images") && strings.Contains(query, "scan_status"):
				return &database.QueryResult{
					Columns: []string{"id", "image_id", "scan_status", "distro_display_name", "status_description"},
					Rows: []map[string]interface{}{
						{"id": int64(1), "image_id": "sha256:abc", "scan_status": "completed", "distro_display_name": "alpine", "status_description": "ok"},
					},
				}, nil
			case strings.Contains(query, "reference"):
				return &database.QueryResult{
					Columns: []string{"ref"},
					Rows:    []map[string]interface{}{{"ref": "nginx:latest"}},
				}, nil
			case strings.Contains(query, "namespace") || strings.Contains(query, "container"):
				return &database.QueryResult{
					Columns: []string{"container"},
					Rows:    []map[string]interface{}{{"container": "default.foo.bar"}},
				}, nil
			case strings.Contains(query, "unique_cves"):
				// Mock returns 1 unique CVE (e.g. CVE-2023-24531 hitting many packages).
				return &database.QueryResult{
					Columns: []string{"total_risk", "total_cves", "unique_cves", "total_exploits", "unique_exploits", "cves_critical", "cves_high", "cves_medium", "cves_low", "cves_negligible", "cves_unknown"},
					Rows: []map[string]interface{}{
						{"total_risk": float64(0.5), "total_cves": int64(791), "unique_cves": int64(1), "total_exploits": int64(0), "unique_exploits": int64(0), "cves_critical": int64(791), "cves_high": int64(0), "cves_medium": int64(0), "cves_low": int64(0), "cves_negligible": int64(0), "cves_unknown": int64(0)},
					},
				}, nil
			case strings.Contains(query, "unique_packages"):
				return &database.QueryResult{
					Columns: []string{"total_packages", "unique_packages"},
					Rows:    []map[string]interface{}{{"total_packages": int64(265), "unique_packages": int64(265)}},
				}, nil
			}
			return &database.QueryResult{Columns: []string{}, Rows: []map[string]interface{}{}}, nil
		},
	}

	handler := ImageDetailFullHandler(provider)
	req := httptest.NewRequest(http.MethodGet, "/api/images/sha256:abc", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	// Find the vuln-stats query and assert it dedupes by cve_id.
	var vulnQuery string
	for _, q := range capturedQueries {
		if strings.Contains(q, "unique_cves") {
			vulnQuery = q
			break
		}
	}
	if vulnQuery == "" {
		t.Fatal("expected a query selecting unique_cves to be executed")
	}
	if !strings.Contains(vulnQuery, "COUNT(DISTINCT v.cve_id) as unique_cves") {
		t.Errorf("unique_cves must use COUNT(DISTINCT v.cve_id); got query: %s", vulnQuery)
	}
	if !strings.Contains(vulnQuery, "COUNT(DISTINCT CASE WHEN v.known_exploited > 0 THEN v.cve_id END) as unique_exploits") {
		t.Errorf("unique_exploits must use COUNT(DISTINCT ... cve_id ...); got query: %s", vulnQuery)
	}
	if strings.Contains(vulnQuery, "COUNT(*) as unique_cves") {
		t.Errorf("unique_cves must not use COUNT(*); got query: %s", vulnQuery)
	}

	// Sanity-check the response carries the deduped value through.
	var response map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if got := response["unique_cves"]; got != float64(1) {
		t.Errorf("expected unique_cves=1 (deduped), got %v", got)
	}
}

// TestImageStatsHandler_UniqueCVEsDedupedByCVEID is the same dedup assertion
// for the filtered /api/images/{digest}/stats endpoint.
func TestImageStatsHandler_UniqueCVEsDedupedByCVEID(t *testing.T) {
	var capturedQueries []string
	provider := &mockQueryProvider{
		queryFunc: func(query string) (*database.QueryResult, error) {
			capturedQueries = append(capturedQueries, query)
			switch {
			case strings.Contains(query, "unique_cves"):
				return &database.QueryResult{
					Columns: []string{"total_risk", "total_cves", "unique_cves", "total_exploits", "unique_exploits"},
					Rows: []map[string]interface{}{
						{"total_risk": float64(0.5), "total_cves": int64(791), "unique_cves": int64(1), "total_exploits": int64(0), "unique_exploits": int64(0)},
					},
				}, nil
			case strings.Contains(query, "cves_critical"):
				return &database.QueryResult{
					Columns: []string{"cves_critical", "cves_high", "cves_medium", "cves_low", "cves_negligible", "cves_unknown"},
					Rows: []map[string]interface{}{
						{"cves_critical": int64(791), "cves_high": int64(0), "cves_medium": int64(0), "cves_low": int64(0), "cves_negligible": int64(0), "cves_unknown": int64(0)},
					},
				}, nil
			case strings.Contains(query, "unique_packages"):
				return &database.QueryResult{
					Columns: []string{"total_packages", "unique_packages"},
					Rows:    []map[string]interface{}{{"total_packages": int64(265), "unique_packages": int64(265)}},
				}, nil
			}
			return &database.QueryResult{Columns: []string{}, Rows: []map[string]interface{}{}}, nil
		},
	}

	handler := ImageStatsHandler(provider)
	req := httptest.NewRequest(http.MethodGet, "/api/images/sha256:abc/stats", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var vulnQuery string
	for _, q := range capturedQueries {
		if strings.Contains(q, "unique_cves") {
			vulnQuery = q
			break
		}
	}
	if vulnQuery == "" {
		t.Fatal("expected a query selecting unique_cves to be executed")
	}
	if !strings.Contains(vulnQuery, "COUNT(DISTINCT v.cve_id) as unique_cves") {
		t.Errorf("unique_cves must use COUNT(DISTINCT v.cve_id); got query: %s", vulnQuery)
	}
	if !strings.Contains(vulnQuery, "COUNT(DISTINCT CASE WHEN v.known_exploited > 0 THEN v.cve_id END) as unique_exploits") {
		t.Errorf("unique_exploits must use COUNT(DISTINCT ... cve_id ...); got query: %s", vulnQuery)
	}
	if strings.Contains(vulnQuery, "COUNT(*) as unique_cves") {
		t.Errorf("unique_cves must not use COUNT(*); got query: %s", vulnQuery)
	}
}

func TestImageVulnerabilitiesDetailHandler(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		mockFunc       func(query string) (*database.QueryResult, error)
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name: "successful vulnerability retrieval",
			path: "/api/images/sha256:abc123/vulnerabilities",
			mockFunc: func(query string) (*database.QueryResult, error) {
				if strings.Contains(query, "COUNT(*)") {
					return &database.QueryResult{
						Columns: []string{"COUNT(*)"},
						Rows:    []map[string]interface{}{{"COUNT(*)": int64(10)}},
					}, nil
				}
				return &database.QueryResult{
					Columns: []string{"vulnerability_id", "vulnerability_severity", "artifact_name"},
					Rows: []map[string]interface{}{
						{
							"vulnerability_id":       "CVE-2023-1234",
							"vulnerability_severity": "Critical",
							"artifact_name":          "openssl",
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
				vulns := response["vulnerabilities"].([]interface{})
				if len(vulns) != 1 {
					t.Errorf("Expected 1 vulnerability, got %d", len(vulns))
				}
			},
		},
		{
			name: "with severity filter",
			path: "/api/images/sha256:abc123/vulnerabilities?severity=Critical,High",
			mockFunc: func(query string) (*database.QueryResult, error) {
				if !strings.Contains(query, "severity IN ('Critical','High')") {
					t.Error("Expected severity filter in query")
				}
				if strings.Contains(query, "COUNT(*)") {
					return &database.QueryResult{
						Columns: []string{"COUNT(*)"},
						Rows:    []map[string]interface{}{{"COUNT(*)": int64(5)}},
					}, nil
				}
				return &database.QueryResult{
					Columns: []string{"vulnerability_severity"},
					Rows:    []map[string]interface{}{},
				}, nil
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid path",
			path:           "/api/images/sha256:abc123",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockQueryProvider{
				queryFunc: tt.mockFunc,
			}

			handler := ImageVulnerabilitiesDetailHandler(provider)
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
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

func TestImagePackagesDetailHandler(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		mockFunc       func(query string) (*database.QueryResult, error)
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name: "successful package retrieval",
			path: "/api/images/sha256:abc123/packages",
			mockFunc: func(query string) (*database.QueryResult, error) {
				if strings.Contains(query, "COUNT(*)") {
					return &database.QueryResult{
						Columns: []string{"COUNT(*)"},
						Rows:    []map[string]interface{}{{"COUNT(*)": int64(100)}},
					}, nil
				}
				return &database.QueryResult{
					Columns: []string{"name", "version", "type"},
					Rows: []map[string]interface{}{
						{
							"name":    "openssl",
							"version": "3.0.0",
							"type":    "apk",
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
				packages := response["packages"].([]interface{})
				if len(packages) != 1 {
					t.Errorf("Expected 1 package, got %d", len(packages))
				}
			},
		},
		{
			name: "with type filter",
			path: "/api/images/sha256:abc123/packages?type=apk,deb",
			mockFunc: func(query string) (*database.QueryResult, error) {
				if !strings.Contains(query, "type IN ('apk','deb')") {
					t.Error("Expected type filter in query")
				}
				if strings.Contains(query, "COUNT(*)") {
					return &database.QueryResult{
						Columns: []string{"COUNT(*)"},
						Rows:    []map[string]interface{}{{"COUNT(*)": int64(50)}},
					}, nil
				}
				return &database.QueryResult{
					Columns: []string{"type"},
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

			handler := ImagePackagesDetailHandler(provider)
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
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

func TestVulnerabilityDetailsHandler(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		mockFunc       func(query string) (*database.QueryResult, error)
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name: "successful details retrieval",
			path: "/api/vulnerabilities/123/details",
			mockFunc: func(query string) (*database.QueryResult, error) {
				if !strings.Contains(query, "vulnerability_id = 123") {
					t.Error("Expected vulnerability_id 123 in query")
				}
				return &database.QueryResult{
					Columns: []string{"details"},
					Rows: []map[string]interface{}{
						{"details": `{"cve":"CVE-2023-1234","severity":"Critical"}`},
					},
				}, nil
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var details map[string]interface{}
				if err := json.Unmarshal([]byte(body), &details); err != nil {
					t.Fatalf("Failed to parse JSON: %v", err)
				}
				if details["cve"] != "CVE-2023-1234" {
					t.Errorf("Expected CVE-2023-1234, got %v", details["cve"])
				}
			},
		},
		{
			name: "vulnerability not found",
			path: "/api/vulnerabilities/999/details",
			mockFunc: func(query string) (*database.QueryResult, error) {
				return &database.QueryResult{
					Columns: []string{"details"},
					Rows:    []map[string]interface{}{},
				}, nil
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "invalid path - too short",
			path:           "/api/vulnerabilities/",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid ID format",
			path:           "/api/vulnerabilities/abc/details",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockQueryProvider{
				queryFunc: tt.mockFunc,
			}

			handler := VulnerabilityDetailsHandler(provider)
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
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

func TestPackageDetailsHandler(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		mockFunc       func(query string) (*database.QueryResult, error)
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name: "successful details retrieval",
			path: "/api/packages/456/details",
			mockFunc: func(query string) (*database.QueryResult, error) {
				if !strings.Contains(query, "package_id = 456") {
					t.Error("Expected package_id 456 in query")
				}
				return &database.QueryResult{
					Columns: []string{"details"},
					Rows: []map[string]interface{}{
						{"details": `{"name":"openssl","version":"3.0.0"}`},
					},
				}, nil
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var details map[string]interface{}
				if err := json.Unmarshal([]byte(body), &details); err != nil {
					t.Fatalf("Failed to parse JSON: %v", err)
				}
				if details["name"] != "openssl" {
					t.Errorf("Expected openssl, got %v", details["name"])
				}
			},
		},
		{
			name: "package not found",
			path: "/api/packages/999/details",
			mockFunc: func(query string) (*database.QueryResult, error) {
				return &database.QueryResult{
					Columns: []string{"details"},
					Rows:    []map[string]interface{}{},
				}, nil
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "invalid path - too short",
			path:           "/api/packages/",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockQueryProvider{
				queryFunc: tt.mockFunc,
			}

			handler := PackageDetailsHandler(provider)
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
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

func TestParseMultiSelect(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "single value",
			input:    "default",
			expected: []string{"default"},
		},
		{
			name:     "multiple values",
			input:    "default,kube-system,monitoring",
			expected: []string{"default", "kube-system", "monitoring"},
		},
		{
			name:     "with spaces",
			input:    "default, kube-system , monitoring",
			expected: []string{"default", "kube-system", "monitoring"},
		},
		{
			name:     "empty string",
			input:    "",
			expected: nil,
		},
		{
			name:     "only commas and spaces",
			input:    " , , ",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseMultiSelect(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d values, got %d", len(tt.expected), len(result))
				return
			}
			for i, expected := range tt.expected {
				if result[i] != expected {
					t.Errorf("Expected value[%d] = %s, got %s", i, expected, result[i])
				}
			}
		})
	}
}

func TestBuildImagesQuery(t *testing.T) {
	tests := []struct {
		name            string
		search          string
		namespaces      []string
		vulnStatuses    []string
		packageTypes    []string
		osNames         []string
		sortBy          string
		sortOrder       string
		expectedInQuery []string
	}{
		{
			name:            "with search term",
			search:          "nginx",
			expectedInQuery: []string{"nginx", "LIKE"},
		},
		{
			name:            "with namespace filter",
			namespaces:      []string{"default", "kube-system"},
			expectedInQuery: []string{"instances.namespace IN ('default','kube-system')"},
		},
		{
			name:            "with vulnerability status filter",
			vulnStatuses:    []string{"fixed", "not-fixed"},
			expectedInQuery: []string{"fix_status IN ('fixed','not-fixed')"},
		},
		{
			name:            "with package type filter",
			packageTypes:    []string{"apk", "deb"},
			expectedInQuery: []string{"type IN ('apk','deb')"},
		},
		{
			name:            "with OS name filter",
			osNames:         []string{"alpine:3.18", "ubuntu:22.04"},
			expectedInQuery: []string{"images.os_name IN ('alpine:3.18','ubuntu:22.04')"},
		},
		{
			name:            "with custom sort",
			sortBy:          "critical_count",
			sortOrder:       "DESC",
			expectedInQuery: []string{"ORDER BY status.sort_order ASC, critical_count DESC"},
		},
		{
			name:            "SQL injection attempt - search",
			search:          "'; DROP TABLE images; --",
			expectedInQuery: []string{"''; DROP TABLE images; --"}, // Should be escaped
		},
		{
			name:            "SQL injection attempt - namespace",
			namespaces:      []string{"' OR '1'='1"},
			expectedInQuery: []string{"''' OR ''1''=''1'"}, // Single quotes are escaped by doubling
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mainQuery, countQuery := buildImagesQuery(
				tt.search,
				tt.namespaces,
				tt.vulnStatuses,
				tt.packageTypes,
				tt.osNames,
				tt.sortBy,
				tt.sortOrder,
				50,
				0,
			)

			// Check that expected strings are in the query
			for _, expected := range tt.expectedInQuery {
				if !strings.Contains(mainQuery, expected) && !strings.Contains(countQuery, expected) {
					t.Errorf("Expected query to contain '%s'\nMain query: %s\nCount query: %s",
						expected, mainQuery, countQuery)
				}
			}

			// Basic sanity checks
			if !strings.Contains(mainQuery, "LIMIT 50") {
				t.Error("Expected LIMIT in main query")
			}
			if !strings.Contains(countQuery, "COUNT(*)") {
				t.Error("Expected COUNT(*) in count query")
			}
		})
	}
}

func TestBuildContainersQuery(t *testing.T) {
	tests := []struct {
		name            string
		search          string
		namespaces      []string
		expectedInQuery []string
	}{
		{
			name:            "with pod search",
			search:          "nginx-pod",
			expectedInQuery: []string{"nginx-pod", "instances.namespace LIKE", "instances.pod LIKE", "instances.name LIKE"},
		},
		{
			name:            "basic query",
			expectedInQuery: []string{"containers instances", "images images"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mainQuery, _ := buildContainersQuery(
				tt.search,
				tt.namespaces,
				nil,
				nil,
				nil,
				"",
				"ASC",
				50,
				0,
			)

			for _, expected := range tt.expectedInQuery {
				if !strings.Contains(mainQuery, expected) {
					t.Errorf("Expected query to contain '%s'\nQuery: %s", expected, mainQuery)
				}
			}
		})
	}
}

// TestRiskAndExploitCalculation verifies that total_risk and exploit_count
// are calculated by multiplying by vulnerability count (for consistency with metrics)
func TestRiskAndExploitCalculation(t *testing.T) {
	t.Run("images query multiplies risk by count", func(t *testing.T) {
		mainQuery, _ := buildImagesQuery(
			"", nil, nil, nil, nil, "", "ASC", 50, 0,
		)

		// Verify risk calculation uses count multiplier
		if !strings.Contains(mainQuery, "SUM(risk * count) as total_risk") {
			t.Error("Expected images query to calculate total_risk as SUM(risk * count)")
		}

		// Verify exploit calculation uses count multiplier
		if !strings.Contains(mainQuery, "SUM(known_exploited * count) as exploit_count") {
			t.Error("Expected images query to calculate exploit_count as SUM(known_exploited * count)")
		}
	})

	t.Run("containers query multiplies risk by count", func(t *testing.T) {
		mainQuery, _ := buildContainersQuery(
			"", nil, nil, nil, nil, "", "ASC", 50, 0,
		)

		// Verify risk calculation uses count multiplier
		if !strings.Contains(mainQuery, "SUM(risk * count) as total_risk") {
			t.Error("Expected containers query to calculate total_risk as SUM(risk * count)")
		}

		// Verify exploit calculation uses count multiplier
		if !strings.Contains(mainQuery, "SUM(known_exploited * count) as exploit_count") {
			t.Error("Expected containers query to calculate exploit_count as SUM(known_exploited * count)")
		}
	})
}

