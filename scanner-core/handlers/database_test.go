package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

// mockDatabaseProvider implements DatabaseProvider for testing
type mockDatabaseProvider struct {
	getAllInstancesFunc           func() (interface{}, error)
	getAllImagesFunc              func() (interface{}, error)
	getAllImageDetailsFunc        func() (interface{}, error)
	getImageDetailsFunc           func(digest string) (interface{}, error)
	getPackagesByImageFunc        func(digest string) (interface{}, error)
	getVulnerabilitiesByImageFunc func(digest string) (interface{}, error)
	getImageSummaryFunc           func(digest string) (interface{}, error)
	getSBOMFunc                   func(digest string) ([]byte, error)
	getVulnerabilitiesFunc        func(digest string) ([]byte, error)
}

func (m *mockDatabaseProvider) GetAllContainers() (interface{}, error) {
	if m.getAllInstancesFunc != nil {
		return m.getAllInstancesFunc()
	}
	return []map[string]interface{}{}, nil
}

func (m *mockDatabaseProvider) GetAllImages() (interface{}, error) {
	if m.getAllImagesFunc != nil {
		return m.getAllImagesFunc()
	}
	return []map[string]interface{}{}, nil
}

func (m *mockDatabaseProvider) GetAllImageDetails() (interface{}, error) {
	if m.getAllImageDetailsFunc != nil {
		return m.getAllImageDetailsFunc()
	}
	return []map[string]interface{}{}, nil
}

func (m *mockDatabaseProvider) GetImageDetails(digest string) (interface{}, error) {
	if m.getImageDetailsFunc != nil {
		return m.getImageDetailsFunc(digest)
	}
	return map[string]interface{}{}, nil
}

func (m *mockDatabaseProvider) GetPackagesByImage(digest string) (interface{}, error) {
	if m.getPackagesByImageFunc != nil {
		return m.getPackagesByImageFunc(digest)
	}
	return []map[string]interface{}{}, nil
}

func (m *mockDatabaseProvider) GetVulnerabilitiesByImage(digest string) (interface{}, error) {
	if m.getVulnerabilitiesByImageFunc != nil {
		return m.getVulnerabilitiesByImageFunc(digest)
	}
	return []map[string]interface{}{}, nil
}

func (m *mockDatabaseProvider) GetImageSummary(digest string) (interface{}, error) {
	if m.getImageSummaryFunc != nil {
		return m.getImageSummaryFunc(digest)
	}
	return map[string]interface{}{}, nil
}

func (m *mockDatabaseProvider) GetSBOM(digest string) ([]byte, error) {
	if m.getSBOMFunc != nil {
		return m.getSBOMFunc(digest)
	}
	return []byte("{}"), nil
}

func (m *mockDatabaseProvider) GetVulnerabilities(digest string) ([]byte, error) {
	if m.getVulnerabilitiesFunc != nil {
		return m.getVulnerabilitiesFunc(digest)
	}
	return []byte("{}"), nil
}

// combinedTestProvider implements both DatabaseProvider and ImageQueryProvider.
// Explicit forwarding methods resolve the ambiguity from embedding both mocks.
type combinedTestProvider struct {
	*mockDatabaseProvider
	*mockQueryProvider
}

func (p *combinedTestProvider) GetSBOM(digest string) ([]byte, error) {
	return p.mockDatabaseProvider.GetSBOM(digest)
}

func (p *combinedTestProvider) GetVulnerabilities(digest string) ([]byte, error) {
	return p.mockDatabaseProvider.GetVulnerabilities(digest)
}

func TestDatabaseImagesHandler(t *testing.T) {
	tests := []struct {
		name           string
		mockFunc       func() (interface{}, error)
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name: "returns images successfully",
			mockFunc: func() (interface{}, error) {
				return []map[string]interface{}{
					{
						"id":     int64(1),
						"digest": "sha256:abc123",
						"status": "completed",
					},
					{
						"id":     int64(2),
						"digest": "sha256:def456",
						"status": "pending",
					},
				}, nil
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var response map[string]interface{}
				if err := json.Unmarshal([]byte(body), &response); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				images := response["images"].([]interface{})
				if len(images) != 2 {
					t.Errorf("Expected 2 images, got %d", len(images))
				}
			},
		},
		{
			name: "handles error",
			mockFunc: func() (interface{}, error) {
				return nil, errors.New("query failed")
			},
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockDatabaseProvider{
				getAllImagesFunc: tt.mockFunc,
			}

			handler := DatabaseImagesHandler(provider)
			req := httptest.NewRequest(http.MethodGet, "/api/containers/images", nil)
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

func TestSBOMDownloadHandler(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		mockFunc       func(digest string) ([]byte, error)
		expectedStatus int
		checkResponse  func(t *testing.T, rec *httptest.ResponseRecorder)
	}{
		{
			name: "successful download",
			path: "/api/sbom/sha256:abc123",
			mockFunc: func(digest string) ([]byte, error) {
				if digest != "sha256:abc123" {
					t.Errorf("Expected digest 'sha256:abc123', got '%s'", digest)
				}
				return []byte(`{"packages":[{"name":"openssl"}]}`), nil
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, rec *httptest.ResponseRecorder) {
				contentType := rec.Header().Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
				}
				disposition := rec.Header().Get("Content-Disposition")
				if !strings.Contains(disposition, "attachment") {
					t.Error("Expected Content-Disposition to contain 'attachment'")
				}
				if !strings.Contains(disposition, "sbom_") {
					t.Error("Expected filename to start with 'sbom_'")
				}
			},
		},
		{
			name: "SBOM not found",
			path: "/api/sbom/sha256:notfound",
			mockFunc: func(digest string) ([]byte, error) {
				return nil, errors.New("not found")
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "missing digest",
			path:           "/api/sbom/",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockDatabaseProvider{
				getSBOMFunc: tt.mockFunc,
			}

			handler := SBOMDownloadHandler(provider)
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, rec)
			}
		})
	}
}

func TestVulnerabilitiesDownloadHandler(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		mockFunc       func(digest string) ([]byte, error)
		expectedStatus int
		checkResponse  func(t *testing.T, rec *httptest.ResponseRecorder)
	}{
		{
			name: "successful download",
			path: "/api/vulnerabilities/sha256:abc123",
			mockFunc: func(digest string) ([]byte, error) {
				if digest != "sha256:abc123" {
					t.Errorf("Expected digest 'sha256:abc123', got '%s'", digest)
				}
				return []byte(`{"matches":[{"vulnerability":{"id":"CVE-2023-1234"}}]}`), nil
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, rec *httptest.ResponseRecorder) {
				contentType := rec.Header().Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("Expected Content-Type 'application/json', got '%s'", contentType)
				}
				disposition := rec.Header().Get("Content-Disposition")
				if !strings.Contains(disposition, "vulnerabilities_") {
					t.Error("Expected filename to start with 'vulnerabilities_'")
				}
			},
		},
		{
			name: "vulnerabilities not found",
			path: "/api/vulnerabilities/sha256:notfound",
			mockFunc: func(digest string) ([]byte, error) {
				return nil, errors.New("not found")
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "missing digest",
			path:           "/api/vulnerabilities/",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockDatabaseProvider{
				getVulnerabilitiesFunc: tt.mockFunc,
			}

			handler := VulnerabilitiesDownloadHandler(provider)
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, rec.Code)
			}

			if tt.checkResponse != nil {
				tt.checkResponse(t, rec)
			}
		})
	}
}

func TestImageDetailsHandler(t *testing.T) {
	tests := []struct {
		name           string
		mockFunc       func() (interface{}, error)
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name: "returns image details successfully",
			mockFunc: func() (interface{}, error) {
				return []map[string]interface{}{
					{
						"digest":          "sha256:abc123",
						"critical_count":  int64(5),
						"high_count":      int64(10),
						"medium_count":    int64(20),
						"package_count":   int64(150),
						"status":          "completed",
					},
				}, nil
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var response map[string]interface{}
				if err := json.Unmarshal([]byte(body), &response); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				images := response["images"].([]interface{})
				if len(images) != 1 {
					t.Errorf("Expected 1 image, got %d", len(images))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockDatabaseProvider{
				getAllImageDetailsFunc: tt.mockFunc,
			}

			handler := ImageDetailsHandler(provider)
			req := httptest.NewRequest(http.MethodGet, "/api/images", nil)
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

func TestImageDetailHandler(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		mockFunc       func(digest string) (interface{}, error)
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name: "returns specific image detail",
			path: "/api/images/sha256:abc123",
			mockFunc: func(digest string) (interface{}, error) {
				if digest != "sha256:abc123" {
					t.Errorf("Expected digest 'sha256:abc123', got '%s'", digest)
				}
				return map[string]interface{}{
					"digest":         "sha256:abc123",
					"critical_count": int64(5),
					"status":         "completed",
				}, nil
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var response map[string]interface{}
				if err := json.Unmarshal([]byte(body), &response); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				if response["digest"] != "sha256:abc123" {
					t.Errorf("Expected digest 'sha256:abc123', got %v", response["digest"])
				}
			},
		},
		{
			name: "image not found",
			path: "/api/images/sha256:notfound",
			mockFunc: func(digest string) (interface{}, error) {
				return nil, errors.New("not found")
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
			provider := &mockDatabaseProvider{
				getImageDetailsFunc: tt.mockFunc,
			}

			handler := ImageDetailHandler(provider)
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

func TestPackagesHandler(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		mockFunc       func(digest string) (interface{}, error)
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name: "returns packages successfully",
			path: "/api/images/sha256:abc123/packages",
			mockFunc: func(digest string) (interface{}, error) {
				if digest != "sha256:abc123" {
					t.Errorf("Expected digest 'sha256:abc123', got '%s'", digest)
				}
				return []map[string]interface{}{
					{
						"name":    "openssl",
						"version": "3.0.0",
						"type":    "apk",
					},
					{
						"name":    "curl",
						"version": "7.88.1",
						"type":    "apk",
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
				if len(packages) != 2 {
					t.Errorf("Expected 2 packages, got %d", len(packages))
				}
			},
		},
		{
			name: "packages not found",
			path: "/api/images/sha256:notfound/packages",
			mockFunc: func(digest string) (interface{}, error) {
				return nil, errors.New("not found")
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "invalid path - missing /packages suffix",
			path:           "/api/images/sha256:abc123",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockDatabaseProvider{
				getPackagesByImageFunc: tt.mockFunc,
			}

			handler := PackagesHandler(provider)
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

func TestVulnerabilitiesHandler(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		mockFunc       func(digest string) (interface{}, error)
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name: "returns vulnerabilities successfully",
			path: "/api/images/sha256:abc123/vulnerabilities",
			mockFunc: func(digest string) (interface{}, error) {
				if digest != "sha256:abc123" {
					t.Errorf("Expected digest 'sha256:abc123', got '%s'", digest)
				}
				return []map[string]interface{}{
					{
						"cve_id":   "CVE-2023-1234",
						"severity": "Critical",
						"package":  "openssl",
					},
					{
						"cve_id":   "CVE-2023-5678",
						"severity": "High",
						"package":  "curl",
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
				if len(vulns) != 2 {
					t.Errorf("Expected 2 vulnerabilities, got %d", len(vulns))
				}
			},
		},
		{
			name: "vulnerabilities not found",
			path: "/api/images/sha256:notfound/vulnerabilities",
			mockFunc: func(digest string) (interface{}, error) {
				return nil, errors.New("not found")
			},
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "invalid path - missing /vulnerabilities suffix",
			path:           "/api/images/sha256:abc123",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockDatabaseProvider{
				getVulnerabilitiesByImageFunc: tt.mockFunc,
			}

			handler := VulnerabilitiesHandler(provider)
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

func TestRegisterDatabaseHandlers(t *testing.T) {
	t.Run("registers handlers without overrides", func(t *testing.T) {
		mux := http.NewServeMux()
		provider := &mockDatabaseProvider{}

		RegisterDatabaseHandlers(mux, provider, nil)

		// Test that handlers are registered by making requests
		tests := []struct {
			path           string
			expectedStatus int
		}{
			{"/api/containers/images", http.StatusOK},
			{"/api/sbom/sha256:test", http.StatusNotFound}, // Will fail to find but handler exists
		}

		for _, tt := range tests {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			// Just check that the handler is registered (not 404)
			if rec.Code == http.StatusNotFound && tt.path != "/api/sbom/sha256:test" {
				t.Errorf("Handler not registered for path %s", tt.path)
			}
		}
	})

	t.Run("uses custom overrides", func(t *testing.T) {
		mux := http.NewServeMux()
		provider := &mockDatabaseProvider{}

		customSBOMCalled := false
		customVulnCalled := false

		overrides := &HandlerOverrides{
			SBOMHandler: func(w http.ResponseWriter, r *http.Request) {
				customSBOMCalled = true
				w.WriteHeader(http.StatusOK)
			},
			VulnerabilitiesHandler: func(w http.ResponseWriter, r *http.Request) {
				customVulnCalled = true
				w.WriteHeader(http.StatusOK)
			},
		}

		RegisterDatabaseHandlers(mux, provider, overrides)

		// Test custom SBOM handler
		req := httptest.NewRequest(http.MethodGet, "/api/sbom/sha256:test", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if !customSBOMCalled {
			t.Error("Custom SBOM handler was not called")
		}

		// Test custom vulnerabilities handler
		req = httptest.NewRequest(http.MethodGet, "/api/vulnerabilities/sha256:test", nil)
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if !customVulnCalled {
			t.Error("Custom vulnerabilities handler was not called")
		}
	})

	t.Run("uses ImageQueryProvider when available", func(t *testing.T) {
		mux := http.NewServeMux()

		provider := &combinedTestProvider{
			mockDatabaseProvider: &mockDatabaseProvider{},
			mockQueryProvider: &mockQueryProvider{
				queryFunc: func(query string) (*database.QueryResult, error) {
					return &database.QueryResult{
						Columns: []string{"id"},
						Rows:    []map[string]interface{}{},
					}, nil
				},
			},
		}

		RegisterDatabaseHandlers(mux, provider, nil)

		// The /api/images handler should use ImagesHandler (with pagination)
		// instead of ImageDetailsHandler
		req := httptest.NewRequest(http.MethodGet, "/api/images?page=1&pageSize=10", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		// Verify we get a valid JSON response
		var response map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Errorf("Failed to unmarshal response: %v", err)
		}
	})
}
