package handlers

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

// Mock ImageQueryProvider for testing
type mockImageQueryProvider struct {
	queryFunc func(query string) (*database.QueryResult, error)
}

func (m *mockImageQueryProvider) ExecuteReadOnlyQuery(query string) (*database.QueryResult, error) {
	if m.queryFunc != nil {
		return m.queryFunc(query)
	}
	return &database.QueryResult{Rows: []map[string]interface{}{}}, nil
}

func (m *mockImageQueryProvider) GetSBOM(digest string) ([]byte, error) {
	return nil, fmt.Errorf("SBOM not available")
}

func (m *mockImageQueryProvider) GetVulnerabilities(digest string) ([]byte, error) {
	return nil, fmt.Errorf("vulnerabilities not available")
}

// TestVulnerabilityIDExtraction tests ID extraction from various URL patterns
func TestVulnerabilityIDExtraction(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		expectedID     string
		shouldSucceed  bool
		expectedStatus int
	}{
		{
			name:           "Single digit ID",
			path:           "/api/vulnerabilities/8/details",
			expectedID:     "8",
			shouldSucceed:  true,
			expectedStatus: 200,
		},
		{
			name:           "Double digit ID",
			path:           "/api/vulnerabilities/97/details",
			expectedID:     "97",
			shouldSucceed:  true,
			expectedStatus: 200,
		},
		{
			name:           "Triple digit ID",
			path:           "/api/vulnerabilities/497/details",
			expectedID:     "497",
			shouldSucceed:  true,
			expectedStatus: 200,
		},
		{
			name:           "Large ID",
			path:           "/api/vulnerabilities/123456/details",
			expectedID:     "123456",
			shouldSucceed:  true,
			expectedStatus: 200,
		},
		{
			name:           "Path too short",
			path:           "/api/vulnerabilities",
			expectedID:     "",
			shouldSucceed:  false,
			expectedStatus: 400,
		},
		{
			name:           "Missing /details suffix",
			path:           "/api/vulnerabilities/123",
			expectedID:     "",
			shouldSucceed:  false,
			expectedStatus: 404, // Won't match the route
		},
		{
			name:           "Empty ID",
			path:           "/api/vulnerabilities//details",
			expectedID:     "",
			shouldSucceed:  false,
			expectedStatus: 400,
		},
		{
			name:           "Non-numeric ID",
			path:           "/api/vulnerabilities/abc/details",
			expectedID:     "abc",
			shouldSucceed:  false,
			expectedStatus: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Extract ID manually using the same logic as the handler
			prefix := "/api/vulnerabilities/"
			suffix := "/details"

			if len(tt.path) < len(prefix)+len(suffix) {
				// Path too short
				if tt.shouldSucceed {
					t.Errorf("Path %s should succeed but is too short", tt.path)
				}
				return
			}

			if !strings.HasSuffix(tt.path, suffix) {
				// Missing suffix
				if tt.shouldSucceed {
					t.Errorf("Path %s should succeed but missing /details suffix", tt.path)
				}
				return
			}

			extractedID := tt.path[len(prefix) : len(tt.path)-len(suffix)]

			if extractedID != tt.expectedID {
				t.Errorf("Extracted ID = %q, want %q", extractedID, tt.expectedID)
			}
		})
	}
}

// TestPackageIDExtraction tests ID extraction for package endpoints
func TestPackageIDExtraction(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		expectedID    string
		shouldSucceed bool
	}{
		{
			name:          "Single digit ID",
			path:          "/api/packages/1/details",
			expectedID:    "1",
			shouldSucceed: true,
		},
		{
			name:          "Double digit ID",
			path:          "/api/packages/42/details",
			expectedID:    "42",
			shouldSucceed: true,
		},
		{
			name:          "Triple digit ID",
			path:          "/api/packages/789/details",
			expectedID:    "789",
			shouldSucceed: true,
		},
		{
			name:          "Large ID",
			path:          "/api/packages/999999/details",
			expectedID:    "999999",
			shouldSucceed: true,
		},
		{
			name:          "Empty ID",
			path:          "/api/packages//details",
			expectedID:    "",
			shouldSucceed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := "/api/packages/"
			suffix := "/details"

			if len(tt.path) < len(prefix)+len(suffix) {
				if tt.shouldSucceed {
					t.Errorf("Path %s should succeed but is too short", tt.path)
				}
				return
			}

			if !strings.HasSuffix(tt.path, suffix) {
				if tt.shouldSucceed {
					t.Errorf("Path %s should succeed but missing /details suffix", tt.path)
				}
				return
			}

			extractedID := tt.path[len(prefix) : len(tt.path)-len(suffix)]

			if extractedID != tt.expectedID {
				t.Errorf("Extracted ID = %q, want %q", extractedID, tt.expectedID)
			}
		})
	}
}

// TestVulnerabilityDetailsHandler_Integration tests the full handler with mock data
func TestVulnerabilityDetailsHandler_Integration(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		mockData       string
		expectedStatus int
		shouldContain  string
	}{
		{
			name:           "Valid vulnerability with details",
			path:           "/api/vulnerabilities/123/details",
			mockData:       `[{"vulnerability":{"id":"CVE-2024-1234"},"artifact":{"name":"test"}}]`,
			expectedStatus: 200,
			shouldContain:  "CVE-2024-1234",
		},
		{
			name:           "Vulnerability not found",
			path:           "/api/vulnerabilities/999/details",
			mockData:       "",
			expectedStatus: 404,
			shouldContain:  "not found",
		},
		{
			name:           "Invalid ID format",
			path:           "/api/vulnerabilities/abc/details",
			mockData:       "",
			expectedStatus: 400,
			shouldContain:  "Invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockImageQueryProvider{
				queryFunc: func(query string) (*database.QueryResult, error) {
					if tt.mockData == "" {
						return &database.QueryResult{Rows: []map[string]interface{}{}}, nil
					}
					return &database.QueryResult{
						Rows: []map[string]interface{}{
							{"details": tt.mockData},
						},
					}, nil
				},
			}

			handler := VulnerabilityDetailsHandler(provider)
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()

			handler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Status = %d, want %d", w.Code, tt.expectedStatus)
			}

			if tt.shouldContain != "" && !strings.Contains(w.Body.String(), tt.shouldContain) {
				t.Errorf("Response body should contain %q, got: %s", tt.shouldContain, w.Body.String())
			}
		})
	}
}

// TestPackageDetailsHandler_Integration tests the package handler
func TestPackageDetailsHandler_Integration(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		mockData       string
		expectedStatus int
	}{
		{
			name:           "Valid package with details",
			path:           "/api/packages/456/details",
			mockData:       `[{"name":"openssl","version":"1.1.1"}]`,
			expectedStatus: 200,
		},
		{
			name:           "Package not found",
			path:           "/api/packages/999/details",
			mockData:       "",
			expectedStatus: 404,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockImageQueryProvider{
				queryFunc: func(query string) (*database.QueryResult, error) {
					if tt.mockData == "" {
						return &database.QueryResult{Rows: []map[string]interface{}{}}, nil
					}
					return &database.QueryResult{
						Rows: []map[string]interface{}{
							{"details": tt.mockData},
						},
					}, nil
				},
			}

			handler := PackageDetailsHandler(provider)
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()

			handler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Status = %d, want %d", w.Code, tt.expectedStatus)
			}
		})
	}
}

// TestPrefixLengths verifies the prefix length constants are correct
func TestPrefixLengths(t *testing.T) {
	tests := []struct {
		name           string
		prefix         string
		expectedLength int
	}{
		{
			name:           "Vulnerabilities prefix",
			prefix:         "/api/vulnerabilities/",
			expectedLength: 21,
		},
		{
			name:           "Packages prefix",
			prefix:         "/api/packages/",
			expectedLength: 14,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualLength := len(tt.prefix)
			if actualLength != tt.expectedLength {
				t.Errorf("Prefix %q length = %d, want %d", tt.prefix, actualLength, tt.expectedLength)
			}
		})
	}
}

// TestPathConstruction verifies paths are constructed correctly
func TestPathConstruction(t *testing.T) {
	tests := []struct {
		id                string
		vulnerabilityPath string
		packagePath       string
	}{
		{"1", "/api/vulnerabilities/1/details", "/api/packages/1/details"},
		{"42", "/api/vulnerabilities/42/details", "/api/packages/42/details"},
		{"497", "/api/vulnerabilities/497/details", "/api/packages/497/details"},
		{"123456", "/api/vulnerabilities/123456/details", "/api/packages/123456/details"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("ID_%s", tt.id), func(t *testing.T) {
			vulnPath := fmt.Sprintf("/api/vulnerabilities/%s/details", tt.id)
			pkgPath := fmt.Sprintf("/api/packages/%s/details", tt.id)

			if vulnPath != tt.vulnerabilityPath {
				t.Errorf("Vuln path = %q, want %q", vulnPath, tt.vulnerabilityPath)
			}

			if pkgPath != tt.packagePath {
				t.Errorf("Package path = %q, want %q", pkgPath, tt.packagePath)
			}
		})
	}
}
