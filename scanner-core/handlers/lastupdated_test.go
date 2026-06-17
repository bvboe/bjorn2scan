package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Mock LastUpdatedProvider for testing
type mockLastUpdatedProvider struct {
	timestamp string
	err       error
}

func (m *mockLastUpdatedProvider) GetLastUpdatedTimestamp(dataType string) (string, error) {
	return m.timestamp, m.err
}

func TestLastUpdatedHandler(t *testing.T) {
	tests := []struct {
		name           string
		dataType       string
		mockTimestamp  string
		mockError      error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "successful request without datatype",
			dataType:       "",
			mockTimestamp:  "2025-12-24T17:30:45Z",
			mockError:      nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "2025-12-24T17:30:45Z",
		},
		{
			name:           "successful request with datatype=image",
			dataType:       "image",
			mockTimestamp:  "2025-12-24T17:30:45Z",
			mockError:      nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "2025-12-24T17:30:45Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockLastUpdatedProvider{
				timestamp: tt.mockTimestamp,
				err:       tt.mockError,
			}

			handler := LastUpdatedHandler(provider)

			// Create request
			url := "/api/lastupdated"
			if tt.dataType != "" {
				url += "?datatype=" + tt.dataType
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			w := httptest.NewRecorder()

			// Call handler
			handler(w, req)

			// Check status code
			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Check response body
			if tt.expectedStatus == http.StatusOK {
				body := w.Body.String()
				if body != tt.expectedBody {
					t.Errorf("Expected body %q, got %q", tt.expectedBody, body)
				}

				// Check Content-Type header
				contentType := w.Header().Get("Content-Type")
				if contentType != "text/plain" {
					t.Errorf("Expected Content-Type 'text/plain', got %q", contentType)
				}

				// Check Cache-Control header
				cacheControl := w.Header().Get("Cache-Control")
				if cacheControl != "no-cache, no-store, must-revalidate" {
					t.Errorf("Expected Cache-Control 'no-cache, no-store, must-revalidate', got %q", cacheControl)
				}
			}
		})
	}
}

func TestLastUpdatedHandler_MethodNotAllowed(t *testing.T) {
	provider := &mockLastUpdatedProvider{
		timestamp: "2025-12-24T17:30:45Z",
		err:       nil,
	}

	handler := LastUpdatedHandler(provider)

	req := httptest.NewRequest(http.MethodPost, "/api/lastupdated", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}
