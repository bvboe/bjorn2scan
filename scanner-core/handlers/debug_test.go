package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/debug"
	"github.com/bvboe/b2s-go/scanner-core/scanning"
)

// Note: We can't easily mock *database.DB as it's a concrete type,
// so these tests focus on the HTTP handler behavior and debug config validation

func TestDebugSQLHandler(t *testing.T) {
	tests := []struct {
		name           string
		debugEnabled   bool
		method         string
		requestBody    string
		expectedStatus int
	}{
		{
			name:           "debug mode disabled",
			debugEnabled:   false,
			method:         http.MethodPost,
			requestBody:    `{"query":"SELECT * FROM images"}`,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "wrong HTTP method",
			debugEnabled:   true,
			method:         http.MethodGet,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "invalid JSON",
			debugEnabled:   true,
			method:         http.MethodPost,
			requestBody:    `{invalid json}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "empty query",
			debugEnabled:   true,
			method:         http.MethodPost,
			requestBody:    `{"query":""}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "multiple statements (SQL injection attempt)",
			debugEnabled:   true,
			method:         http.MethodPost,
			requestBody:    `{"query":"SELECT * FROM images; DROP TABLE images; --"}`,
			expectedStatus: http.StatusBadRequest, // Should be rejected by validation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			debugConfig := debug.NewDebugConfig(tt.debugEnabled)

			// We can't easily mock *database.DB, so we pass nil for tests that
			// should fail before reaching the database
			handler := DebugSQLHandler(nil, debugConfig)
			req := httptest.NewRequest(tt.method, "/api/debug/sql", bytes.NewBufferString(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d. Body: %s", tt.expectedStatus, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestDebugMetricsHandler(t *testing.T) {
	tests := []struct {
		name           string
		debugEnabled   bool
		method         string
		setupMetrics   func(debugConfig *debug.DebugConfig)
		setupQueue     *scanning.JobQueue
		expectedStatus int
		checkResponse  func(t *testing.T, body string)
	}{
		{
			name:           "debug mode disabled",
			debugEnabled:   false,
			method:         http.MethodGet,
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "wrong HTTP method",
			debugEnabled:   true,
			method:         http.MethodPost,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:         "returns basic metrics",
			debugEnabled: true,
			method:       http.MethodGet,
			setupMetrics: func(debugConfig *debug.DebugConfig) {
				// Record some requests
				debugConfig.RecordRequest("/api/images", 50*time.Millisecond)
				debugConfig.RecordRequest("/api/images", 100*time.Millisecond)
				debugConfig.RecordRequest("/api/containers", 75*time.Millisecond)
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var response map[string]interface{}
				if err := json.Unmarshal([]byte(body), &response); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				if response["request_count"].(float64) != 3 {
					t.Errorf("Expected request_count 3, got %v", response["request_count"])
				}
				endpoints := response["endpoints"].(map[string]interface{})
				if len(endpoints) != 2 {
					t.Errorf("Expected 2 endpoints, got %d", len(endpoints))
				}
				// Check /api/images endpoint
				if imagesEndpoint, ok := endpoints["/api/images"].(map[string]interface{}); ok {
					if imagesEndpoint["count"].(float64) != 2 {
						t.Errorf("Expected /api/images count 2, got %v", imagesEndpoint["count"])
					}
					// Average should be (50+100)/2 = 75ms
					avgDuration := imagesEndpoint["avg_duration_ms"].(float64)
					if avgDuration < 74 || avgDuration > 76 {
						t.Errorf("Expected avg_duration_ms ~75, got %v", avgDuration)
					}
				} else {
					t.Error("/api/images endpoint not found in metrics")
				}
			},
		},
		{
			name:         "includes queue depth",
			debugEnabled: true,
			method:       http.MethodGet,
			setupQueue: &scanning.JobQueue{
				// Mock queue with some depth
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var response map[string]interface{}
				if err := json.Unmarshal([]byte(body), &response); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				// queue_depth should be present
				if _, ok := response["queue_depth"]; !ok {
					t.Error("Expected queue_depth in response")
				}
			},
		},
		{
			name:         "empty metrics",
			debugEnabled: true,
			method:       http.MethodGet,
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				var response map[string]interface{}
				if err := json.Unmarshal([]byte(body), &response); err != nil {
					t.Fatalf("Failed to parse response: %v", err)
				}
				if response["request_count"].(float64) != 0 {
					t.Errorf("Expected request_count 0, got %v", response["request_count"])
				}
				endpoints := response["endpoints"].(map[string]interface{})
				if len(endpoints) != 0 {
					t.Errorf("Expected 0 endpoints, got %d", len(endpoints))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			debugConfig := debug.NewDebugConfig(tt.debugEnabled)

			if tt.setupMetrics != nil {
				tt.setupMetrics(debugConfig)
			}

			handler := DebugMetricsHandler(debugConfig, tt.setupQueue)
			req := httptest.NewRequest(tt.method, "/api/debug/metrics", nil)
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

func TestRegisterDebugHandlers(t *testing.T) {
	t.Run("registers handlers when debug enabled", func(t *testing.T) {
		mux := http.NewServeMux()
		debugConfig := debug.NewDebugConfig(true)

		RegisterDebugHandlers(mux, nil, debugConfig, nil)

		// Test that handlers are registered
		tests := []struct {
			path   string
			method string
		}{
			{"/api/debug/sql", http.MethodPost},
			{"/api/debug/metrics", http.MethodGet},
		}

		for _, tt := range tests {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			// Should not be 404 (handler is registered)
			if rec.Code == http.StatusNotFound {
				t.Errorf("Handler not registered for %s %s", tt.method, tt.path)
			}
		}
	})

	t.Run("does not register handlers when debug disabled", func(t *testing.T) {
		mux := http.NewServeMux()
		debugConfig := debug.NewDebugConfig(false)

		RegisterDebugHandlers(mux, nil, debugConfig, nil)

		// Test that handlers are NOT registered
		req := httptest.NewRequest(http.MethodPost, "/api/debug/sql", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		// Should be 404 (handler not registered)
		if rec.Code != http.StatusNotFound {
			t.Errorf("Expected 404 for debug handler when debug disabled, got %d", rec.Code)
		}
	})

	t.Run("handles nil debug config", func(t *testing.T) {
		mux := http.NewServeMux()

		// Should not panic
		RegisterDebugHandlers(mux, nil, nil, nil)

		req := httptest.NewRequest(http.MethodPost, "/api/debug/sql", nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		// Should be 404 (handler not registered)
		if rec.Code != http.StatusNotFound {
			t.Errorf("Expected 404 when debug config is nil, got %d", rec.Code)
		}
	})
}
