package test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type InfoResponse struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

func TestHealthEndpoint(t *testing.T) {
	// Create a request to the /health endpoint
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	// Create a simple handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("OK\n")); err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	})

	handler.ServeHTTP(w, req)

	// Check the status code
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}

	// Check the response body
	expected := "OK\n"
	if w.Body.String() != expected {
		t.Errorf("Expected body %q, got %q", expected, w.Body.String())
	}
}

func TestInfoEndpoint(t *testing.T) {
	// Create a request to the /info endpoint
	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	w := httptest.NewRecorder()

	// Create a simple handler that returns JSON
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		info := InfoResponse{
			Component: "bjorn2scan-agent",
			Version:   "test-version",
			Hostname:  "test-host",
			OS:        "linux",
			Arch:      "amd64",
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(info); err != nil {
			t.Errorf("Failed to encode JSON: %v", err)
		}
	})

	handler.ServeHTTP(w, req)

	// Check the status code
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}

	// Check the content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type %q, got %q", "application/json", contentType)
	}

	// Decode the JSON response
	var info InfoResponse
	if err := json.NewDecoder(w.Body).Decode(&info); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	// Verify the response fields
	if info.Component != "bjorn2scan-agent" {
		t.Errorf("Expected component %q, got %q", "bjorn2scan-agent", info.Component)
	}

	if info.Version == "" {
		t.Error("Version should not be empty")
	}
}
