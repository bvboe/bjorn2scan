package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type testInfoProvider struct {
	Component string
	Version   string
}

func (t *testInfoProvider) GetInfo() interface{} {
	return map[string]string{
		"component": t.Component,
		"version":   t.Version,
	}
}

func (t *testInfoProvider) GetClusterName() string {
	return "test-cluster"
}

func (t *testInfoProvider) GetVersion() string {
	return t.Version
}

func (t *testInfoProvider) GetScanContainers() bool {
	return true
}

func (t *testInfoProvider) GetScanNodes() bool {
	return false
}

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	HealthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}

	expected := "OK\n"
	if w.Body.String() != expected {
		t.Errorf("Expected body %q, got %q", expected, w.Body.String())
	}
}

func TestInfoHandler(t *testing.T) {
	provider := &testInfoProvider{
		Component: "test-component",
		Version:   "1.0.0",
	}

	req := httptest.NewRequest(http.MethodGet, "/info", nil)
	w := httptest.NewRecorder()

	handler := InfoHandler(provider)
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type %q, got %q", "application/json", contentType)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	if response["component"] != "test-component" {
		t.Errorf("Expected component %q, got %q", "test-component", response["component"])
	}

	if response["version"] != "1.0.0" {
		t.Errorf("Expected version %q, got %q", "1.0.0", response["version"])
	}
}

func TestRegisterHandlers(t *testing.T) {
	provider := &testInfoProvider{
		Component: "test-component",
		Version:   "1.0.0",
	}

	mux := http.NewServeMux()
	RegisterHandlers(mux, provider, nil)

	// Test health endpoint
	reqHealth := httptest.NewRequest(http.MethodGet, "/health", nil)
	wHealth := httptest.NewRecorder()
	mux.ServeHTTP(wHealth, reqHealth)

	if wHealth.Code != http.StatusOK {
		t.Errorf("Health endpoint: expected status %d, got %d", http.StatusOK, wHealth.Code)
	}

	if wHealth.Body.String() != "OK\n" {
		t.Errorf("Health endpoint: expected body %q, got %q", "OK\n", wHealth.Body.String())
	}

	// Test info endpoint
	reqInfo := httptest.NewRequest(http.MethodGet, "/info", nil)
	wInfo := httptest.NewRecorder()
	mux.ServeHTTP(wInfo, reqInfo)

	if wInfo.Code != http.StatusOK {
		t.Errorf("Info endpoint: expected status %d, got %d", http.StatusOK, wInfo.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(wInfo.Body).Decode(&response); err != nil {
		t.Fatalf("Info endpoint: failed to decode JSON: %v", err)
	}

	if response["component"] != "test-component" {
		t.Errorf("Info endpoint: expected component %q, got %q", "test-component", response["component"])
	}
}
