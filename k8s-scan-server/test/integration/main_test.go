package integration_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

const (
	defaultServiceURL = "http://localhost:8080"
	requestTimeout    = 5 * time.Second
)

type InfoResponse struct {
	Version   string `json:"version"`
	PodName   string `json:"pod_name"`
	Namespace string `json:"namespace"`
}

func getServiceURL() string {
	if url := os.Getenv("SERVICE_URL"); url != "" {
		return url
	}
	return defaultServiceURL
}

func TestHealthEndpoint(t *testing.T) {
	client := &http.Client{Timeout: requestTimeout}
	url := fmt.Sprintf("%s/health", getServiceURL())

	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("Failed to call /health endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	t.Logf("✓ Health endpoint returned status %d", resp.StatusCode)
}

func TestInfoEndpoint(t *testing.T) {
	client := &http.Client{Timeout: requestTimeout}
	url := fmt.Sprintf("%s/info", getServiceURL())

	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("Failed to call /info endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var info InfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		t.Fatalf("Failed to decode JSON response: %v", err)
	}

	// Validate response fields
	if info.Version == "" {
		t.Error("Expected non-empty version field")
	}

	if info.PodName == "" {
		t.Error("Expected non-empty pod_name field")
	}

	if info.Namespace == "" {
		t.Error("Expected non-empty namespace field")
	}

	t.Logf("✓ Info endpoint returned valid response:")
	t.Logf("  Version: %s", info.Version)
	t.Logf("  Pod Name: %s", info.PodName)
	t.Logf("  Namespace: %s", info.Namespace)
}

func TestServiceAvailability(t *testing.T) {
	client := &http.Client{Timeout: requestTimeout}
	url := getServiceURL()

	// Test that the service is reachable and responds within timeout
	start := time.Now()
	resp, err := client.Get(fmt.Sprintf("%s/health", url))
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Service not available: %v", err)
	}
	defer resp.Body.Close()

	if elapsed > requestTimeout {
		t.Errorf("Service response time %v exceeded timeout %v", elapsed, requestTimeout)
	}

	t.Logf("✓ Service responded in %v", elapsed)
}

func TestEndpointNotFound(t *testing.T) {
	client := &http.Client{Timeout: requestTimeout}
	url := fmt.Sprintf("%s/nonexistent", getServiceURL())

	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("Failed to call nonexistent endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404 for nonexistent endpoint, got %d", resp.StatusCode)
	}

	t.Logf("✓ Nonexistent endpoint correctly returned 404")
}
