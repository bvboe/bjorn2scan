package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

func TestNewMetricsHandler_MethodNotAllowed(t *testing.T) {
	info := &MockInfoProvider{deploymentName: "cluster", deploymentType: "kubernetes", version: "1.0.0"}
	provider := newMockStreamingProvider()
	config := UnifiedConfig{}
	staleness := newTestStalenessStore(provider)

	handler := NewMetricsHandler(info, "uuid", provider, config, staleness)

	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405 for POST, got %d", w.Result().StatusCode)
	}
}

func TestNewMetricsHandler_ContentType(t *testing.T) {
	info := &MockInfoProvider{deploymentName: "cluster", deploymentType: "kubernetes", version: "1.0.0"}
	provider := newMockStreamingProvider()
	config := UnifiedConfig{DeploymentEnabled: true}
	staleness := newTestStalenessStore(provider)

	handler := NewMetricsHandler(info, "uuid", provider, config, staleness)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Expected text/plain Content-Type, got %q", ct)
	}
}

func TestNewMetricsHandler_ReturnsMetrics(t *testing.T) {
	info := &MockInfoProvider{deploymentName: "test-cluster", deploymentType: "kubernetes", version: "1.0.0"}
	provider := newMockStreamingProvider()
	provider.scannedNodes = []nodes.NodeWithStatus{
		{
			Node: nodes.Node{
				Name:          "node-1",
				Hostname:      "node-1.local",
				OSRelease:     "Ubuntu 22.04",
				KernelVersion: "5.15.0",
				Architecture:  "amd64",
			},
		},
	}
	provider.nodeVulns = []database.NodeVulnerabilityForMetrics{
		{
			NodeName:       "node-1",
			Hostname:       "node-1.local",
			OSRelease:      "Ubuntu 22.04",
			KernelVersion:  "5.15.0",
			Architecture:   "amd64",
			CVEID:          "CVE-2024-1234",
			Severity:       "Critical",
			Risk:          9.8,
			FixStatus:      "fixed",
			FixVersion:     "1.0.1",
			KnownExploited: 1,
			PackageName:    "openssl",
			PackageVersion: "3.0.2",
			PackageType:    "deb",
			Count:          1,
		},
	}

	config := UnifiedConfig{
		DeploymentEnabled:                 true,
		NodeScannedEnabled:                true,
		NodeVulnerabilitiesEnabled:        true,
		NodeVulnerabilityRiskEnabled:      true,
		NodeVulnerabilityExploitedEnabled: true,
	}
	staleness := newTestStalenessStore(provider)

	handler := NewMetricsHandler(info, "test-uuid", provider, config, staleness)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Result().StatusCode)
	}

	body := w.Body.String()

	if !strings.Contains(body, "bjorn2scan_node_scanned{") {
		t.Error("Expected bjorn2scan_node_scanned metric")
	}
	if !strings.Contains(body, "bjorn2scan_node_vulnerability{") {
		t.Error("Expected bjorn2scan_node_vulnerability metric")
	}
	if !strings.Contains(body, "bjorn2scan_node_vulnerability_risk{") {
		t.Error("Expected bjorn2scan_node_vulnerability_risk metric")
	}
	if !strings.Contains(body, "bjorn2scan_node_vulnerability_exploited{") {
		t.Error("Expected bjorn2scan_node_vulnerability_exploited metric")
	}
	if !strings.Contains(body, `node="node-1"`) {
		t.Error("Expected node label")
	}
	if !strings.Contains(body, `vulnerability="CVE-2024-1234"`) {
		t.Error("Expected vulnerability label")
	}
}

func TestNewMetricsHandler_DisabledNodeMetrics(t *testing.T) {
	info := &MockInfoProvider{deploymentName: "cluster", deploymentType: "kubernetes", version: "1.0.0"}
	provider := newMockStreamingProvider()
	provider.scannedNodes = []nodes.NodeWithStatus{
		{Node: nodes.Node{Name: "node-1"}},
	}

	// All node metrics disabled
	config := UnifiedConfig{
		DeploymentEnabled:                 true,
		NodeScannedEnabled:                false,
		NodeVulnerabilitiesEnabled:        false,
		NodeVulnerabilityRiskEnabled:      false,
		NodeVulnerabilityExploitedEnabled: false,
	}
	staleness := newTestStalenessStore(provider)

	handler := NewMetricsHandler(info, "uuid", provider, config, staleness)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	body := w.Body.String()
	if strings.Contains(body, "bjorn2scan_node_") {
		t.Error("Should not have node metrics when all node metrics are disabled")
	}
}
