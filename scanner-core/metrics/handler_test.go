package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bvboe/bjorn2scan/scanner-core/database"
	"github.com/bvboe/bjorn2scan/scanner-core/nodes"
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
			CVEID:          "CVE-2024-1234",
			Severity:       "Critical",
			Risk:           9.8,
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

// TestNodeMetricLabelPlacement pins where the per-node invariants live: they
// belong on bjorn2scan_node_scanned only, not repeated on every vulnerability
// datapoint. On a large cluster the vulnerability families carry hundreds of
// thousands of series, so repeating kernel_version / architecture / instance_type
// there cost ~46 MB (12.7%) of the payload for no added information —
// see docs/OTEL-DATA-ARCHITECTURE.md.
//
// os_release deliberately stays on the vulnerability families: the node
// dashboard's "Vulnerabilities by OS" panel does sum by (os_release) directly on
// them.
func TestNodeMetricLabelPlacement(t *testing.T) {
	info := &MockInfoProvider{deploymentName: "test-cluster", deploymentType: "kubernetes", version: "1.0.0"}
	provider := newMockStreamingProvider()
	provider.scannedNodes = []nodes.NodeWithStatus{
		{Node: nodes.Node{
			Name: "node-1", Hostname: "node-1.local",
			OSRelease: "Ubuntu 22.04", KernelVersion: "5.15.0", Architecture: "amd64",
		}},
	}
	provider.nodeVulns = []database.NodeVulnerabilityForMetrics{
		{
			NodeName: "node-1", Hostname: "node-1.local", OSRelease: "Ubuntu 22.04",
			CVEID: "CVE-2024-1234", Severity: "Critical", Risk: 9.8,
			FixStatus: "fixed", FixVersion: "1.0.1", KnownExploited: 1,
			PackageName: "openssl", PackageVersion: "3.0.2", PackageType: "deb", Count: 1,
		},
	}
	config := UnifiedConfig{
		NodeScannedEnabled:                true,
		NodeVulnerabilitiesEnabled:        true,
		NodeVulnerabilityRiskEnabled:      true,
		NodeVulnerabilityExploitedEnabled: true,
	}
	handler := NewMetricsHandler(info, "test-uuid", provider, config, newTestStalenessStore(provider))
	w := httptest.NewRecorder()
	handler(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	var nodeScanned, nodeVuln []string
	for _, line := range strings.Split(w.Body.String(), "\n") {
		switch {
		case strings.HasPrefix(line, "bjorn2scan_node_scanned{"):
			nodeScanned = append(nodeScanned, line)
		case strings.HasPrefix(line, "bjorn2scan_node_vulnerability"):
			nodeVuln = append(nodeVuln, line)
		}
	}
	if len(nodeScanned) == 0 || len(nodeVuln) == 0 {
		t.Fatalf("expected both families to be emitted: node_scanned=%d node_vulnerability=%d",
			len(nodeScanned), len(nodeVuln))
	}

	// Per-node invariants must appear ONLY on node_scanned.
	invariants := []string{"kernel_version", "architecture", "instance_type"}
	for _, label := range invariants {
		for _, line := range nodeScanned {
			if !strings.Contains(line, label+`="`) {
				t.Errorf("node_scanned must carry %s: %s", label, line)
			}
		}
		for _, line := range nodeVuln {
			if strings.Contains(line, label+`="`) {
				t.Errorf("node_vulnerability must NOT carry %s (per-node invariant): %s", label, line)
			}
		}
	}

	// The vulnerability families must still carry what identifies the finding and
	// what the dashboards join on.
	required := []string{"node", "hostname", "os_release", "severity", "vulnerability",
		"package_name", "package_version", "package_type", "fix_status", "fixed_version"}
	for _, label := range required {
		for _, line := range nodeVuln {
			if !strings.Contains(line, label+`="`) {
				t.Errorf("node_vulnerability must carry %s: %s", label, line)
			}
		}
	}
}
