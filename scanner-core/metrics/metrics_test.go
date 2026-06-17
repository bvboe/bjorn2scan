package metrics

import (
	"strings"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// MockInfoProvider implements InfoProvider for testing.
// Exported so otel_test.go (same package) can use it.
type MockInfoProvider struct {
	deploymentName string
	deploymentType string
	version        string
	deploymentIP   string
	consoleURL     string
	grypeDBBuilt   string
}

func (m *MockInfoProvider) GetDeploymentName() string { return m.deploymentName }
func (m *MockInfoProvider) GetDeploymentType() string { return m.deploymentType }
func (m *MockInfoProvider) GetVersion() string        { return m.version }
func (m *MockInfoProvider) GetDeploymentIP() string   { return m.deploymentIP }
func (m *MockInfoProvider) GetConsoleURL() string     { return m.consoleURL }
func (m *MockInfoProvider) GetGrypeDBBuilt() string   { return m.grypeDBBuilt }

// MockStreamingProvider implements both StreamingProvider and StalenessDB for testing.
// The staleness methods delegate to the embedded mockStalenessDB so tests can verify upserts.
type MockStreamingProvider struct {
	containers       []database.ScannedContainer
	vulns            []database.ContainerVulnerability
	scanStatuses     []database.ImageScanStatusCount
	nodeScanStatuses []database.NodeScanStatusCount
	scannedNodes     []nodes.NodeWithStatus
	nodeVulns        []database.NodeVulnerabilityForMetrics
	stalenessDB      *mockStalenessDB
	err              error
}

func newMockStreamingProvider() *MockStreamingProvider {
	return &MockStreamingProvider{stalenessDB: &mockStalenessDB{}}
}

func (m *MockStreamingProvider) StreamScannedContainers(cb func(database.ScannedContainer) error) error {
	if m.err != nil {
		return m.err
	}
	for _, c := range m.containers {
		if err := cb(c); err != nil {
			return err
		}
	}
	return nil
}

func (m *MockStreamingProvider) StreamContainerVulnerabilities(cb func(database.ContainerVulnerability) error) error {
	if m.err != nil {
		return m.err
	}
	for _, v := range m.vulns {
		if err := cb(v); err != nil {
			return err
		}
	}
	return nil
}

func (m *MockStreamingProvider) GetImageScanStatusCounts() ([]database.ImageScanStatusCount, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.scanStatuses, nil
}

func (m *MockStreamingProvider) GetNodeScanStatusCounts() ([]database.NodeScanStatusCount, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.nodeScanStatuses, nil
}

func (m *MockStreamingProvider) GetScannedNodes() ([]nodes.NodeWithStatus, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.scannedNodes, nil
}

func (m *MockStreamingProvider) StreamNodeVulnerabilitiesForMetrics(cb func(database.NodeVulnerabilityForMetrics) error) error {
	if m.err != nil {
		return m.err
	}
	for _, v := range m.nodeVulns {
		if err := cb(v); err != nil {
			return err
		}
	}
	return nil
}

func (m *MockStreamingProvider) QueryStaleness(cycleStart int64) ([]database.StalenessRow, error) {
	return m.stalenessDB.QueryStaleness(cycleStart)
}

func (m *MockStreamingProvider) HydrateStalenessState() (map[uint64]int64, error) {
	return m.stalenessDB.HydrateStalenessState()
}

func (m *MockStreamingProvider) ApplyStalenessChanges(toUpsert []database.StalenessRow, toStale []uint64, expiresAtUnix int64) error {
	return m.stalenessDB.ApplyStalenessChanges(toUpsert, toStale, expiresAtUnix)
}

func (m *MockStreamingProvider) DeleteExpiredStaleness(expireBefore int64) error {
	return m.stalenessDB.DeleteExpiredStaleness(expireBefore)
}

// newTestStalenessStore creates a StalenessStore backed by the mock provider's staleness DB.
func newTestStalenessStore(p *MockStreamingProvider) *StalenessStore {
	return NewStalenessStore(p.stalenessDB, time.Hour)
}

// streamMetricsToString is a helper that runs StreamMetrics and returns the output as a string.
func streamMetricsToString(
	t *testing.T,
	info InfoProvider,
	deploymentUUID string,
	provider *MockStreamingProvider,
	config UnifiedConfig,
	staleRows []database.StalenessRow,
) string {
	t.Helper()
	staleness := newTestStalenessStore(provider)
	var buf strings.Builder
	batch, err := StreamMetrics(&buf, info, deploymentUUID, provider, config, staleRows, time.Now())
	if err != nil {
		t.Fatalf("StreamMetrics returned error: %v", err)
	}
	if err := staleness.ApplyDiff(batch, time.Now()); err != nil {
		t.Fatalf("ApplyDiff failed: %v", err)
	}
	return buf.String()
}

func TestStreamMetrics_DeploymentMetric(t *testing.T) {
	info := &MockInfoProvider{
		deploymentName: "test-host",
		deploymentType: "agent",
		version:        "1.0.0",
	}
	provider := newMockStreamingProvider()
	config := UnifiedConfig{DeploymentEnabled: true}

	output := streamMetricsToString(t, info, "test-uuid", provider, config, nil)

	if !strings.Contains(output, "bjorn2scan_deployment{") {
		t.Error("Expected bjorn2scan_deployment metric")
	}
	if !strings.Contains(output, `deployment_uuid="test-uuid"`) {
		t.Error("Expected deployment_uuid label")
	}
	if !strings.Contains(output, `deployment_name="test-host"`) {
		t.Error("Expected deployment_name label")
	}
	if !strings.Contains(output, `deployment_type="agent"`) {
		t.Error("Expected deployment_type label")
	}
	if !strings.Contains(output, `bjorn2scan_version="1.0.0"`) {
		t.Error("Expected bjorn2scan_version label")
	}
	if !strings.Contains(output, "} 1\n") {
		t.Error("Expected metric value of 1")
	}
}

func TestStreamMetrics_ImageScanned(t *testing.T) {
	info := &MockInfoProvider{deploymentName: "prod-cluster", deploymentType: "kubernetes", version: "2.0.0"}
	provider := newMockStreamingProvider()
	provider.containers = []database.ScannedContainer{
		{Namespace: "default", Pod: "app-pod", Name: "app", NodeName: "node-1", Reference: "app:v1", Digest: "sha256:abc", OSName: "alpine"},
		{Namespace: "kube-system", Pod: "dns-pod", Name: "dns", NodeName: "node-2", Reference: "dns:1.0", Digest: "sha256:def", OSName: "alpine"},
	}
	config := UnifiedConfig{ScannedContainersEnabled: true}

	output := streamMetricsToString(t, info, "uuid", provider, config, nil)

	if !strings.Contains(output, "bjorn2scan_image_scanned{") {
		t.Error("Expected bjorn2scan_image_scanned metric")
	}
	count := strings.Count(output, "bjorn2scan_image_scanned{")
	if count != 2 {
		t.Errorf("Expected 2 image_scanned metrics, got %d", count)
	}
}

func TestStreamMetrics_ContainerVulnerabilities_ThreeFamilies(t *testing.T) {
	info := &MockInfoProvider{deploymentName: "cluster", deploymentType: "kubernetes", version: "1.0.0"}
	provider := newMockStreamingProvider()
	provider.vulns = []database.ContainerVulnerability{
		{
			Namespace: "default", Pod: "pod1", Name: "app", NodeName: "node-1",
			Reference: "app:v1", Digest: "sha256:abc", OSName: "alpine",
			CVEID: "CVE-2024-1234", Severity: "Critical", Risk: 9.8,
			FixStatus: "fixed", FixedVersion: "2.0.0",
			KnownExploited: 1, Count: 1,
		},
	}
	config := UnifiedConfig{
		VulnerabilitiesEnabled:        true,
		VulnerabilityRiskEnabled:      true,
		VulnerabilityExploitedEnabled: true,
	}

	output := streamMetricsToString(t, info, "uuid", provider, config, nil)

	if !strings.Contains(output, "bjorn2scan_image_vulnerability{") {
		t.Error("Expected bjorn2scan_image_vulnerability metric")
	}
	if !strings.Contains(output, "bjorn2scan_image_vulnerability_risk{") {
		t.Error("Expected bjorn2scan_image_vulnerability_risk metric")
	}
	if !strings.Contains(output, "bjorn2scan_image_vulnerability_exploited{") {
		t.Error("Expected bjorn2scan_image_vulnerability_exploited metric")
	}
}

func TestStreamMetrics_NodeMetrics(t *testing.T) {
	info := &MockInfoProvider{deploymentName: "cluster", deploymentType: "kubernetes", version: "1.0.0"}
	provider := newMockStreamingProvider()
	provider.scannedNodes = []nodes.NodeWithStatus{
		{Node: nodes.Node{Name: "node-1", Hostname: "node-1.local", OSRelease: "Ubuntu 22.04", KernelVersion: "5.15.0", Architecture: "amd64"}},
	}
	provider.nodeVulns = []database.NodeVulnerabilityForMetrics{
		{NodeName: "node-1", CVEID: "CVE-2024-5678", Severity: "High", Risk: 7.5, KnownExploited: 1, Count: 2},
	}
	config := UnifiedConfig{
		NodeScannedEnabled:                true,
		NodeVulnerabilitiesEnabled:        true,
		NodeVulnerabilityRiskEnabled:      true,
		NodeVulnerabilityExploitedEnabled: true,
	}

	output := streamMetricsToString(t, info, "uuid", provider, config, nil)

	if !strings.Contains(output, "bjorn2scan_node_scanned{") {
		t.Error("Expected bjorn2scan_node_scanned metric")
	}
	if !strings.Contains(output, "bjorn2scan_node_vulnerability{") {
		t.Error("Expected bjorn2scan_node_vulnerability metric")
	}
	if !strings.Contains(output, "bjorn2scan_node_vulnerability_risk{") {
		t.Error("Expected bjorn2scan_node_vulnerability_risk metric")
	}
	if !strings.Contains(output, "bjorn2scan_node_vulnerability_exploited{") {
		t.Error("Expected bjorn2scan_node_vulnerability_exploited metric")
	}
}

func TestStreamMetrics_NodeScanStatus(t *testing.T) {
	info := &MockInfoProvider{deploymentName: "cluster", deploymentType: "kubernetes", version: "1.0.0"}
	provider := newMockStreamingProvider()
	provider.nodeScanStatuses = []database.NodeScanStatusCount{
		{Status: "completed", Count: 5},
		{Status: "vuln_scan_failed", Count: 1},
		{Status: "pending", Count: 0},
	}
	config := UnifiedConfig{NodeScanStatusEnabled: true}

	output := streamMetricsToString(t, info, "uuid", provider, config, nil)

	if !strings.Contains(output, "bjorn2scan_node_scan_status{") {
		t.Fatal("Expected bjorn2scan_node_scan_status metric")
	}
	if !strings.Contains(output, `scan_status="completed"`) || !strings.Contains(output, `scan_status="vuln_scan_failed"`) {
		t.Error("Expected scan_status labels for completed and vuln_scan_failed")
	}
	// 3 statuses emitted (including the zero-count one)
	if c := strings.Count(output, "bjorn2scan_node_scan_status{"); c != 3 {
		t.Errorf("Expected 3 node_scan_status series, got %d", c)
	}
}

func TestStreamMetrics_NaNForStaleRows(t *testing.T) {
	info := &MockInfoProvider{deploymentName: "cluster", deploymentType: "kubernetes", version: "1.0.0"}
	provider := newMockStreamingProvider()
	config := UnifiedConfig{DeploymentEnabled: true}

	staleRows := []database.StalenessRow{
		{
			MetricKey:  "bjorn2scan_image_scanned|pod=old-pod",
			FamilyName: "bjorn2scan_image_scanned",
			LabelsJSON: `{"pod":"old-pod","namespace":"default"}`,
		},
	}

	output := streamMetricsToString(t, info, "uuid", provider, config, staleRows)

	if !strings.Contains(output, "NaN") {
		t.Error("Expected NaN value for stale metric")
	}
	if !strings.Contains(output, "bjorn2scan_image_scanned{") {
		t.Error("Expected stale family header to be written")
	}
}

func TestStreamMetrics_EmptyProvider(t *testing.T) {
	info := &MockInfoProvider{deploymentName: "cluster", deploymentType: "kubernetes", version: "1.0.0"}
	provider := newMockStreamingProvider()
	config := UnifiedConfig{
		DeploymentEnabled:          true,
		ScannedContainersEnabled:   true,
		VulnerabilitiesEnabled:     true,
		NodeScannedEnabled:         true,
		NodeVulnerabilitiesEnabled: true,
	}

	output := streamMetricsToString(t, info, "uuid", provider, config, nil)

	// Should produce the deployment metric (1 point) but no image/node metrics (empty)
	if !strings.Contains(output, "bjorn2scan_deployment{") {
		t.Error("Expected deployment metric even with empty provider")
	}
	// No image scanned metrics (empty containers)
	if strings.Contains(output, "bjorn2scan_image_scanned{") {
		t.Error("Should not have image_scanned metrics for empty provider")
	}
}

func TestStreamMetrics_DisabledMetrics(t *testing.T) {
	info := &MockInfoProvider{deploymentName: "cluster", deploymentType: "kubernetes", version: "1.0.0"}
	provider := newMockStreamingProvider()
	provider.containers = []database.ScannedContainer{
		{Namespace: "default", Pod: "pod1", Name: "app", NodeName: "node-1"},
	}
	config := UnifiedConfig{} // All disabled

	output := streamMetricsToString(t, info, "uuid", provider, config, nil)

	if strings.Contains(output, "bjorn2scan_") {
		t.Error("Should not have any metrics when all disabled")
	}
}

func TestStreamMetrics_StalenessTracking(t *testing.T) {
	info := &MockInfoProvider{deploymentName: "cluster", deploymentType: "kubernetes", version: "1.0.0"}
	provider := newMockStreamingProvider()
	provider.containers = []database.ScannedContainer{
		{Namespace: "default", Pod: "pod1", Name: "app", NodeName: "node-1", Reference: "app:v1", Digest: "sha256:abc"},
	}
	config := UnifiedConfig{ScannedContainersEnabled: true}

	staleness := newTestStalenessStore(provider)
	var buf strings.Builder
	batch, err := StreamMetrics(&buf, info, "uuid", provider, config, nil, time.Now())
	if err != nil {
		t.Fatalf("StreamMetrics failed: %v", err)
	}

	// ApplyDiff simulates what the handler does after the HTTP response is flushed.
	if err := staleness.ApplyDiff(batch, time.Now()); err != nil {
		t.Fatalf("ApplyDiff failed: %v", err)
	}

	// Verify new metrics were upserted (first cycle — nothing in DB yet)
	if len(provider.stalenessDB.upserts) == 0 {
		t.Error("Expected new metrics to be upserted after ApplyDiff")
	}
}
