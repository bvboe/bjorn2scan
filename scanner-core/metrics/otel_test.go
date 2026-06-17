package metrics

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
)

// MockDirectOTLPSender is a test double for DirectOTLPSender.
type MockDirectOTLPSender struct {
	mu          sync.Mutex
	sendCalls   int
	closeCalls  int
	allMetrics  [][]*metricsv1.Metric
	sendErr     error
}

func newMockDirectOTLPSender() *MockDirectOTLPSender {
	return &MockDirectOTLPSender{}
}

func (m *MockDirectOTLPSender) Send(_ context.Context, metrics []*metricsv1.Metric) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sendErr != nil {
		return m.sendErr
	}
	// Deep copy the slice so callers can't mutate stored data
	cp := make([]*metricsv1.Metric, len(metrics))
	copy(cp, metrics)
	m.allMetrics = append(m.allMetrics, cp)
	m.sendCalls++
	return nil
}

func (m *MockDirectOTLPSender) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closeCalls++
	return nil
}

func (m *MockDirectOTLPSender) TotalDataPoints() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	total := 0
	for _, batch := range m.allMetrics {
		for _, metric := range batch {
			total += len(metric.GetGauge().GetDataPoints())
		}
	}
	return total
}

func (m *MockDirectOTLPSender) SendCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sendCalls
}

// makeTestOTELExporter creates an OTELExporter wired to a MockDirectOTLPSender for testing.
// Returns both the exporter and the mock so tests can inspect what was sent.
func makeTestOTELExporter(t *testing.T, provider *MockStreamingProvider, cfg OTELConfig, config UnifiedConfig) (*OTELExporter, *MockDirectOTLPSender) {
	t.Helper()
	ctx := context.Background()
	info := &MockInfoProvider{deploymentName: "test-cluster", deploymentType: "kubernetes", version: "1.0.0"}

	var staleness *StalenessStore
	if provider != nil {
		staleness = newTestStalenessStore(provider)
	} else {
		staleness = NewStalenessStore(&mockStalenessDB{}, time.Hour)
	}

	var sp StreamingProvider
	if provider != nil {
		sp = provider
	}

	e, err := NewOTELExporter(ctx, info, "test-uuid", sp, config, cfg, staleness)
	if err != nil {
		t.Fatalf("Failed to create OTEL exporter: %v", err)
	}

	mock := newMockDirectOTLPSender()
	e.setSender(mock)
	return e, mock
}

func defaultOTELConfig() OTELConfig {
	return OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 1 * time.Minute,
		Insecure:     true,
	}
}

func TestNewOTELExporter_Success(t *testing.T) {
	e, mock := makeTestOTELExporter(t, nil, defaultOTELConfig(), UnifiedConfig{DeploymentEnabled: true})
	defer func() { _ = e.Shutdown() }()

	if e.sender == nil {
		t.Error("Expected non-nil sender")
	}
	if e.ctx == nil {
		t.Error("Expected non-nil context")
	}
	if e.cancel == nil {
		t.Error("Expected non-nil cancel function")
	}
	if mock == nil {
		t.Error("Expected non-nil mock sender")
	}
}

func TestNewOTELExporter_WithHTTPProtocol(t *testing.T) {
	cfg := OTELConfig{
		Endpoint:     "prometheus:9090",
		Protocol:     OTELProtocolHTTP,
		PushInterval: 30 * time.Second,
		Insecure:     true,
	}
	e, _ := makeTestOTELExporter(t, nil, cfg, UnifiedConfig{})
	defer func() { _ = e.Shutdown() }()

	if e.config.Protocol != OTELProtocolHTTP {
		t.Errorf("Expected HTTP protocol, got %v", e.config.Protocol)
	}
	if e.config.Endpoint != "prometheus:9090" {
		t.Errorf("Expected prometheus:9090, got %v", e.config.Endpoint)
	}
}

func TestRecordMetrics_NilProvider(t *testing.T) {
	e, _ := makeTestOTELExporter(t, nil, defaultOTELConfig(), UnifiedConfig{DeploymentEnabled: true})
	defer func() { _ = e.Shutdown() }()

	// recordMetrics with nil provider should not panic
	e.recordMetrics()
}

func TestRecordMetrics_SendsToSender(t *testing.T) {
	provider := newMockStreamingProvider()
	config := UnifiedConfig{
		DeploymentEnabled:        true,
		ScannedContainersEnabled: true,
		NodeScannedEnabled:       true,
	}
	e, mock := makeTestOTELExporter(t, provider, defaultOTELConfig(), config)
	defer func() { _ = e.Shutdown() }()

	e.recordMetrics()

	if mock.SendCallCount() == 0 {
		t.Error("Expected sender.Send to be called after recordMetrics")
	}
}

func TestRecordMetrics_DeploymentMetricSent(t *testing.T) {
	provider := newMockStreamingProvider()
	config := UnifiedConfig{DeploymentEnabled: true}
	e, mock := makeTestOTELExporter(t, provider, defaultOTELConfig(), config)
	defer func() { _ = e.Shutdown() }()

	e.recordMetrics()

	if mock.TotalDataPoints() == 0 {
		t.Error("Expected at least one data point after recordMetrics")
	}
	// Verify deployment metric is present
	found := false
	mock.mu.Lock()
	for _, batch := range mock.allMetrics {
		for _, m := range batch {
			if m.Name == "bjorn2scan_deployment" {
				found = true
			}
		}
	}
	mock.mu.Unlock()
	if !found {
		t.Error("Expected bjorn2scan_deployment metric in sent data")
	}
}

func TestRecordMetrics_NodeVulnsGoThroughAccumulator(t *testing.T) {
	provider := newMockStreamingProvider()
	provider.nodeVulns = []database.NodeVulnerabilityForMetrics{
		{NodeName: "node-1", CVEID: "CVE-2024-001", Severity: "Critical", Risk: 9.8, Count: 1},
		{NodeName: "node-1", CVEID: "CVE-2024-002", Severity: "High", Risk: 7.5, Count: 1},
	}
	config := UnifiedConfig{
		NodeVulnerabilitiesEnabled:   true,
		NodeVulnerabilityRiskEnabled: true,
	}
	e, mock := makeTestOTELExporter(t, provider, defaultOTELConfig(), config)
	defer func() { _ = e.Shutdown() }()

	e.recordMetrics()

	// Node vulns should appear in sent data
	foundVuln := false
	foundRisk := false
	mock.mu.Lock()
	for _, batch := range mock.allMetrics {
		for _, m := range batch {
			if m.Name == "bjorn2scan_node_vulnerability" {
				foundVuln = true
			}
			if m.Name == "bjorn2scan_node_vulnerability_risk" {
				foundRisk = true
			}
		}
	}
	mock.mu.Unlock()
	if !foundVuln {
		t.Error("Expected bjorn2scan_node_vulnerability in sent data")
	}
	if !foundRisk {
		t.Error("Expected bjorn2scan_node_vulnerability_risk in sent data")
	}
}

func TestRecordMetrics_NaNForStaleMetrics(t *testing.T) {
	provider := newMockStreamingProvider()
	// Pre-seed a stale row with a future expiry so QueryStaleness returns it.
	futureExpiry := time.Now().Add(1 * time.Hour).Unix()
	withHydratedRow(provider.stalenessDB,
		"bjorn2scan_deployment|deployment_name=old-cluster|deployment_uuid=old-uuid",
		"bjorn2scan_deployment",
		`{"deployment_name":"old-cluster","deployment_uuid":"old-uuid"}`,
		&futureExpiry)

	config := UnifiedConfig{DeploymentEnabled: true}
	e, mock := makeTestOTELExporter(t, provider, defaultOTELConfig(), config)
	defer func() { _ = e.Shutdown() }()

	e.recordMetrics()

	// Should have sent data — the NaN for the stale metric plus the live deployment metric
	if mock.SendCallCount() == 0 {
		t.Error("Expected Send to be called")
	}
}

func TestShutdown_GracefulShutdown(t *testing.T) {
	e, _ := makeTestOTELExporter(t, nil, defaultOTELConfig(), UnifiedConfig{})
	_ = e.Shutdown()

	select {
	case <-e.ctx.Done():
		// Expected
	default:
		t.Error("Expected context to be cancelled after shutdown")
	}
}

func TestShutdown_MultipleShutdowns(t *testing.T) {
	e, _ := makeTestOTELExporter(t, nil, defaultOTELConfig(), UnifiedConfig{})
	_ = e.Shutdown()
	_ = e.Shutdown() // second shutdown should not panic
}

func TestShutdown_ClosesSender(t *testing.T) {
	e, mock := makeTestOTELExporter(t, nil, defaultOTELConfig(), UnifiedConfig{})
	_ = e.Shutdown()

	mock.mu.Lock()
	closes := mock.closeCalls
	mock.mu.Unlock()
	if closes == 0 {
		t.Error("Expected sender.Close to be called on Shutdown")
	}
}

func TestStart_StartsBackgroundPush(t *testing.T) {
	cfg := OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 100 * time.Millisecond,
		Insecure:     true,
	}
	e, _ := makeTestOTELExporter(t, nil, cfg, UnifiedConfig{})
	defer func() { _ = e.Shutdown() }()

	e.Start()
	time.Sleep(250 * time.Millisecond)
	// If we got here without deadlock or panic, the test passes
}

func TestStart_StopsOnShutdown(t *testing.T) {
	cfg := OTELConfig{
		Endpoint:     "localhost:4317",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 50 * time.Millisecond,
		Insecure:     true,
	}
	e, _ := makeTestOTELExporter(t, nil, cfg, UnifiedConfig{})
	e.Start()
	time.Sleep(100 * time.Millisecond)
	_ = e.Shutdown()
	time.Sleep(100 * time.Millisecond)

	select {
	case <-e.ctx.Done():
		// Expected
	default:
		t.Error("Expected context to be cancelled after shutdown")
	}
}

func TestOTELProtocolConstants(t *testing.T) {
	if OTELProtocolGRPC != "grpc" {
		t.Errorf("Expected OTELProtocolGRPC='grpc', got %q", OTELProtocolGRPC)
	}
	if OTELProtocolHTTP != "http" {
		t.Errorf("Expected OTELProtocolHTTP='http', got %q", OTELProtocolHTTP)
	}
}

func TestOTELConfig_AllFields(t *testing.T) {
	config := OTELConfig{
		Endpoint:     "test:1234",
		Protocol:     OTELProtocolGRPC,
		PushInterval: 5 * time.Minute,
		Insecure:     false,
	}

	if config.Endpoint != "test:1234" {
		t.Errorf("Expected endpoint 'test:1234', got %q", config.Endpoint)
	}
	if config.Protocol != OTELProtocolGRPC {
		t.Errorf("Expected protocol 'grpc', got %q", config.Protocol)
	}
	if config.PushInterval != 5*time.Minute {
		t.Errorf("Expected 5m, got %v", config.PushInterval)
	}
	if config.Insecure {
		t.Error("Expected insecure=false")
	}
}

func TestOTELExporter_RecordMetrics_WithNodeData(t *testing.T) {
	provider := newMockStreamingProvider()
	provider.scannedNodes = []nodes.NodeWithStatus{
		{Node: nodes.Node{Name: "node-1", Hostname: "node-1.local", Architecture: "amd64"}},
	}
	config := UnifiedConfig{
		DeploymentEnabled:  true,
		NodeScannedEnabled: true,
	}
	e, mock := makeTestOTELExporter(t, provider, defaultOTELConfig(), config)
	defer func() { _ = e.Shutdown() }()

	e.recordMetrics()

	if mock.TotalDataPoints() == 0 {
		t.Error("Expected data points after recording metrics with node data")
	}
}
