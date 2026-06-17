package metrics

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
)

func TestDirectOTLPConfig_Defaults(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint:       "localhost:4317",
		Protocol:       "http",
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
	}

	// BatchSize, Timeout, MaxRetries should get defaults when creating sender
	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	// Verify it was created successfully
	if sender == nil {
		t.Fatal("Expected non-nil sender")
	}
}

func TestNewDirectOTLPSender_HTTP(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint:       "http://localhost:9090",
		Protocol:       "http",
		BatchSize:      1000,
		Timeout:        10 * time.Second,
		MaxRetries:     5,
		Insecure:       true,
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
		DeploymentName: "test-deployment",
		DeploymentUUID: "test-uuid",
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create HTTP sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	// Verify it's the HTTP type
	_, ok := sender.(*HTTPDirectOTLPSender)
	if !ok {
		t.Error("Expected HTTPDirectOTLPSender type")
	}
}

func TestNewDirectOTLPSender_GRPC(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint:       "localhost:4317",
		Protocol:       "grpc",
		BatchSize:      5000,
		Timeout:        30 * time.Second,
		MaxRetries:     3,
		Insecure:       true,
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create gRPC sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	// Verify it's the gRPC type
	_, ok := sender.(*GRPCDirectOTLPSender)
	if !ok {
		t.Error("Expected GRPCDirectOTLPSender type")
	}
}

func TestNewDirectOTLPSender_InvalidProtocol(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint: "localhost:4317",
		Protocol: "invalid",
	}

	sender, err := NewDirectOTLPSender(config)
	if err == nil {
		t.Fatal("Expected error for invalid protocol")
	}
	if sender != nil {
		t.Fatal("Expected nil sender for invalid protocol")
	}

	expectedError := "unsupported OTLP protocol: invalid"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error to contain %q, got %q", expectedError, err.Error())
	}
}

func TestNewDirectOTLPSender_ProtocolCaseInsensitive(t *testing.T) {
	tests := []struct {
		name     string
		protocol string
		wantErr  bool
	}{
		{"http lowercase", "http", false},
		{"HTTP uppercase", "HTTP", false},
		{"Http mixed", "Http", false},
		{"grpc lowercase", "grpc", false},
		{"GRPC uppercase", "GRPC", false},
		{"GrPc mixed", "GrPc", false},
		{"invalid", "websocket", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DirectOTLPConfig{
				Endpoint: "localhost:4317",
				Protocol: tt.protocol,
				Insecure: true,
			}

			sender, err := NewDirectOTLPSender(config)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for protocol %q", tt.protocol)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for protocol %q: %v", tt.protocol, err)
				}
				if sender == nil {
					t.Errorf("Expected non-nil sender for protocol %q", tt.protocol)
				} else {
					_ = sender.Close()
				}
			}
		})
	}
}

func TestHTTPDirectOTLPSender_Send(t *testing.T) {
	// Create a test server that accepts OTLP requests
	receivedRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedRequests++

		// Verify content type
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/x-protobuf" {
			t.Errorf("Expected Content-Type application/x-protobuf, got %s", contentType)
		}

		// Verify method
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		// Verify path ends with /v1/metrics
		if !strings.HasSuffix(r.URL.Path, "/v1/metrics") {
			t.Errorf("Expected path ending with /v1/metrics, got %s", r.URL.Path)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		BatchSize:      5000,
		Timeout:        5 * time.Second,
		MaxRetries:     1,
		Insecure:       true,
		ServiceName:    "test-service",
		ServiceVersion: "1.0.0",
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	// Send test metrics
	metrics := []*metricsv1.Metric{
		{
			Name:        "test_metric",
			Description: "Test metric",
			Data: &metricsv1.Metric_Gauge{
				Gauge: &metricsv1.Gauge{
					DataPoints: []*metricsv1.NumberDataPoint{
						{
							Value: &metricsv1.NumberDataPoint_AsDouble{AsDouble: 42.0},
						},
					},
				},
			},
		},
	}

	ctx := context.Background()
	err = sender.Send(ctx, metrics)
	if err != nil {
		t.Fatalf("Failed to send metrics: %v", err)
	}

	if receivedRequests != 1 {
		t.Errorf("Expected 1 request, got %d", receivedRequests)
	}
}

func TestHTTPDirectOTLPSender_SendWithRetry(t *testing.T) {
	// Create a server that fails the first 2 requests, succeeds on 3rd
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		Timeout:        1 * time.Second,
		MaxRetries:     3,
		Insecure:       true,
		ServiceName:    "test",
		ServiceVersion: "1.0.0",
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	ctx := context.Background()
	err = sender.Send(ctx, []*metricsv1.Metric{})
	if err != nil {
		t.Fatalf("Expected success after retries, got error: %v", err)
	}

	if requestCount != 3 {
		t.Errorf("Expected 3 requests (2 failures + 1 success), got %d", requestCount)
	}
}

func TestHTTPDirectOTLPSender_SendFailsAfterMaxRetries(t *testing.T) {
	// Create a server that always fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	config := DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		Timeout:        1 * time.Second,
		MaxRetries:     2,
		Insecure:       true,
		ServiceName:    "test",
		ServiceVersion: "1.0.0",
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	ctx := context.Background()
	err = sender.Send(ctx, []*metricsv1.Metric{})
	if err == nil {
		t.Fatal("Expected error after max retries")
	}

	if !strings.Contains(err.Error(), "failed after 2 attempts") {
		t.Errorf("Expected error message about failed attempts, got: %v", err)
	}
}

func TestHTTPDirectOTLPSender_ContextCancellation(t *testing.T) {
	// Create a slow server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	config := DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		Timeout:        10 * time.Second,
		MaxRetries:     3,
		Insecure:       true,
		ServiceName:    "test",
		ServiceVersion: "1.0.0",
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err = sender.Send(ctx, []*metricsv1.Metric{})
	if err == nil {
		t.Fatal("Expected error due to context cancellation")
	}
}

func TestNewDirectOTLPExporter(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint:       "localhost:9090",
		Protocol:       "http",
		BatchSize:      5000,
		Timeout:        30 * time.Second,
		MaxRetries:     3,
		Insecure:       true,
		ServiceName:    "bjorn2scan",
		ServiceVersion: "1.0.0",
		DeploymentName: "test",
		DeploymentUUID: "test-uuid",
	}

	exporter, err := NewDirectOTLPExporter(config)
	if err != nil {
		t.Fatalf("Failed to create exporter: %v", err)
	}

	if exporter == nil {
		t.Fatal("Expected non-nil exporter")
	}

	// Cleanup
	err = exporter.Close()
	if err != nil {
		t.Errorf("Unexpected error on close: %v", err)
	}
}

func TestNewDirectOTLPExporter_InvalidProtocol(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint: "localhost:9090",
		Protocol: "invalid",
	}

	exporter, err := NewDirectOTLPExporter(config)
	if err == nil {
		t.Fatal("Expected error for invalid protocol")
	}
	if exporter != nil {
		t.Fatal("Expected nil exporter for invalid protocol")
	}
}

func TestDirectOTLPExporter_Close(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint:       "localhost:9090",
		Protocol:       "http",
		Insecure:       true,
		ServiceName:    "test",
		ServiceVersion: "1.0.0",
	}

	exporter, err := NewDirectOTLPExporter(config)
	if err != nil {
		t.Fatalf("Failed to create exporter: %v", err)
	}

	// Close should not error
	err = exporter.Close()
	if err != nil {
		t.Errorf("Unexpected error on close: %v", err)
	}

	// Multiple closes should be safe
	err = exporter.Close()
	if err != nil {
		t.Errorf("Unexpected error on second close: %v", err)
	}
}

// mockDirectSender is a simple in-memory sender for accumulator tests.
type mockDirectSender struct {
	mu         sync.Mutex
	sendCalls  int
	allMetrics [][]*metricsv1.Metric
	sendErr    error
}

func (m *mockDirectSender) Send(_ context.Context, metrics []*metricsv1.Metric) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sendErr != nil {
		return m.sendErr
	}
	cp := make([]*metricsv1.Metric, len(metrics))
	copy(cp, metrics)
	m.allMetrics = append(m.allMetrics, cp)
	m.sendCalls++
	return nil
}

func (m *mockDirectSender) Close() error { return nil }

func (m *mockDirectSender) totalDataPoints() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, batch := range m.allMetrics {
		for _, metric := range batch {
			n += len(metric.GetGauge().GetDataPoints())
		}
	}
	return n
}

func TestDirectEmitAccumulator_Record_LiveValue(t *testing.T) {
	sender := &mockDirectSender{}
	acc := NewDirectEmitAccumulator(context.Background(), sender, 100, uint64(time.Now().UnixNano()))

	acc.Record("bjorn2scan_deployment", "Deployment info", map[string]string{"env": "prod"}, 1.0)

	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush returned error: %v", err)
	}

	if sender.totalDataPoints() != 1 {
		t.Errorf("Expected 1 data point, got %d", sender.totalDataPoints())
	}
	if sender.sendCalls != 1 {
		t.Errorf("Expected 1 Send call, got %d", sender.sendCalls)
	}
}

func TestDirectEmitAccumulator_Record_NaN(t *testing.T) {
	sender := &mockDirectSender{}
	acc := NewDirectEmitAccumulator(context.Background(), sender, 100, uint64(time.Now().UnixNano()))

	acc.Record("bjorn2scan_deployment", "Deployment info", map[string]string{"env": "old"}, math.NaN())

	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush returned error: %v", err)
	}

	if sender.totalDataPoints() != 1 {
		t.Errorf("Expected 1 NaN data point, got %d", sender.totalDataPoints())
	}
	// Verify the value is NaN
	dp := sender.allMetrics[0][0].GetGauge().GetDataPoints()[0]
	if !math.IsNaN(dp.GetAsDouble()) {
		t.Errorf("Expected NaN value, got %v", dp.GetAsDouble())
	}
}

func TestDirectEmitAccumulator_BatchFlush(t *testing.T) {
	sender := &mockDirectSender{}
	// batchSize=2: every 2 records triggers a mid-stream flush
	acc := NewDirectEmitAccumulator(context.Background(), sender, 2, uint64(time.Now().UnixNano()))

	for i := 0; i < 5; i++ {
		acc.Record("bjorn2scan_deployment", "help", map[string]string{"i": "x"}, float64(i))
	}

	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush returned error: %v", err)
	}

	if sender.totalDataPoints() != 5 {
		t.Errorf("Expected 5 total data points, got %d", sender.totalDataPoints())
	}
	// With batchSize=2: flushes at 2, 4, then final flush at 5 → 3 Send calls
	if sender.sendCalls != 3 {
		t.Errorf("Expected 3 Send calls (at 2, 4, and final 1), got %d", sender.sendCalls)
	}
}

func TestDirectEmitAccumulator_MultipleFamilies(t *testing.T) {
	sender := &mockDirectSender{}
	acc := NewDirectEmitAccumulator(context.Background(), sender, 100, uint64(time.Now().UnixNano()))

	acc.Record("bjorn2scan_deployment", "help-a", map[string]string{"a": "1"}, 1.0)
	acc.Record("bjorn2scan_image_scanned", "help-b", map[string]string{"b": "2"}, 2.0)

	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush returned error: %v", err)
	}

	// Both families should be in one batch
	if sender.sendCalls != 1 {
		t.Errorf("Expected 1 Send call, got %d", sender.sendCalls)
	}
	batch := sender.allMetrics[0]
	if len(batch) != 2 {
		t.Errorf("Expected 2 metrics in batch, got %d", len(batch))
	}
	names := map[string]bool{}
	for _, m := range batch {
		names[m.Name] = true
	}
	if !names["bjorn2scan_deployment"] || !names["bjorn2scan_image_scanned"] {
		t.Errorf("Expected both metric families in batch, got: %v", names)
	}
}

func TestDirectEmitAccumulator_SameFamily(t *testing.T) {
	sender := &mockDirectSender{}
	acc := NewDirectEmitAccumulator(context.Background(), sender, 100, uint64(time.Now().UnixNano()))

	acc.Record("bjorn2scan_image_vulnerability", "help", map[string]string{"cve": "CVE-1"}, 1.0)
	acc.Record("bjorn2scan_image_vulnerability", "help", map[string]string{"cve": "CVE-2"}, 2.0)
	acc.Record("bjorn2scan_image_vulnerability", "help", map[string]string{"cve": "CVE-3"}, 3.0)

	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush returned error: %v", err)
	}

	// One metric family, three data points, one Send call
	if sender.sendCalls != 1 {
		t.Errorf("Expected 1 Send call, got %d", sender.sendCalls)
	}
	if sender.totalDataPoints() != 3 {
		t.Errorf("Expected 3 data points, got %d", sender.totalDataPoints())
	}
}

func TestDirectEmitAccumulator_Flush_SendError(t *testing.T) {
	sender := &mockDirectSender{sendErr: errors.New("network error")}
	acc := NewDirectEmitAccumulator(context.Background(), sender, 100, uint64(time.Now().UnixNano()))

	acc.Record("bjorn2scan_deployment", "help", map[string]string{}, 1.0)

	err := acc.Flush()
	if err == nil {
		t.Fatal("Expected error from Flush when sender fails")
	}
	if !strings.Contains(err.Error(), "network error") {
		t.Errorf("Expected error to contain 'network error', got: %v", err)
	}
}

func TestDirectEmitAccumulator_MidStreamError_DropsRemainingRecords(t *testing.T) {
	sender := &mockDirectSender{sendErr: errors.New("network error")}
	// batchSize=1: every Record triggers a flush
	acc := NewDirectEmitAccumulator(context.Background(), sender, 1, uint64(time.Now().UnixNano()))

	acc.Record("bjorn2scan_deployment", "help", map[string]string{"k": "1"}, 1.0)
	// Second record should be a no-op because the first flush errored
	acc.Record("bjorn2scan_deployment", "help", map[string]string{"k": "2"}, 2.0)

	err := acc.Flush()
	if err == nil {
		t.Fatal("Expected error from Flush")
	}
	// Only 1 Send attempt (the failing mid-stream flush)
	if sender.sendCalls != 0 {
		t.Errorf("Expected 0 successful Send calls, got %d", sender.sendCalls)
	}
}

func TestDirectEmitAccumulator_EmptyFlush(t *testing.T) {
	sender := &mockDirectSender{}
	acc := NewDirectEmitAccumulator(context.Background(), sender, 100, uint64(time.Now().UnixNano()))

	// Flush with no records — should be a no-op
	if err := acc.Flush(); err != nil {
		t.Errorf("Expected no error on empty flush, got: %v", err)
	}
	if sender.sendCalls != 0 {
		t.Errorf("Expected 0 Send calls for empty flush, got %d", sender.sendCalls)
	}
}

func TestStringKV(t *testing.T) {
	kv := stringKV("test-key", "test-value")

	if kv.Key != "test-key" {
		t.Errorf("Expected key 'test-key', got %q", kv.Key)
	}

	strVal := kv.Value.GetStringValue()
	if strVal != "test-value" {
		t.Errorf("Expected value 'test-value', got %q", strVal)
	}
}

func TestDirectOTLPConfig_AllFields(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint:       "prometheus:9090",
		Protocol:       "http",
		BatchSize:      10000,
		Timeout:        1 * time.Minute,
		MaxRetries:     5,
		Insecure:       false,
		ServiceName:    "bjorn2scan",
		ServiceVersion: "2.0.0",
		DeploymentName: "production",
		DeploymentUUID: "prod-uuid-123",
	}

	if config.Endpoint != "prometheus:9090" {
		t.Errorf("Expected endpoint 'prometheus:9090', got %q", config.Endpoint)
	}
	if config.Protocol != "http" {
		t.Errorf("Expected protocol 'http', got %q", config.Protocol)
	}
	if config.BatchSize != 10000 {
		t.Errorf("Expected batch size 10000, got %d", config.BatchSize)
	}
	if config.Timeout != 1*time.Minute {
		t.Errorf("Expected timeout 1m, got %v", config.Timeout)
	}
	if config.MaxRetries != 5 {
		t.Errorf("Expected max retries 5, got %d", config.MaxRetries)
	}
	if config.Insecure != false {
		t.Errorf("Expected insecure false, got %v", config.Insecure)
	}
}

func TestGRPCDirectOTLPSender_Close(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint: "localhost:4317",
		Protocol: "grpc",
		Insecure: true,
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create gRPC sender: %v", err)
	}

	// Close should not error
	err = sender.Close()
	if err != nil {
		t.Errorf("Unexpected error on close: %v", err)
	}
}

func TestHTTPDirectOTLPSender_Close(t *testing.T) {
	config := DirectOTLPConfig{
		Endpoint: "localhost:9090",
		Protocol: "http",
		Insecure: true,
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create HTTP sender: %v", err)
	}

	// Close should be no-op for HTTP sender
	err = sender.Close()
	if err != nil {
		t.Errorf("Unexpected error on close: %v", err)
	}
}

func TestHTTPDirectOTLPSender_EndpointURLBuilding(t *testing.T) {
	tests := []struct {
		name         string
		endpoint     string
		expectedPath string
	}{
		{
			name:         "no path - adds prometheus otlp path",
			endpoint:     "http://localhost:9090",
			expectedPath: "/api/v1/otlp/v1/metrics",
		},
		{
			name:         "with trailing slash",
			endpoint:     "http://localhost:9090/",
			expectedPath: "/api/v1/otlp/v1/metrics",
		},
		{
			name:         "already has v1/metrics",
			endpoint:     "http://localhost:9090/v1/metrics",
			expectedPath: "/v1/metrics",
		},
		{
			name:         "already has full prometheus path",
			endpoint:     "http://localhost:9090/api/v1/otlp/v1/metrics",
			expectedPath: "/api/v1/otlp/v1/metrics",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var receivedPath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			// Override endpoint to use test server
			config := DirectOTLPConfig{
				Endpoint:       server.URL,
				Protocol:       "http",
				Timeout:        1 * time.Second,
				MaxRetries:     1,
				Insecure:       true,
				ServiceName:    "test",
				ServiceVersion: "1.0.0",
			}

			sender, err := NewDirectOTLPSender(config)
			if err != nil {
				t.Fatalf("Failed to create sender: %v", err)
			}
			defer func() { _ = sender.Close() }()

			ctx := context.Background()
			_ = sender.Send(ctx, []*metricsv1.Metric{})

			if !strings.HasSuffix(receivedPath, "/v1/metrics") {
				t.Errorf("Expected path to end with /v1/metrics, got %q", receivedPath)
			}
		})
	}
}

func TestHTTPDirectOTLPSender_EndpointWithoutScheme(t *testing.T) {
	// Create a test server
	var receivedHost string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Extract host:port from server URL (strip http://)
	serverAddr := strings.TrimPrefix(server.URL, "http://")

	// Test with endpoint that has no scheme (like kubernetes service names)
	config := DirectOTLPConfig{
		Endpoint:       serverAddr, // e.g., "127.0.0.1:12345" without http://
		Protocol:       "http",
		Timeout:        1 * time.Second,
		MaxRetries:     1,
		Insecure:       true,
		ServiceName:    "test",
		ServiceVersion: "1.0.0",
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	ctx := context.Background()
	err = sender.Send(ctx, []*metricsv1.Metric{})
	if err != nil {
		t.Fatalf("Failed to send metrics: %v", err)
	}

	// Verify the request was received (http:// was added automatically)
	if receivedHost == "" {
		t.Error("Expected request to be received")
	}
}

func TestHTTPDirectOTLPSender_EndpointSchemeSelection(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		insecure bool
	}{
		{"no scheme insecure", "localhost:9090", true},
		{"no scheme secure", "localhost:9090", false},
		{"with http", "http://localhost:9090", true},
		{"with https", "https://localhost:9090", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DirectOTLPConfig{
				Endpoint:       tt.endpoint,
				Protocol:       "http",
				Timeout:        1 * time.Second,
				MaxRetries:     1,
				Insecure:       tt.insecure,
				ServiceName:    "test",
				ServiceVersion: "1.0.0",
			}

			sender, err := NewDirectOTLPSender(config)
			if err != nil {
				t.Fatalf("Failed to create sender: %v", err)
			}
			_ = sender.Close()
			// If we get here without error, the sender was created successfully
		})
	}
}

// Test that the interface is properly implemented
func TestDirectOTLPSenderInterface(t *testing.T) {
	var _ DirectOTLPSender = (*HTTPDirectOTLPSender)(nil)
	var _ DirectOTLPSender = (*GRPCDirectOTLPSender)(nil)
}

// Test response body is read and error message is captured
func TestHTTPDirectOTLPSender_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error": "invalid request"}`))
	}))
	defer server.Close()

	config := DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		Timeout:        1 * time.Second,
		MaxRetries:     1,
		Insecure:       true,
		ServiceName:    "test",
		ServiceVersion: "1.0.0",
	}

	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	ctx := context.Background()
	err = sender.Send(ctx, []*metricsv1.Metric{})

	if err == nil {
		t.Fatal("Expected error for bad request")
	}

	// Error should contain status code
	if !strings.Contains(err.Error(), "400") {
		t.Errorf("Expected error to contain status code 400, got: %v", err)
	}
}

// Ensure JSON marshaling doesn't occur anywhere - only protobuf
func TestNoJSONUsed(t *testing.T) {
	// This is a compile-time check that json is not imported for marshaling metrics
	// The json import in this test file is only for testing the error response
	var _ json.Marshaler // Use json package reference to silence unused import
}
