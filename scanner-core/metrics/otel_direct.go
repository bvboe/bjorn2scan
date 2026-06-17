package metrics

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
)


// DirectOTLPConfig holds configuration for direct OTLP export
type DirectOTLPConfig struct {
	Endpoint       string        // e.g., "http://prometheus:9090/api/v1/otlp" or "otel-collector:4317"
	Protocol       string        // "http" or "grpc"
	BatchSize      int           // Number of data points per batch (default 5000)
	Timeout        time.Duration // HTTP timeout per request
	MaxRetries     int           // Maximum retry attempts (default 3)
	Insecure       bool          // Allow insecure connections
	ServiceName    string
	ServiceVersion string
	DeploymentName string
	DeploymentUUID string
}

// DirectOTLPSender is the interface for sending metrics directly via OTLP
type DirectOTLPSender interface {
	Send(ctx context.Context, metrics []*metricsv1.Metric) error
	Close() error
}

// HTTPDirectOTLPSender sends metrics directly via OTLP HTTP
type HTTPDirectOTLPSender struct {
	config     DirectOTLPConfig
	httpClient *http.Client
	resource   *resourcev1.Resource
}

// GRPCDirectOTLPSender sends metrics directly via OTLP gRPC
type GRPCDirectOTLPSender struct {
	config   DirectOTLPConfig
	conn     *grpc.ClientConn
	client   colmetricspb.MetricsServiceClient
	resource *resourcev1.Resource
}

// NewDirectOTLPSender creates the appropriate sender based on protocol
func NewDirectOTLPSender(config DirectOTLPConfig) (DirectOTLPSender, error) {
	if config.BatchSize <= 0 {
		config.BatchSize = 5000
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxRetries <= 0 {
		config.MaxRetries = 3
	}

	resource := &resourcev1.Resource{
		Attributes: []*commonv1.KeyValue{
			stringKV("service.name", config.ServiceName),
			stringKV("service.version", config.ServiceVersion),
			stringKV("deployment.name", config.DeploymentName),
			stringKV("deployment.uuid", config.DeploymentUUID),
		},
	}

	protocol := strings.ToLower(config.Protocol)
	switch protocol {
	case "http":
		return newHTTPDirectOTLPSender(config, resource)
	case "grpc":
		return newGRPCDirectOTLPSender(config, resource)
	default:
		return nil, fmt.Errorf("unsupported OTLP protocol: %s (supported: http, grpc)", config.Protocol)
	}
}

func newHTTPDirectOTLPSender(config DirectOTLPConfig, resource *resourcev1.Resource) (*HTTPDirectOTLPSender, error) {
	transport := &http.Transport{}
	if config.Insecure {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &HTTPDirectOTLPSender{
		config: config,
		httpClient: &http.Client{
			Timeout:   config.Timeout,
			Transport: transport,
		},
		resource: resource,
	}, nil
}

func newGRPCDirectOTLPSender(config DirectOTLPConfig, resource *resourcev1.Resource) (*GRPCDirectOTLPSender, error) {
	var opts []grpc.DialOption
	if config.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	}

	conn, err := grpc.NewClient(config.Endpoint, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}

	return &GRPCDirectOTLPSender{
		config:   config,
		conn:     conn,
		client:   colmetricspb.NewMetricsServiceClient(conn),
		resource: resource,
	}, nil
}

// Send sends metrics via HTTP with retry logic
func (s *HTTPDirectOTLPSender) Send(ctx context.Context, metrics []*metricsv1.Metric) error {
	return s.sendWithRetry(ctx, metrics)
}

func (s *HTTPDirectOTLPSender) sendWithRetry(ctx context.Context, metrics []*metricsv1.Metric) error {
	var lastErr error
	for attempt := 0; attempt < s.config.MaxRetries; attempt++ {
		if err := s.sendOnce(ctx, metrics); err == nil {
			return nil
		} else {
			lastErr = err
			// Exponential backoff: 100ms, 200ms, 400ms...
			backoff := time.Duration(100<<attempt) * time.Millisecond
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
	}
	return fmt.Errorf("failed after %d attempts: %w", s.config.MaxRetries, lastErr)
}

func (s *HTTPDirectOTLPSender) sendOnce(ctx context.Context, metrics []*metricsv1.Metric) error {
	request := &metricsv1.MetricsData{
		ResourceMetrics: []*metricsv1.ResourceMetrics{
			{
				Resource: s.resource,
				ScopeMetrics: []*metricsv1.ScopeMetrics{
					{
						Scope: &commonv1.InstrumentationScope{
							Name:    "bjorn2scan",
							Version: s.config.ServiceVersion,
						},
						Metrics: metrics,
					},
				},
			},
		},
	}

	data, err := proto.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal metrics: %w", err)
	}

	// Build endpoint URL - add http:// prefix if no scheme is present
	endpoint := s.config.Endpoint
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		if s.config.Insecure {
			endpoint = "http://" + endpoint
		} else {
			endpoint = "https://" + endpoint
		}
	}
	// Append OTLP metrics path - use Prometheus-compatible path /api/v1/otlp/v1/metrics
	// This matches the SDK configuration in otel.go
	if !strings.Contains(endpoint, "/v1/metrics") {
		if !strings.HasSuffix(endpoint, "/") {
			endpoint += "/"
		}
		endpoint += "api/v1/otlp/v1/metrics"
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-protobuf")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("OTLP export failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Close closes the HTTP client (no-op for HTTP)
func (s *HTTPDirectOTLPSender) Close() error {
	return nil
}

// Send sends metrics via gRPC with retry logic
func (s *GRPCDirectOTLPSender) Send(ctx context.Context, metrics []*metricsv1.Metric) error {
	return s.sendWithRetry(ctx, metrics)
}

func (s *GRPCDirectOTLPSender) sendWithRetry(ctx context.Context, metrics []*metricsv1.Metric) error {
	var lastErr error
	for attempt := 0; attempt < s.config.MaxRetries; attempt++ {
		if err := s.sendOnce(ctx, metrics); err == nil {
			return nil
		} else {
			lastErr = err
			// Exponential backoff: 100ms, 200ms, 400ms...
			backoff := time.Duration(100<<attempt) * time.Millisecond
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
	}
	return fmt.Errorf("failed after %d attempts: %w", s.config.MaxRetries, lastErr)
}

func (s *GRPCDirectOTLPSender) sendOnce(ctx context.Context, metrics []*metricsv1.Metric) error {
	request := &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricsv1.ResourceMetrics{
			{
				Resource: s.resource,
				ScopeMetrics: []*metricsv1.ScopeMetrics{
					{
						Scope: &commonv1.InstrumentationScope{
							Name:    "bjorn2scan",
							Version: s.config.ServiceVersion,
						},
						Metrics: metrics,
					},
				},
			},
		},
	}

	_, err := s.client.Export(ctx, request)
	if err != nil {
		return fmt.Errorf("gRPC export failed: %w", err)
	}

	return nil
}

// Close closes the gRPC connection
func (s *GRPCDirectOTLPSender) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// DirectOTLPExporter sends metrics directly via OTLP without SDK buffering
type DirectOTLPExporter struct {
	config DirectOTLPConfig
	sender DirectOTLPSender
}

// NewDirectOTLPExporter creates a new direct OTLP exporter
func NewDirectOTLPExporter(config DirectOTLPConfig) (*DirectOTLPExporter, error) {
	sender, err := NewDirectOTLPSender(config)
	if err != nil {
		return nil, err
	}

	return &DirectOTLPExporter{
		config: config,
		sender: sender,
	}, nil
}

// Close closes the exporter
func (e *DirectOTLPExporter) Close() error {
	if e.sender != nil {
		return e.sender.Close()
	}
	return nil
}

// DirectEmitAccumulator accumulates metric data points and sends them via DirectOTLPSender
// in bounded batches. It implements the emit(familyName, help, labels, value) callback
// pattern used by collectMetrics, routing all metrics — including node vulnerabilities —
// through a single transport path without any SDK buffering.
//
// Usage:
//
//	acc := NewDirectEmitAccumulator(ctx, sender, batchSize, timeUnixNano)
//	collectMetrics(provider, config, ..., acc.Record, onBatchFull)
//	if err := acc.Flush(); err != nil { ... }
type DirectEmitAccumulator struct {
	ctx          context.Context
	sender       DirectOTLPSender
	batchSize    int
	timeUnixNano uint64
	pending      map[string]*metricsv1.Metric // keyed by familyName
	pendingCount int
	batchesSent  int
	totalPoints  int
	err          error // first send error; subsequent Records are no-ops
}

// NewDirectEmitAccumulator creates an accumulator for a single metrics collection cycle.
// timeUnixNano should be set once per cycle (e.g. uint64(time.Now().UnixNano())).
func NewDirectEmitAccumulator(ctx context.Context, sender DirectOTLPSender, batchSize int, timeUnixNano uint64) *DirectEmitAccumulator {
	if batchSize <= 0 {
		batchSize = 5000
	}
	return &DirectEmitAccumulator{
		ctx:          ctx,
		sender:       sender,
		batchSize:    batchSize,
		timeUnixNano: timeUnixNano,
		pending:      make(map[string]*metricsv1.Metric),
	}
}

// Record adds a data point for the given metric family. NaN values pass through as-is
// (IEEE 754 NaN is valid in protobuf double — Prometheus interprets them as stale markers).
// If a mid-stream flush fails, the error is stored and subsequent calls are no-ops;
// the error is returned by Flush().
func (a *DirectEmitAccumulator) Record(familyName, help string, labels map[string]string, value float64) {
	if a.err != nil {
		return
	}

	m, ok := a.pending[familyName]
	if !ok {
		m = &metricsv1.Metric{
			Name:        familyName,
			Description: help,
			Data:        &metricsv1.Metric_Gauge{Gauge: &metricsv1.Gauge{}},
		}
		a.pending[familyName] = m
	}

	attrs := make([]*commonv1.KeyValue, 0, len(labels))
	for k, v := range labels {
		attrs = append(attrs, stringKV(k, v))
	}
	m.GetGauge().DataPoints = append(m.GetGauge().DataPoints, &metricsv1.NumberDataPoint{
		Attributes:   attrs,
		TimeUnixNano: a.timeUnixNano,
		Value:        &metricsv1.NumberDataPoint_AsDouble{AsDouble: value},
	})
	a.pendingCount++

	if a.pendingCount >= a.batchSize {
		if err := a.flush(); err != nil {
			a.err = err
		}
	}
}

// Flush sends any remaining pending data points. Must be called after all Record calls.
// Returns the first error encountered during any flush (including mid-stream flushes).
func (a *DirectEmitAccumulator) Flush() error {
	if a.err != nil {
		return a.err
	}
	if err := a.flush(); err != nil {
		return err
	}
	if a.totalPoints > 0 || a.batchesSent > 0 {
		log.Debug("sent data points to OTLP",
			"total_points", a.totalPoints,
			"batch_count", a.batchesSent)
	}
	return nil
}

func (a *DirectEmitAccumulator) flush() error {
	if a.pendingCount == 0 {
		return nil
	}

	metrics := make([]*metricsv1.Metric, 0, len(a.pending))
	for _, m := range a.pending {
		if len(m.GetGauge().DataPoints) > 0 {
			metrics = append(metrics, m)
		}
	}

	if len(metrics) == 0 {
		return nil
	}

	if err := a.sender.Send(a.ctx, metrics); err != nil {
		return fmt.Errorf("failed to send batch %d: %w", a.batchesSent, err)
	}

	a.batchesSent++
	a.totalPoints += a.pendingCount

	// Reset pending for the next batch
	a.pending = make(map[string]*metricsv1.Metric)
	a.pendingCount = 0
	return nil
}

// Helper to create string KeyValue
func stringKV(key, value string) *commonv1.KeyValue {
	return &commonv1.KeyValue{
		Key:   key,
		Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: value}},
	}
}
