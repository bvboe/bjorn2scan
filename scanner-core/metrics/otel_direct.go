package metrics

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpcgzip "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/protobuf/proto"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
)

// DirectOTLPConfig holds configuration for direct OTLP export
type DirectOTLPConfig struct {
	Endpoint       string        // e.g., "http://prometheus:9090/api/v1/otlp" or "otel-collector:4317"
	Protocol       string        // "http" or "grpc"
	Compression    string        // "gzip" (default) or "none"
	BatchSize      int           // Data points per batch (default DefaultDirectBatchSize)
	Timeout        time.Duration // HTTP timeout per request
	MaxRetries     int           // Maximum retry attempts (default 3)
	Insecure       bool          // Allow insecure connections
	ServiceName    string
	ServiceVersion string
	DeploymentName string
	DeploymentUUID string
}

// DefaultDirectBatchSize is the number of data points per OTLP request when
// none is configured.
//
// Left at 5,000 after measurement. A one-pass sweep on a 508,657-point workload
// suggested larger batches were ~12% faster end to end, but a paired A/B run
// reversed the ordering, and the spread across repeats of the *same* setting was
// larger than the effect:
//
//	 5,000 pts/batch -> 102 requests -> 7,214 and 6,601 ms total
//	20,000           ->  26          -> 6,353, 7,105 and 7,440 ms total
//
// Receiver ingest is dominated by per-sample cost, not per-request overhead:
// 5x the requests (batch size 1,000, 509 requests) cost only ~12% more time in
// HTTP, which bounds the per-request component at roughly 1.8 ms. Amortizing
// that over 76 fewer requests is ~140 ms of a ~7,000 ms export — under 2%, well
// inside noise.
//
// So batch size is not a useful lever here, and larger batches make the binding
// constraint worse: an entire batch is accumulated in memory before being
// marshalled and compressed, and memory, not latency, is what limits this
// exporter. Raise it only with evidence from a paired test.
const DefaultDirectBatchSize = 5000

// Supported values for DirectOTLPConfig.Compression. Mirrors the OTEL
// convention for OTEL_EXPORTER_OTLP_COMPRESSION.
const (
	CompressionGzip = "gzip"
	CompressionNone = "none"
)

// gzipEnabled reports whether payloads should be gzip-compressed. Anything other
// than an explicit "none" enables compression, so an empty or unrecognised value
// keeps the (beneficial) default rather than silently sending uncompressed.
func gzipEnabled(compression string) bool {
	return !strings.EqualFold(strings.TrimSpace(compression), CompressionNone)
}

// gzipCompress returns data gzip-compressed at the default level.
// The writer must be closed before the buffer is read — deferring the Close
// would yield a truncated payload.
func gzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.DefaultCompression)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip writer: %w", err)
	}
	if _, err := zw.Write(data); err != nil {
		_ = zw.Close()
		return nil, fmt.Errorf("failed to gzip metrics payload: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize gzip payload: %w", err)
	}
	return buf.Bytes(), nil
}

// DirectOTLPSender is the interface for sending metrics directly via OTLP
type DirectOTLPSender interface {
	Send(ctx context.Context, metrics []*metricsv1.Metric) error
	Close() error
	// Stats returns cumulative wire volume since the sender was created.
	Stats() SenderStats
}

// SenderStats reports how much data a sender has put on the wire. Compressed is
// 0 when the transport compresses opaquely (gRPC does its own framing), so
// callers must treat 0 as "unknown", not "nothing sent".
type SenderStats struct {
	BytesUncompressed uint64
	BytesCompressed   uint64

	// Cumulative time inside each phase of a send. The exporter logs per-cycle
	// deltas of these.
	//
	// Without the split, "send" is one number covering three unrelated costs —
	// protobuf marshalling, gzip and the HTTP round-trip — which is not enough to
	// tell a CPU problem from a network one. On a large deployment sending took 18
	// of a 30-second export, and the total told you nothing about which of the
	// three to attack.
	//
	// Marshal and compress are CPU on the sending pod; HTTP covers the wire plus
	// however long the receiver takes to accept the batch. They are counted per
	// attempt, so retries are included — matching the byte counters above.
	MarshalNanos  uint64
	CompressNanos uint64
	HTTPNanos     uint64
}

// HTTPDirectOTLPSender sends metrics directly via OTLP HTTP
type HTTPDirectOTLPSender struct {
	config     DirectOTLPConfig
	httpClient *http.Client
	resource   *resourcev1.Resource

	bytesUncompressed atomic.Uint64
	bytesCompressed   atomic.Uint64

	marshalNanos  atomic.Uint64
	compressNanos atomic.Uint64
	httpNanos     atomic.Uint64
}

// GRPCDirectOTLPSender sends metrics directly via OTLP gRPC
type GRPCDirectOTLPSender struct {
	config   DirectOTLPConfig
	conn     *grpc.ClientConn
	client   colmetricspb.MetricsServiceClient
	resource *resourcev1.Resource

	// gRPC compresses inside its own framing, so only the pre-compression size
	// is observable here.
	bytesUncompressed atomic.Uint64

	// gRPC marshals and compresses inside Export(), so those phases cannot be
	// timed separately the way they can over HTTP. Everything lands in exportNanos,
	// which is reported as HTTPNanos.
	exportNanos atomic.Uint64
}

// NewDirectOTLPSender creates the appropriate sender based on protocol
func NewDirectOTLPSender(config DirectOTLPConfig) (DirectOTLPSender, error) {
	if config.BatchSize <= 0 {
		config.BatchSize = DefaultDirectBatchSize
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

	if gzipEnabled(config.Compression) {
		// Registered by importing google.golang.org/grpc/encoding/gzip. gRPC sets
		// the grpc-encoding header and negotiates with the server itself.
		opts = append(opts, grpc.WithDefaultCallOptions(grpc.UseCompressor(grpcgzip.Name)))
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

	marshalStart := time.Now()
	data, err := proto.Marshal(request)
	s.marshalNanos.Add(uint64(time.Since(marshalStart)))
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

	body := data
	compressed := gzipEnabled(s.config.Compression)
	if compressed {
		compressStart := time.Now()
		body, err = gzipCompress(data)
		s.compressNanos.Add(uint64(time.Since(compressStart)))
		if err != nil {
			return err
		}
	}
	// Counted per attempt, so retries are included — these are bytes genuinely
	// put on the wire, not logical payload size.
	s.bytesUncompressed.Add(uint64(len(data)))
	s.bytesCompressed.Add(uint64(len(body)))

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-protobuf")
	if compressed {
		req.Header.Set("Content-Encoding", "gzip")
	}

	// Timed around the response body read as well as the round-trip: the receiver
	// streams its reply, so stopping at Do() would undercount how long Prometheus
	// actually took to accept the batch.
	httpStart := time.Now()
	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.httpNanos.Add(uint64(time.Since(httpStart)))
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		s.httpNanos.Add(uint64(time.Since(httpStart)))
		return fmt.Errorf("OTLP export failed with status %d: %s", resp.StatusCode, string(body))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	s.httpNanos.Add(uint64(time.Since(httpStart)))

	return nil
}

// Close closes the HTTP client (no-op for HTTP)
func (s *HTTPDirectOTLPSender) Close() error {
	return nil
}

// Stats reports cumulative wire volume and per-phase timing for this sender.
func (s *HTTPDirectOTLPSender) Stats() SenderStats {
	return SenderStats{
		BytesUncompressed: s.bytesUncompressed.Load(),
		BytesCompressed:   s.bytesCompressed.Load(),
		MarshalNanos:      s.marshalNanos.Load(),
		CompressNanos:     s.compressNanos.Load(),
		HTTPNanos:         s.httpNanos.Load(),
	}
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

	s.bytesUncompressed.Add(uint64(proto.Size(request)))

	exportStart := time.Now()
	_, err := s.client.Export(ctx, request)
	s.exportNanos.Add(uint64(time.Since(exportStart)))
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

// Stats reports cumulative wire volume. BytesCompressed is 0 because gRPC
// compresses inside its own framing, where the post-compression size is not
// visible to the client.
func (s *GRPCDirectOTLPSender) Stats() SenderStats {
	// MarshalNanos and CompressNanos stay zero: gRPC does both inside Export(),
	// so the whole cost is attributed to HTTPNanos rather than guessed at.
	return SenderStats{
		BytesUncompressed: s.bytesUncompressed.Load(),
		HTTPNanos:         s.exportNanos.Load(),
	}
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
	sendDuration time.Duration // cumulative time inside sender.Send
	err          error         // first send error; subsequent Records are no-ops
}

// SendDuration reports how much of the cycle was spent in sender.Send. Collection
// and sending interleave (a full batch flushes mid-collection), so this is the
// only way to separate wire time from serialisation time.
func (a *DirectEmitAccumulator) SendDuration() time.Duration { return a.sendDuration }

// Totals reports what was pushed this cycle.
func (a *DirectEmitAccumulator) Totals() (batches, points int) {
	return a.batchesSent, a.totalPoints
}

// NewDirectEmitAccumulator creates an accumulator for a single metrics collection cycle.
// timeUnixNano should be set once per cycle (e.g. uint64(time.Now().UnixNano())).
func NewDirectEmitAccumulator(ctx context.Context, sender DirectOTLPSender, batchSize int, timeUnixNano uint64) *DirectEmitAccumulator {
	if batchSize <= 0 {
		batchSize = DefaultDirectBatchSize
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

	sendStart := time.Now()
	err := a.sender.Send(a.ctx, metrics)
	a.sendDuration += time.Since(sendStart)
	if err != nil {
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
