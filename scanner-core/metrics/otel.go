package metrics

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// OTELProtocol represents the protocol to use for OTLP
type OTELProtocol string

const (
	// OTELProtocolGRPC uses gRPC for OTLP communication
	OTELProtocolGRPC OTELProtocol = "grpc"
	// OTELProtocolHTTP uses HTTP for OTLP communication
	OTELProtocolHTTP OTELProtocol = "http"
)

// OTELConfig holds OpenTelemetry configuration
type OTELConfig struct {
	Endpoint     string
	Protocol     OTELProtocol
	PushInterval time.Duration
	Insecure     bool
	Compression  string // "gzip" (default) or "none"
	// UseDirectExport is deprecated. Direct export is now always used. This field is ignored.
	UseDirectExport bool
	DirectBatchSize int // Batch size for direct export (default 5000)
}

// OTELExporter exports metrics to an OpenTelemetry collector via direct OTLP.
// All metrics (including high-cardinality node vulnerabilities) are streamed in bounded
// batches — no SDK buffering, no in-memory gauge store, single timer.
type OTELExporter struct {
	provider       StreamingProvider
	unifiedConfig  UnifiedConfig
	config         OTELConfig
	sender         DirectOTLPSender
	ctx            context.Context
	cancel         context.CancelFunc
	infoProvider   InfoProvider
	deploymentUUID string
	staleness      *StalenessStore

	// Sender counters are cumulative; these hold the previous reading so each
	// log line reports the delta for that cycle.
	lastBytesUncompressed uint64
	lastBytesCompressed   uint64
}

// NewOTELExporter creates a new OTEL metrics exporter.
// provider must implement StreamingProvider (e.g. *database.DB).
// staleness is shared with the Prometheus handler for consistent NaN behaviour.
func NewOTELExporter(
	ctx context.Context,
	infoProvider InfoProvider,
	deploymentUUID string,
	provider StreamingProvider,
	unifiedConfig UnifiedConfig,
	config OTELConfig,
	staleness *StalenessStore,
) (*OTELExporter, error) {
	batchSize := config.DirectBatchSize
	if batchSize <= 0 {
		batchSize = 5000
	}

	directCfg := DirectOTLPConfig{
		Endpoint:       config.Endpoint,
		Protocol:       strings.ToLower(string(config.Protocol)),
		BatchSize:      batchSize,
		Timeout:        30 * time.Second,
		MaxRetries:     3,
		Insecure:       config.Insecure,
		Compression:    config.Compression,
		ServiceName:    "bjorn2scan",
		ServiceVersion: infoProvider.GetVersion(),
		DeploymentName: infoProvider.GetDeploymentName(),
		DeploymentUUID: deploymentUUID,
	}

	sender, err := NewDirectOTLPSender(directCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP sender: %w", err)
	}

	exporterCtx, cancel := context.WithCancel(ctx)

	return &OTELExporter{
		provider:       provider,
		unifiedConfig:  unifiedConfig,
		config:         config,
		sender:         sender,
		ctx:            exporterCtx,
		cancel:         cancel,
		infoProvider:   infoProvider,
		deploymentUUID: deploymentUUID,
		staleness:      staleness,
	}, nil
}

// setSender replaces the underlying sender (for testing).
func (e *OTELExporter) setSender(sender DirectOTLPSender) {
	if e.sender != nil {
		_ = e.sender.Close()
	}
	e.sender = sender
}

// Start begins pushing metrics to the OTEL collector
func (e *OTELExporter) Start() {
	go e.pushMetrics()
}

// pushMetrics periodically collects and pushes metrics
func (e *OTELExporter) pushMetrics() {
	// Push immediately on start
	e.recordMetrics()

	ticker := time.NewTicker(e.config.PushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			e.recordMetrics()
		case <-e.ctx.Done():
			return
		}
	}
}

// recordMetrics collects all metrics and sends them via the direct OTLP sender.
// All metric families — including node vulnerabilities — go through the same
// bounded-batch accumulator. No SDK, no in-memory gauge store, no second timer.
func (e *OTELExporter) recordMetrics() {
	cycleStart := time.Now()
	deploymentName := e.infoProvider.GetDeploymentName()
	cycleStartUnix := cycleStart.Unix()
	timeUnixNano := uint64(cycleStart.UnixNano())

	stalenessStart := time.Now()
	staleRows, err := e.staleness.QueryStale(cycleStart)
	if err != nil {
		log.Error("failed to query stale metrics for OTEL", "error", err)
	}
	stalenessMS := time.Since(stalenessStart).Milliseconds()

	batchSize := e.config.DirectBatchSize
	if batchSize <= 0 {
		batchSize = 5000
	}

	accumulator := NewDirectEmitAccumulator(e.ctx, e.sender, batchSize, timeUnixNano)

	remaining, err := collectMetrics(e.provider, e.unifiedConfig, e.infoProvider, e.deploymentUUID,
		deploymentName, cycleStartUnix, staleRows, 0, accumulator.Record, nil)
	if err != nil {
		log.Error("error collecting metrics for OTEL", "error", err)
	}

	if err := accumulator.Flush(); err != nil {
		log.Error("error flushing OTEL metrics", "error", err)
	}

	go func() {
		if err := e.staleness.ApplyDiff(remaining, cycleStart); err != nil {
			log.Warn("failed to apply staleness diff in OTEL exporter", "error", err)
		}
		e.staleness.DeleteExpired(cycleStart)
	}()

	// Collection and sending interleave — a full batch flushes mid-collection — so
	// wire time is measured inside the accumulator and collection is the remainder.
	// bytes_compressed is 0 for gRPC, which compresses inside its own framing.
	batches, points := accumulator.Totals()
	sendMS := accumulator.SendDuration().Milliseconds()
	totalMS := time.Since(cycleStart).Milliseconds()
	stats := e.sender.Stats()

	fields := []any{
		"duration_ms", totalMS,
		"staleness_ms", stalenessMS,
		"send_ms", sendMS,
		"collect_ms", totalMS - sendMS - stalenessMS,
		"batches", batches,
		"data_points", points,
		"bytes_uncompressed", stats.BytesUncompressed - e.lastBytesUncompressed,
		"bytes_compressed", stats.BytesCompressed - e.lastBytesCompressed,
	}
	if sent := stats.BytesCompressed - e.lastBytesCompressed; sent > 0 {
		fields = append(fields, "compression_ratio",
			float64(stats.BytesUncompressed-e.lastBytesUncompressed)/float64(sent))
	}
	e.lastBytesUncompressed = stats.BytesUncompressed
	e.lastBytesCompressed = stats.BytesCompressed

	log.Info("OTEL export complete", fields...)
}

// Shutdown gracefully shuts down the OTEL exporter
func (e *OTELExporter) Shutdown() error {
	e.cancel()
	if e.sender != nil {
		return e.sender.Close()
	}
	return nil
}
