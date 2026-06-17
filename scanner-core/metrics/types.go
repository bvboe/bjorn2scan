package metrics

import (
	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// MetricPoint represents a single metric observation with labels and value
type MetricPoint struct {
	Labels map[string]string
	Value  float64
}

// MetricFamily represents a family of metrics (e.g., all bjorn2scan_deployment metrics)
type MetricFamily struct {
	Name    string        // Metric name (e.g., "bjorn2scan_deployment")
	Help    string        // Help text
	Type    string        // Metric type (e.g., "gauge")
	Metrics []MetricPoint // All metric points in this family
}

// MetricsData holds all metrics to be exported
type MetricsData struct {
	Families []MetricFamily
}

// UnifiedConfig holds all configuration for the unified metrics handler.
// It merges CollectorConfig and NodeCollectorConfig into a single struct.
type UnifiedConfig struct {
	// Image/container metrics
	DeploymentEnabled             bool
	ScannedContainersEnabled      bool
	VulnerabilitiesEnabled        bool
	VulnerabilityExploitedEnabled bool
	VulnerabilityRiskEnabled      bool
	ImageScanStatusEnabled        bool
	// Node metrics
	NodeScannedEnabled                bool
	NodeScanStatusEnabled             bool
	NodeVulnerabilitiesEnabled        bool
	NodeVulnerabilityRiskEnabled      bool
	NodeVulnerabilityExploitedEnabled bool
	// Staleness
	StalenessWindow int64 // Staleness window in seconds (use cfg.MetricsStalenessWindow.Seconds())
}

// StreamingProvider is the unified database interface required by the new metrics handler.
// It combines streaming access to container and node data with staleness persistence.
// *database.DB satisfies this interface.
type StreamingProvider interface {
	// Container data (streaming — avoids loading all vulnerabilities into memory)
	StreamScannedContainers(func(database.ScannedContainer) error) error
	StreamContainerVulnerabilities(func(database.ContainerVulnerability) error) error
	GetImageScanStatusCounts() ([]database.ImageScanStatusCount, error)
	// Node data
	GetScannedNodes() ([]nodes.NodeWithStatus, error)
	GetNodeScanStatusCounts() ([]database.NodeScanStatusCount, error)
	StreamNodeVulnerabilitiesForMetrics(func(database.NodeVulnerabilityForMetrics) error) error
	// Staleness persistence (backed by the metric_staleness table; key_hash schema added in v48).
	// HydrateStalenessState is called once at StalenessStore construction; ApplyStalenessChanges
	// commits each cycle's diff in a single transaction.
	QueryStaleness(cycleStart int64) ([]database.StalenessRow, error)
	HydrateStalenessState() (map[uint64]int64, error)
	ApplyStalenessChanges(toUpsert []database.StalenessRow, toStale []uint64, expiresAtUnix int64) error
	DeleteExpiredStaleness(expireBefore int64) error
}
