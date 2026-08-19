// Package metrics provides Prometheus metrics exposition for bjorn2scan.
package metrics

// containerInfo holds common container information used for building metric labels
type containerInfo struct {
	NodeName  string
	Namespace string
	Pod       string
	Name      string
	Reference string
	Digest    string
	OSName    string
	Arch      string
}

// Note: the pre-joined "hierarchical" attributes (deployment_uuid_namespace,
// deployment_uuid_namespace_pod_container, ...) used to be built here and emitted
// on every container/image datapoint. They were synthetic join keys for Grafana's
// joinByField transform, which can only join on a single field. Dashboards now
// derive them at query time with PromQL label_join(...), so they are no longer
// exported — see docs/OTEL-DATA-ARCHITECTURE.md.

// InfoProvider provides deployment information for metrics labels
type InfoProvider interface {
	GetDeploymentName() string // hostname for agent, cluster name for k8s
	GetDeploymentType() string // "agent" or "kubernetes"
	GetVersion() string
	GetDeploymentIP() string // primary outbound IP for agent, node IP for k8s
	GetConsoleURL() string   // web UI URL (empty if disabled)
	GetGrypeDBBuilt() string // grype vulnerability database build timestamp (RFC3339 format, empty if unavailable)
}

// CollectorConfig holds configuration for which metrics to collect.
// Kept for backward compatibility with OTEL code that has not yet been migrated.
// New code should use UnifiedConfig instead.
type CollectorConfig struct {
	DeploymentEnabled             bool
	ScannedContainersEnabled      bool
	VulnerabilitiesEnabled        bool
	VulnerabilityExploitedEnabled bool
	VulnerabilityRiskEnabled      bool
	ImageScanStatusEnabled        bool
}
