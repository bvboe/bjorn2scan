// Package metrics provides Prometheus metrics exposition for bjorn2scan.
package metrics

import (
	"fmt"
)

// containerInfo holds common container information used for building hierarchical labels
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

// hierarchicalLabels holds the pre-computed hierarchical label values
type hierarchicalLabels struct {
	DeploymentUUIDHostName              string
	DeploymentUUIDNamespace             string
	DeploymentUUIDNamespaceImage        string
	DeploymentUUIDNamespaceImageDigest  string
	DeploymentUUIDNamespacePod          string
	DeploymentUUIDNamespacePodContainer string
}

// buildHierarchicalLabels computes hierarchical labels from deployment UUID and container info
func buildHierarchicalLabels(deploymentUUID string, info containerInfo) hierarchicalLabels {
	return hierarchicalLabels{
		DeploymentUUIDHostName:              fmt.Sprintf("%s.%s", deploymentUUID, info.NodeName),
		DeploymentUUIDNamespace:             fmt.Sprintf("%s.%s", deploymentUUID, info.Namespace),
		DeploymentUUIDNamespaceImage:        fmt.Sprintf("%s.%s.%s", deploymentUUID, info.Namespace, info.Reference),
		DeploymentUUIDNamespaceImageDigest:  fmt.Sprintf("%s.%s.%s", deploymentUUID, info.Namespace, info.Digest),
		DeploymentUUIDNamespacePod:          fmt.Sprintf("%s.%s.%s", deploymentUUID, info.Namespace, info.Pod),
		DeploymentUUIDNamespacePodContainer: fmt.Sprintf("%s.%s.%s.%s", deploymentUUID, info.Namespace, info.Pod, info.Name),
	}
}

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
