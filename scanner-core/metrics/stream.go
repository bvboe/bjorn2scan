package metrics

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// StreamMetrics writes all enabled metric families to w in Prometheus text format,
// then emits NaN for any genuinely stale metrics from a previous cycle.
//
// Returns the accumulated staleness rows for the caller to persist asynchronously.
// The caller should call staleness.FlushAll(batch, cycleStart) and
// staleness.DeleteExpired(cycleStart) after the HTTP response is flushed, so that
// DB writes do not block the client.
//
// Memory profile: 64KB write buffer + staleness batch proportional to total metric count.
// At current scale (~100k-300k rows × ~200 bytes), this is ~20-60MB — acceptable.
func StreamMetrics(
	w io.Writer,
	info InfoProvider,
	deploymentUUID string,
	provider StreamingProvider,
	config UnifiedConfig,
	staleRows []database.StalenessRow,
	cycleStart time.Time,
) ([]database.StalenessRow, error) {
	bw := bufio.NewWriterSize(w, 64*1024)
	deploymentName := info.GetDeploymentName()

	// writtenFamilies tracks which families have had HELP+TYPE written.
	// Avoids duplicate headers when multiple metrics share the same family.
	writtenFamilies := make(map[string]bool)

	// writeErr captures the first write error; subsequent writes are no-ops.
	var writeErr error

	writeHeader := func(name string) {
		if writeErr != nil || writtenFamilies[name] {
			return
		}
		writtenFamilies[name] = true
		meta := familyMeta[name]
		_, writeErr = fmt.Fprintf(bw, "# HELP %s %s\n# TYPE %s %s\n", name, meta[0], name, meta[1])
	}

	emit := func(familyName, _ string, labels map[string]string, value float64) {
		writeHeader(familyName)
		if writeErr != nil {
			return
		}
		if math.IsNaN(value) {
			_, writeErr = fmt.Fprintf(bw, "%s{%s} NaN\n", familyName, formatLabels(labels))
		} else {
			_, writeErr = fmt.Fprintf(bw, "%s{%s} %g\n", familyName, formatLabels(labels), value)
		}
	}

	// No mid-stream flushing: the full batch is returned for async flush after the response.
	batch, err := collectMetrics(provider, config, info, deploymentUUID, deploymentName,
		cycleStart.Unix(), staleRows, 0, emit, nil)
	if err != nil {
		return nil, err
	}
	if writeErr != nil {
		return nil, writeErr
	}
	database.WriteOpMetrics(bw)
	return batch, bw.Flush()
}

// ─── Label builder standalone functions ──────────────────────────────────────
// These are used by collectMetrics. The Collector/NodeCollector methods delegate to these.

// buildDeploymentLabels builds the labels for the bjorn2scan_deployment metric.
func buildDeploymentLabels(info InfoProvider, deploymentUUID, deploymentName string) map[string]string {
	deploymentIP := info.GetDeploymentIP()
	consoleURL := info.GetConsoleURL()
	grypeDBBuilt := info.GetGrypeDBBuilt()

	labels := map[string]string{
		"deployment_uuid":    deploymentUUID,
		"deployment_name":    deploymentName,
		"deployment_type":    info.GetDeploymentType(),
		"bjorn2scan_version": info.GetVersion(),
	}
	if deploymentIP != "" {
		labels["deployment_ip"] = deploymentIP
	}
	if consoleURL != "" {
		labels["deployment_console"] = consoleURL
	}
	if grypeDBBuilt != "" {
		labels["grype_db_built"] = grypeDBBuilt
	}
	return labels
}

// buildContainerBaseLabels creates the common label map for container metrics.
func buildContainerBaseLabels(deploymentUUID, deploymentName string, info containerInfo) map[string]string {
	hl := buildHierarchicalLabels(deploymentUUID, info)
	return map[string]string{
		"deployment_uuid":                         deploymentUUID,
		"deployment_name":                         deploymentName,
		"deployment_uuid_host_name":               hl.DeploymentUUIDHostName,
		"deployment_uuid_namespace":               hl.DeploymentUUIDNamespace,
		"deployment_uuid_namespace_image":         hl.DeploymentUUIDNamespaceImage,
		"deployment_uuid_namespace_image_digest":  hl.DeploymentUUIDNamespaceImageDigest,
		"deployment_uuid_namespace_pod":           hl.DeploymentUUIDNamespacePod,
		"deployment_uuid_namespace_pod_container": hl.DeploymentUUIDNamespacePodContainer,
		"host_name":                               info.NodeName,
		"namespace":                               info.Namespace,
		"pod":                                     info.Pod,
		"container":                               info.Name,
		"distro":                                  info.OSName,
		"architecture":                            info.Arch,
		"image_reference":                         info.Reference,
		"image_digest":                            info.Digest,
		"instance_type":                           "CONTAINER",
	}
}

// buildContainerVulnerabilityLabels creates labels for container vulnerability metrics.
func buildContainerVulnerabilityLabels(deploymentUUID, deploymentName string, v database.ContainerVulnerability) map[string]string {
	info := containerInfo{
		NodeName:  v.NodeName,
		Namespace: v.Namespace,
		Pod:       v.Pod,
		Name:      v.Name,
		Reference: v.Reference,
		Digest:    v.Digest,
		OSName:    v.OSName,
	}
	hl := buildHierarchicalLabels(deploymentUUID, info)
	vulnerabilityID := fmt.Sprintf("%s.%d", deploymentUUID, v.VulnID)

	return map[string]string{
		"deployment_uuid":                         deploymentUUID,
		"deployment_name":                         deploymentName,
		"deployment_uuid_host_name":               hl.DeploymentUUIDHostName,
		"deployment_uuid_namespace":               hl.DeploymentUUIDNamespace,
		"deployment_uuid_namespace_image":         hl.DeploymentUUIDNamespaceImage,
		"deployment_uuid_namespace_image_digest":  hl.DeploymentUUIDNamespaceImageDigest,
		"deployment_uuid_namespace_pod":           hl.DeploymentUUIDNamespacePod,
		"deployment_uuid_namespace_pod_container": hl.DeploymentUUIDNamespacePodContainer,
		"host_name":                               info.NodeName,
		"namespace":                               info.Namespace,
		"pod":                                     info.Pod,
		"container":                               info.Name,
		"distro":                                  info.OSName,
		"image_reference":                         info.Reference,
		"image_digest":                            info.Digest,
		"instance_type":                           "CONTAINER",
		"severity":                                v.Severity,
		"vulnerability":                           v.CVEID,
		"vulnerability_id":                        vulnerabilityID,
		"package_name":                            v.PackageName,
		"package_version":                         v.PackageVersion,
		"fix_status":                              v.FixStatus,
		"fixed_version":                           v.FixedVersion,
	}
}

// buildNodeBaseLabels creates the common label map for node metrics.
func buildNodeBaseLabels(deploymentUUID, deploymentName string, node nodes.NodeWithStatus) map[string]string {
	return map[string]string{
		"deployment_uuid": deploymentUUID,
		"deployment_name": deploymentName,
		"node":            node.Name,
		"hostname":        node.Hostname,
		"os_release":      node.OSRelease,
		"kernel_version":  node.KernelVersion,
		"architecture":    node.Architecture,
		"instance_type":   "NODE",
	}
}

// buildNodeVulnerabilityLabels creates labels for node vulnerability metrics.
func buildNodeVulnerabilityLabels(deploymentUUID, deploymentName string, v database.NodeVulnerabilityForMetrics) map[string]string {
	vulnerabilityID := fmt.Sprintf("%s.%d", deploymentUUID, v.VulnID)
	return map[string]string{
		"deployment_uuid":  deploymentUUID,
		"deployment_name":  deploymentName,
		"node":             v.NodeName,
		"hostname":         v.Hostname,
		"os_release":       v.OSRelease,
		"kernel_version":   v.KernelVersion,
		"architecture":     v.Architecture,
		"instance_type":    "NODE",
		"severity":         v.Severity,
		"vulnerability":    v.CVEID,
		"vulnerability_id": vulnerabilityID,
		"package_name":     v.PackageName,
		"package_version":  v.PackageVersion,
		"package_type":     v.PackageType,
		"fix_status":       v.FixStatus,
		"fixed_version":    v.FixVersion,
	}
}
