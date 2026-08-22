package metrics

import (
	"bufio"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"time"

	"github.com/bvboe/bjorn2scan/scanner-core/database"
	"github.com/bvboe/bjorn2scan/scanner-core/nodes"
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
	WriteRuntimeMetrics(bw)
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
	return map[string]string{
		"deployment_uuid": deploymentUUID,
		"deployment_name": deploymentName,
		"host_name":       info.NodeName,
		"namespace":       info.Namespace,
		"pod":             info.Pod,
		"container":       info.Name,
		"distro":          info.OSName,
		"architecture":    info.Arch,
		"image_reference": info.Reference,
		"image_digest":    info.Digest,
		"instance_type":   "CONTAINER",
	}
}

// findingID builds the vulnerability_id label from the identity of the finding
// rather than from its database row id.
//
// The row id was unstable. Rescans delete every vulnerability row for an entity
// and re-insert it, so identical findings came back under new ids on every scan.
// Because vulnerability_id is a label, a new id means a new time series: a single
// grype database update retired and recreated every series in the deployment.
// Measured in kind, a node rescan reissued all 2,725 node findings (ids
// 546–3,270 became 3,271–5,995) and 100% of the retired series had a live twin
// identical in every label except this one — the churn carried no information at
// all. In production that doubled the exported series for the length of the
// staleness window and drove a QueryStaleness call to 210 seconds.
//
// The inputs must reproduce the grain of the row id they replace, no finer and no
// coarser. Node ids identify (node, CVE, package, version, type); image ids
// identify (image, CVE, package, version) and are deliberately shared by every
// container running that image, so counting distinct ids still counts distinct
// findings. Both tuples were verified unique against production data.
//
// FNV-1a 64-bit, matching HashMetricKey. At ~10⁶ findings the birthday collision
// probability is ~3×10⁻⁸; a collision would merge two findings in a correlation
// join for one cycle, which is proportionate for near-realtime correlation.
// The deployment UUID is kept as a literal prefix rather than hashed in, so the
// id stays visibly deployment-scoped and cannot collide across deployments.
func findingID(deploymentUUID string, parts ...string) string {
	h := fnv.New64a()
	for i, p := range parts {
		if i > 0 {
			// Unit separator: cannot occur in package names, CVE ids or hostnames,
			// so ("ab","c") and ("a","bc") cannot hash alike.
			_, _ = h.Write([]byte{0x1f})
		}
		_, _ = h.Write([]byte(p))
	}
	return fmt.Sprintf("%s.%016x", deploymentUUID, h.Sum64())
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
	// Image grain: shared by every container running this image, matching the
	// image_vulnerabilities row id this replaces.
	vulnerabilityID := findingID(deploymentUUID,
		v.Digest, v.CVEID, v.PackageName, v.PackageVersion)

	return map[string]string{
		"deployment_uuid":  deploymentUUID,
		"deployment_name":  deploymentName,
		"host_name":        info.NodeName,
		"namespace":        info.Namespace,
		"pod":              info.Pod,
		"container":        info.Name,
		"distro":           info.OSName,
		"image_reference":  info.Reference,
		"image_digest":     info.Digest,
		"instance_type":    "CONTAINER",
		"severity":         v.Severity,
		"vulnerability":    v.CVEID,
		"vulnerability_id": vulnerabilityID,
		"package_name":     v.PackageName,
		"package_version":  v.PackageVersion,
		"fix_status":       v.FixStatus,
		"fixed_version":    v.FixedVersion,
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
	// Node grain, matching the node_vulnerabilities row id this replaces.
	vulnerabilityID := findingID(deploymentUUID,
		v.NodeName, v.CVEID, v.PackageName, v.PackageVersion, v.PackageType)
	return map[string]string{
		"deployment_uuid":  deploymentUUID,
		"deployment_name":  deploymentName,
		"node":             v.NodeName,
		"hostname":         v.Hostname,
		"os_release":       v.OSRelease,
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
