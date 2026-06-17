package metrics

import (
	"encoding/json"
	"fmt"
	"math"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

// familyMeta maps each metric family name to its [help text, metric type].
// Used to write HELP/TYPE headers and to look up help text for stale NaN emission.
var familyMeta = map[string][2]string{
	"bjorn2scan_deployment":                    {"Bjorn2scan deployment information", "gauge"},
	"bjorn2scan_image_scanned":                 {"Bjorn2scan scanned container image information", "gauge"},
	"bjorn2scan_image_vulnerability":           {"Bjorn2scan vulnerability information for container images", "gauge"},
	"bjorn2scan_image_vulnerability_risk":      {"Bjorn2scan vulnerability risk scores for container images", "gauge"},
	"bjorn2scan_image_vulnerability_exploited": {"Bjorn2scan known exploited vulnerabilities (CISA KEV) in container images", "gauge"},
	"bjorn2scan_image_scan_status":             {"Count of running container images by scan status", "gauge"},
	"bjorn2scan_node_scanned":                  {"Bjorn2scan scanned node information", "gauge"},
	"bjorn2scan_node_scan_status":              {"Count of nodes by scan status", "gauge"},
	"bjorn2scan_node_vulnerability":            {"Bjorn2scan vulnerability information for nodes", "gauge"},
	"bjorn2scan_node_vulnerability_risk":       {"Bjorn2scan vulnerability risk scores for nodes", "gauge"},
	"bjorn2scan_node_vulnerability_exploited":  {"Bjorn2scan known exploited vulnerabilities (CISA KEV) on nodes", "gauge"},
}

// defaultCollectBatchSize is the number of staleness rows accumulated before onBatchFull fires.
const defaultCollectBatchSize = 1000

// collectMetrics drives one pass over all enabled metric data sources, calling emit for
// each live data point and, after all live data is processed, for each genuinely stale
// metric (value = math.NaN()).
//
// Staleness tracking:
//   - Each live point is added to the staleness batch with lastSeenUnix = cycleStartUnix.
//   - When the batch reaches batchSize, onBatchFull(batch) is called and the batch is reset.
//     Pass nil for onBatchFull to disable mid-stream flushing (Prometheus path).
//   - NaN points are NOT added to the batch — they signal removal, not presence.
//   - Stale rows whose key was also emitted as a live point this cycle are suppressed;
//     this prevents NaN from overwriting a live value when the same metric appears in
//     both the stale query result and the current collection pass.
//
// Returns the remaining partial batch for the caller to flush at their preferred time.
func collectMetrics(
	provider StreamingProvider,
	config UnifiedConfig,
	infoProvider InfoProvider,
	deploymentUUID, deploymentName string,
	cycleStartUnix int64,
	staleRows []database.StalenessRow,
	batchSize int,
	emit func(familyName, help string, labels map[string]string, value float64),
	onBatchFull func([]database.StalenessRow),
) ([]database.StalenessRow, error) {
	if batchSize <= 0 {
		batchSize = defaultCollectBatchSize
	}

	// liveKeys tracks every metric key emitted as a live value in this cycle.
	// Used to suppress NaN for metrics that are still active.
	liveKeys := make(map[string]struct{})
	var batch []database.StalenessRow

	// record emits one live data point and queues it for staleness tracking.
	record := func(familyName string, labels map[string]string, value float64) error {
		help := familyMeta[familyName][0]
		emit(familyName, help, labels, value)

		labelsJSON, err := json.Marshal(labels)
		if err != nil {
			return fmt.Errorf("failed to marshal labels: %w", err)
		}
		key := generateMetricKey(familyName, labels)
		liveKeys[key] = struct{}{}
		batch = append(batch, database.StalenessRow{
			MetricKey:  key,
			FamilyName: familyName,
			LabelsJSON: string(labelsJSON),
		})
		if onBatchFull != nil && len(batch) >= batchSize {
			onBatchFull(batch)
			batch = batch[:0]
		}
		return nil
	}

	// ─── 1. Deployment metric ─────────────────────────────────────────────────
	if config.DeploymentEnabled {
		labels := buildDeploymentLabels(infoProvider, deploymentUUID, deploymentName)
		if err := record("bjorn2scan_deployment", labels, 1); err != nil {
			return nil, err
		}
	}

	// ─── 2. Image scanned (streaming) ────────────────────────────────────────
	if config.ScannedContainersEnabled {
		if err := provider.StreamScannedContainers(func(ctr database.ScannedContainer) error {
			info := containerInfo{
				NodeName:  ctr.NodeName,
				Namespace: ctr.Namespace,
				Pod:       ctr.Pod,
				Name:      ctr.Name,
				Reference: ctr.Reference,
				Digest:    ctr.Digest,
				OSName:    ctr.OSName,
				Arch:      ctr.Architecture,
			}
			return record("bjorn2scan_image_scanned", buildContainerBaseLabels(deploymentUUID, deploymentName, info), 1)
		}); err != nil {
			return nil, fmt.Errorf("streaming scanned containers: %w", err)
		}
	}

	// ─── 3. Image vulnerabilities (3 families, single DB pass) ───────────────
	needsVulns := config.VulnerabilitiesEnabled || config.VulnerabilityExploitedEnabled || config.VulnerabilityRiskEnabled
	if needsVulns {
		if err := provider.StreamContainerVulnerabilities(func(v database.ContainerVulnerability) error {
			labels := buildContainerVulnerabilityLabels(deploymentUUID, deploymentName, v)
			if config.VulnerabilitiesEnabled {
				if err := record("bjorn2scan_image_vulnerability", labels, float64(v.Count)); err != nil {
					return err
				}
			}
			if config.VulnerabilityRiskEnabled {
				if err := record("bjorn2scan_image_vulnerability_risk", labels, v.Risk*float64(v.Count)); err != nil {
					return err
				}
			}
			if config.VulnerabilityExploitedEnabled && v.KnownExploited > 0 {
				if err := record("bjorn2scan_image_vulnerability_exploited", labels, float64(v.KnownExploited*v.Count)); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return nil, fmt.Errorf("streaming container vulnerabilities: %w", err)
		}
	}

	// ─── 4. Image scan status (small, load all at once) ──────────────────────
	if config.ImageScanStatusEnabled {
		statusCounts, err := provider.GetImageScanStatusCounts()
		if err != nil {
			return nil, fmt.Errorf("getting image scan status counts: %w", err)
		}
		for _, sc := range statusCounts {
			labels := map[string]string{
				"deployment_uuid": deploymentUUID,
				"scan_status":     sc.Status,
			}
			if err := record("bjorn2scan_image_scan_status", labels, float64(sc.Count)); err != nil {
				return nil, err
			}
		}
	}

	// ─── 5. Node scanned (small, load all at once) ────────────────────────────
	if config.NodeScannedEnabled {
		nodeList, err := provider.GetScannedNodes()
		if err != nil {
			return nil, fmt.Errorf("getting scanned nodes: %w", err)
		}
		for _, node := range nodeList {
			if err := record("bjorn2scan_node_scanned", buildNodeBaseLabels(deploymentUUID, deploymentName, node), 1); err != nil {
				return nil, err
			}
		}
	}

	// ─── 5b. Node scan status (small, load all at once) ──────────────────────
	if config.NodeScanStatusEnabled {
		statusCounts, err := provider.GetNodeScanStatusCounts()
		if err != nil {
			return nil, fmt.Errorf("getting node scan status counts: %w", err)
		}
		for _, sc := range statusCounts {
			labels := map[string]string{
				"deployment_uuid": deploymentUUID,
				"scan_status":     sc.Status,
			}
			if err := record("bjorn2scan_node_scan_status", labels, float64(sc.Count)); err != nil {
				return nil, err
			}
		}
	}

	// ─── 6. Node vulnerabilities (3 families, single DB pass) ────────────────
	needsNodeVulns := config.NodeVulnerabilitiesEnabled || config.NodeVulnerabilityRiskEnabled || config.NodeVulnerabilityExploitedEnabled
	if needsNodeVulns {
		if err := provider.StreamNodeVulnerabilitiesForMetrics(func(v database.NodeVulnerabilityForMetrics) error {
			labels := buildNodeVulnerabilityLabels(deploymentUUID, deploymentName, v)
			if config.NodeVulnerabilitiesEnabled {
				if err := record("bjorn2scan_node_vulnerability", labels, float64(v.Count)); err != nil {
					return err
				}
			}
			if config.NodeVulnerabilityRiskEnabled {
				if err := record("bjorn2scan_node_vulnerability_risk", labels, v.Risk*float64(v.Count)); err != nil {
					return err
				}
			}
			if config.NodeVulnerabilityExploitedEnabled && v.KnownExploited > 0 {
				if err := record("bjorn2scan_node_vulnerability_exploited", labels, float64(v.KnownExploited*v.Count)); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return nil, fmt.Errorf("streaming node vulnerabilities: %w", err)
		}
	}

	// ─── 7. Emit NaN for genuinely stale metrics ─────────────────────────────
	// Skip any metric that was also emitted as a live value this cycle. Those rows appear
	// stale only because QueryStale runs before the live flush updates last_seen_unix.
	for _, row := range staleRows {
		if _, isLive := liveKeys[row.MetricKey]; isLive {
			continue
		}
		var labels map[string]string
		if err := json.Unmarshal([]byte(row.LabelsJSON), &labels); err != nil {
			log.Warn("skipping stale metric: invalid labels JSON",
				"family", row.FamilyName, "metric_key", row.MetricKey, "error", err)
			continue
		}
		help := familyMeta[row.FamilyName][0]
		emit(row.FamilyName, help, labels, math.NaN())
	}

	return batch, nil
}
