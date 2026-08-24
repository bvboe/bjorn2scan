package jobs

import (
	"fmt"
	"time"

	"github.com/bvboe/bjorn2scan/scanner-core/nodes"
)

// NodeDatabaseInterface defines the interface for database operations needed by node rescan
type NodeDatabaseInterface interface {
	GetNodesNeedingRescan(currentGrypeDBBuilt time.Time) ([]nodes.NodeWithStatus, error)
}

// NodeScanQueueInterface defines the interface for enqueueing node scans
type NodeScanQueueInterface interface {
	EnqueueHostForceScan(nodeName string)
}

// RescanNodesOnDBUpdate rescans nodes that were scanned with an older grype database
// This is called by the existing RescanDatabaseJob when the grype DB updates,
// rather than running as a separate scheduled job. This avoids unnecessary
// duplicate rescans since the grype DB typically updates every 24 hours.
func RescanNodesOnDBUpdate(db NodeDatabaseInterface, scanQueue NodeScanQueueInterface, currentGrypeDBBuilt time.Time) error {
	if db == nil || scanQueue == nil {
		return nil // Host scanning not configured
	}

	log.Info("checking nodes for vulnerability database update")

	// Find nodes that were scanned with an older grype database
	nodeList, err := db.GetNodesNeedingRescan(currentGrypeDBBuilt)
	if err != nil {
		return fmt.Errorf("failed to get nodes needing rescan: %w", err)
	}

	if len(nodeList) == 0 {
		log.Info("all nodes are up-to-date with current grype database, nothing to rescan")
		return nil
	}

	log.Info("found nodes scanned with older grype database, triggering rescan",
		"count", len(nodeList))

	// Every host scan regenerates the SBOM before rescanning; there is no
	// SBOM-preserving variant despite what earlier comments here claimed. A
	// periodic rescan-nodes job used to sit alongside this to "detect package
	// drift" with fresh SBOMs, but it was never scheduled and would have
	// duplicated this path: grype publishes daily (29 intervals measured, median
	// 24.0h, max 24.3h), so this already refreshes every node's SBOM about once a
	// day.
	for _, node := range nodeList {
		scanQueue.EnqueueHostForceScan(node.Name)
	}

	log.Info("enqueued nodes for rescanning",
		"count", len(nodeList))
	return nil
}
