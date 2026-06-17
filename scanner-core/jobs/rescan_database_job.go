package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/grype"
	"github.com/bvboe/b2s-go/scanner-core/scanning"
	"github.com/bvboe/b2s-go/scanner-core/vulndb"
)

// DatabaseUpdateChecker defines the interface for checking vulnerability database updates
type DatabaseUpdateChecker interface {
	CheckForUpdates(ctx context.Context) (bool, error)
	GetCurrentVersion() *vulndb.DatabaseStatus
}

// stuckScanMaxAge is how long a node or image may sit in a transient scan state
// ('generating_sbom', 'scanning_vulnerabilities') before the reaper treats it as
// orphaned and resets it. It must be safely larger than the real scan timeouts
// (host SBOM 15m + vuln scan 10m = 25m worst case) so in-flight scans are never
// reaped prematurely.
const stuckScanMaxAge = 30 * time.Minute

// DatabaseInterface defines the interface for database operations needed by RescanDatabaseJob
type DatabaseInterface interface {
	GetImagesByStatus(status database.Status) ([]database.ContainerImage, error)
	GetFirstContainerForImage(digest string) (*database.ContainerRow, error)
	GetImagesNeedingRescan(currentGrypeDBBuilt time.Time) ([]database.ContainerImage, error)
	ReapStuckScans(maxAge time.Duration) (nodeRows, imageRows int64, err error)
}

// ReadinessSetter defines the interface for updating database readiness state
// This allows the rescan-database job to mark the database as ready when it
// successfully verifies or updates the vulnerability database
type ReadinessSetter interface {
	SetReady(status *grype.DatabaseStatus)
}

// RescanDatabaseJob triggers a rescan when the vulnerability database is updated
type RescanDatabaseJob struct {
	dbUpdater       DatabaseUpdateChecker
	db              DatabaseInterface
	scanQueue       ScanQueueInterface
	readinessSetter ReadinessSetter // Optional: updates readiness state when DB is ready
	// Node scanning support (optional)
	nodeDB        NodeDatabaseInterface
	nodeScanQueue NodeScanQueueInterface
}

// NewRescanDatabaseJob creates a new rescan database job
func NewRescanDatabaseJob(dbUpdater DatabaseUpdateChecker, db DatabaseInterface, scanQueue ScanQueueInterface) *RescanDatabaseJob {
	if dbUpdater == nil {
		panic("RescanDatabaseJob requires a non-nil DatabaseUpdateChecker")
	}
	if db == nil {
		panic("RescanDatabaseJob requires a non-nil database")
	}
	if scanQueue == nil {
		panic("RescanDatabaseJob requires a non-nil scan queue")
	}

	return &RescanDatabaseJob{
		dbUpdater: dbUpdater,
		db:        db,
		scanQueue: scanQueue,
	}
}

// SetReadinessSetter sets the readiness setter for updating database ready state
// This is optional - if not set, the job will not update readiness state
func (j *RescanDatabaseJob) SetReadinessSetter(setter ReadinessSetter) {
	j.readinessSetter = setter
}

// SetNodeScanning configures node scanning support for the job
// When enabled, the job will also rescan nodes when the grype DB updates
func (j *RescanDatabaseJob) SetNodeScanning(nodeDB NodeDatabaseInterface, nodeScanQueue NodeScanQueueInterface) {
	j.nodeDB = nodeDB
	j.nodeScanQueue = nodeScanQueue
}

func (j *RescanDatabaseJob) Name() string {
	return "rescan-database"
}

func (j *RescanDatabaseJob) Run(ctx context.Context) error {
	log.Info("checking for vulnerability database updates")

	// Recover any scans orphaned in a transient state since the last cycle.
	// ResetInterruptedScans only runs at startup, so a scan wedged while the
	// server keeps running would otherwise stay stuck until the next restart.
	// Marking them vuln_scan_failed lets the rescan logic below re-enqueue them.
	if nodeRows, imageRows, err := j.db.ReapStuckScans(stuckScanMaxAge); err != nil {
		log.Warn("failed to reap stuck scans", "error", err)
	} else if nodeRows > 0 || imageRows > 0 {
		log.Info("reaped stuck scans", "nodes", nodeRows, "images", imageRows)
	}

	// Check for and download any available updates
	// This also updates the persistent timestamp tracking
	_, err := j.dbUpdater.CheckForUpdates(ctx)
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	// Get the current grype database version
	currentVersion := j.dbUpdater.GetCurrentVersion()
	if currentVersion == nil {
		log.Warn("no grype database available, skipping rescan")
		return nil
	}

	log.Info("current grype database",
		"built", currentVersion.Built.Format(time.RFC3339))

	// Update readiness state if setter is configured
	// This ensures the pod becomes ready even if initial download failed but db-updater succeeded
	if j.readinessSetter != nil {
		j.readinessSetter.SetReady(&grype.DatabaseStatus{
			Available:     true,
			Built:         currentVersion.Built,
			SchemaVersion: currentVersion.SchemaVersion,
			Path:          currentVersion.Path,
		})
	}

	// Find images that were scanned with an older grype database (or never tracked)
	// This is more intelligent than rescanning all images - it only rescans those that need it
	images, err := j.db.GetImagesNeedingRescan(currentVersion.Built)
	if err != nil {
		return fmt.Errorf("failed to get images needing rescan: %w", err)
	}

	if len(images) == 0 {
		log.Info("all images are up-to-date with current grype database, nothing to rescan")
	} else {
		log.Info("found images scanned with older grype database, triggering rescan",
			"image_count", len(images))

		// Enqueue force scan for each image
		rescanned := 0
		for _, img := range images {
			// Get the first container to determine node and runtime
			instance, err := j.db.GetFirstContainerForImage(img.Digest)
			if err != nil {
				log.Warn("could not find instance for image",
					"digest", img.Digest,
					"error", err)
				continue
			}

			// Enqueue force scan (ForceScan=true skips SBOM generation, only runs Grype)
			j.scanQueue.EnqueueForceScan(
				containers.ImageID{
					Digest:    img.Digest,
					Reference: instance.Reference,
				},
				instance.NodeName,
				instance.ContainerRuntime,
			)
			rescanned++
		}

		log.Info("enqueued images for rescanning",
			"count", rescanned)
	}

	// Also rescan nodes if node scanning is configured
	// This runs regardless of whether images needed rescan
	if j.nodeDB != nil && j.nodeScanQueue != nil {
		if err := RescanNodesOnDBUpdate(j.nodeDB, j.nodeScanQueue, currentVersion.Built); err != nil {
			log.Warn("failed to rescan nodes",
				"error", err)
			// Don't fail the job - node scanning is optional
		}
	}

	return nil
}

// ScanQueueInterface defines the interface for enqueueing scans
type ScanQueueInterface interface {
	EnqueueForceScan(image containers.ImageID, nodeName string, containerRuntime string)
}

// Ensure scanning.JobQueue implements ScanQueueInterface
var _ ScanQueueInterface = (*scanning.JobQueue)(nil)

// Ensure database.DB implements DatabaseInterface
var _ DatabaseInterface = (*database.DB)(nil)

// Ensure vulndb.DatabaseUpdater implements DatabaseUpdateChecker
var _ DatabaseUpdateChecker = (*vulndb.DatabaseUpdater)(nil)
