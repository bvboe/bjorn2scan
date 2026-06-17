package scanning

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/grype"
	"github.com/bvboe/b2s-go/scanner-core/logging"
)

var (
	log      = logging.For(logging.ComponentQueue)
	grypeLog = logging.For(logging.ComponentGrype)
	nodesLog = logging.For(logging.ComponentNodes)
)

// ScanJob represents a request to scan a container image
type ScanJob struct {
	Image            containers.ImageID
	NodeName         string // K8s node name where image is located (empty for agent)
	ContainerRuntime string // "docker" or "containerd"
	ForceScan        bool   // If true, rescan even if SBOM already exists
}

// HostScanJob represents a request to scan a node's host filesystem
type HostScanJob struct {
	NodeName   string // K8s node name to scan
	ForceScan  bool   // If true, rescan vulns using existing SBOM (skip SBOM regeneration)
	FullRescan bool   // If true, always regenerate SBOM (node packages may have changed)
}

// SBOMRetriever is a callback function that retrieves an SBOM for an image
// The implementation is provided by the caller (agent or k8s-scan-server)
// Returns the SBOM as JSON bytes, or an error
type SBOMRetriever func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error)

// HostSBOMRetriever is a callback function that retrieves a host SBOM for a node
// The implementation is provided by the caller (k8s-scan-server)
// Returns the SBOM as JSON bytes, or an error
type HostSBOMRetriever func(ctx context.Context, nodeName string) ([]byte, error)

// DBReadinessChecker allows the queue to wait for the vulnerability database to be ready
// This interface is implemented by handlers.DatabaseReadinessState
type DBReadinessChecker interface {
	WaitForReady(ctx context.Context) bool
}

// QueueFullBehavior defines what happens when the queue reaches max depth
type QueueFullBehavior int

const (
	// QueueFullDrop drops the new job and logs a warning (default)
	QueueFullDrop QueueFullBehavior = iota
	// QueueFullDropOldest removes the oldest job and adds the new one
	QueueFullDropOldest
	// QueueFullBlock blocks until space is available (may cause goroutine buildup)
	QueueFullBlock
)

// QueueConfig configures the job queue behavior
type QueueConfig struct {
	// MaxDepth is the maximum number of jobs in the queue (0 = unbounded)
	MaxDepth int
	// FullBehavior defines what happens when queue is full
	FullBehavior QueueFullBehavior
}

// QueueMetrics tracks queue statistics
type QueueMetrics struct {
	currentDepth   int
	peakDepth      int
	totalEnqueued  int64
	totalDropped   int64
	totalProcessed int64
	mu             sync.RWMutex
}

// JobQueue manages a queue of scan jobs and processes them serially with a single worker
type JobQueue struct {
	jobs              []ScanJob
	hostJobs          []HostScanJob
	jobsMu            sync.Mutex
	jobsAvailable     *sync.Cond
	sbomRetriever     SBOMRetriever
	hostSBOMRetriever HostSBOMRetriever
	db                *database.DB
	ctx               context.Context
	cancel            context.CancelFunc
	wg                sync.WaitGroup
	grypeCfg          grype.Config
	config            QueueConfig
	metrics           QueueMetrics
	dbReadinessState  DBReadinessChecker // Allows waiting for grype DB to be ready
}

// NewJobQueue creates a new job queue with the specified SBOM retriever and configuration
// Vulnerability scanning is handled internally using Grype with custom configuration
func NewJobQueue(db *database.DB, sbomRetriever SBOMRetriever, grypeCfg grype.Config, queueCfg QueueConfig) *JobQueue {
	ctx, cancel := context.WithCancel(context.Background())

	queue := &JobQueue{
		jobs:          make([]ScanJob, 0),
		hostJobs:      make([]HostScanJob, 0),
		sbomRetriever: sbomRetriever,
		db:            db,
		ctx:           ctx,
		cancel:        cancel,
		grypeCfg:      grypeCfg,
		config:        queueCfg,
	}
	queue.jobsAvailable = sync.NewCond(&queue.jobsMu)

	// Start the worker goroutine
	queue.wg.Add(1)
	go queue.worker()

	if queueCfg.MaxDepth > 0 {
		log.Info("scan job queue initialized", "max_depth", queueCfg.MaxDepth, "behavior", queueCfg.FullBehavior)
	} else {
		log.Info("scan job queue initialized", "max_depth", "unbounded", "workers", 1)
	}
	return queue
}

// NewJobQueueWithDefaults creates a new job queue with default Grype and queue configuration
// This is a convenience method for applications that don't need custom settings
// Default: unbounded queue (MaxDepth=0), drops new jobs when full (though it never fills)
func NewJobQueueWithDefaults(db *database.DB, sbomRetriever SBOMRetriever) *JobQueue {
	return NewJobQueue(db, sbomRetriever, grype.Config{}, QueueConfig{MaxDepth: 0, FullBehavior: QueueFullDrop})
}

// SetDBReadinessChecker sets the database readiness checker for the queue
// When set, the queue will wait for the grype database to be ready before processing vulnerability scans
func (q *JobQueue) SetDBReadinessChecker(checker DBReadinessChecker) {
	q.dbReadinessState = checker
}

// SetHostSBOMRetriever sets the callback function for retrieving host SBOMs
// This must be set before host scan jobs can be processed
func (q *JobQueue) SetHostSBOMRetriever(retriever HostSBOMRetriever) {
	q.hostSBOMRetriever = retriever
	log.Info("host SBOM retriever configured")
}

// Enqueue adds a scan job to the queue with respect to max depth and full behavior
func (q *JobQueue) Enqueue(job ScanJob) {

	q.jobsMu.Lock()
	defer q.jobsMu.Unlock()

	// Check if shutting down
	select {
	case <-q.ctx.Done():
		log.Warn("queue shutting down, cannot enqueue job")
		return
	default:
	}

	// Check if queue is at max depth
	if q.config.MaxDepth > 0 && len(q.jobs) >= q.config.MaxDepth {
		switch q.config.FullBehavior {
		case QueueFullDrop:
			// Drop the new job
			log.Warn("queue full, dropping new job",
				"depth", len(q.jobs),
				"image", job.Image.Reference,
				"digest", job.Image.Digest)
			q.updateMetrics(0, 0, 1) // Increment dropped count
			return

		case QueueFullDropOldest:
			// Remove oldest job and add new one
			dropped := q.jobs[0]
			q.jobs = q.jobs[1:]
			log.Warn("queue full, dropping oldest job",
				"depth", len(q.jobs)+1,
				"dropped_image", dropped.Image.Reference,
				"new_image", job.Image.Reference)
			q.updateMetrics(0, 0, 1) // Increment dropped count

		case QueueFullBlock:
			// Block until space is available
			// Release lock and wait for signal
			for len(q.jobs) >= q.config.MaxDepth {
				q.jobsAvailable.Wait()
				// Check shutdown again after waking up
				select {
				case <-q.ctx.Done():
					log.Warn("queue shutting down while waiting to enqueue")
					return
				default:
				}
			}
		}
	}

	// Add job to queue
	q.jobs = append(q.jobs, job)
	currentDepth := len(q.jobs)

	log.Debug("enqueued scan job",
		"image", job.Image.Reference,
		"digest", job.Image.Digest,
		"node", job.NodeName,
		"runtime", job.ContainerRuntime,
		"queue_depth", currentDepth)

	// Update metrics
	q.updateMetrics(currentDepth, 1, 0)

	q.jobsAvailable.Signal()
}

// EnqueueScan is a convenience method for enqueuing a scan with individual parameters
// This implements the ScanQueueInterface used by the container manager
func (q *JobQueue) EnqueueScan(image containers.ImageID, nodeName string, containerRuntime string) {
	job := ScanJob{
		Image:            image,
		NodeName:         nodeName,
		ContainerRuntime: containerRuntime,
		ForceScan:        false,
	}
	q.Enqueue(job)
}

// EnqueueForceScan enqueues a scan job with ForceScan=true to retry failed or incomplete scans
// This implements the ScanQueueInterface used by the container manager
func (q *JobQueue) EnqueueForceScan(image containers.ImageID, nodeName string, containerRuntime string) {
	job := ScanJob{
		Image:            image,
		NodeName:         nodeName,
		ContainerRuntime: containerRuntime,
		ForceScan:        true,
	}
	q.Enqueue(job)
}

// EnqueueHostScan adds a host scan job to the queue
// This scans the host filesystem on a Kubernetes node for packages and vulnerabilities
func (q *JobQueue) EnqueueHostScan(nodeName string) {
	q.enqueueHostJob(HostScanJob{
		NodeName:  nodeName,
		ForceScan: false,
	})
}

// EnqueueHostForceScan adds a host scan job that forces a full rescan
// This always retrieves a fresh SBOM because node packages can change over time.
// Used when the Grype database updates to detect newly-discovered vulnerabilities.
func (q *JobQueue) EnqueueHostForceScan(nodeName string) {
	q.enqueueHostJob(HostScanJob{
		NodeName:   nodeName,
		ForceScan:  true,
		FullRescan: true,
	})
}

// EnqueueHostFullRescan adds a host scan job that regenerates both SBOM and vulnerabilities
// This always retrieves a fresh SBOM because node packages can change over time.
// Used by the periodic rescan-nodes job to detect package drift.
func (q *JobQueue) EnqueueHostFullRescan(nodeName string) {
	q.enqueueHostJob(HostScanJob{
		NodeName:   nodeName,
		ForceScan:  true,
		FullRescan: true,
	})
}

// enqueueHostJob adds a host scan job to the queue
func (q *JobQueue) enqueueHostJob(job HostScanJob) {

	q.jobsMu.Lock()
	defer q.jobsMu.Unlock()

	// Check if shutting down
	select {
	case <-q.ctx.Done():
		log.Warn("queue shutting down, cannot enqueue host scan job")
		return
	default:
	}

	// Check if this node is already in the queue
	for _, existing := range q.hostJobs {
		if existing.NodeName == job.NodeName {
			log.Debug("host scan already in queue, skipping", "node", job.NodeName)
			return
		}
	}

	// Check queue depth limit
	totalJobs := len(q.jobs) + len(q.hostJobs)
	if q.config.MaxDepth > 0 && totalJobs >= q.config.MaxDepth {
		switch q.config.FullBehavior {
		case QueueFullDrop:
			q.updateMetrics(0, 0, 1)
			log.Warn("queue full, dropping host scan job", "depth", totalJobs, "node", job.NodeName)
			return
		case QueueFullDropOldest:
			// For host jobs, drop oldest host job if possible, otherwise oldest regular job
			if len(q.hostJobs) > 0 {
				dropped := q.hostJobs[0]
				q.hostJobs = q.hostJobs[1:]
				log.Warn("queue full, dropping oldest host scan job", "dropped_node", dropped.NodeName)
			} else if len(q.jobs) > 0 {
				dropped := q.jobs[0]
				q.jobs = q.jobs[1:]
				log.Warn("queue full, dropping oldest scan job", "dropped_image", dropped.Image.Reference)
			}
			q.updateMetrics(0, 0, 1)
		case QueueFullBlock:
			// Block until space available (simplified - just drop with warning)
			q.updateMetrics(0, 0, 1)
			log.Warn("queue full, dropping host scan job (blocking not implemented)", "depth", totalJobs, "node", job.NodeName)
			return
		}
	}

	q.hostJobs = append(q.hostJobs, job)
	currentDepth := len(q.jobs) + len(q.hostJobs)
	q.updateMetrics(currentDepth, 1, 0)

	log.Debug("enqueued host scan", "node", job.NodeName, "force", job.ForceScan, "queue_depth", currentDepth)

	// Signal that jobs are available
	q.jobsAvailable.Signal()
}

// updateMetrics updates queue metrics (must be called with jobsMu held or metrics.mu)
func (q *JobQueue) updateMetrics(currentDepth int, enqueued int64, dropped int64) {
	q.metrics.mu.Lock()
	defer q.metrics.mu.Unlock()

	if currentDepth > 0 {
		q.metrics.currentDepth = currentDepth
		if currentDepth > q.metrics.peakDepth {
			q.metrics.peakDepth = currentDepth
		}
	}

	if enqueued > 0 {
		q.metrics.totalEnqueued += enqueued
	}

	if dropped > 0 {
		q.metrics.totalDropped += dropped
	}
}

// GetQueueDepth returns the current number of jobs in the queue (both image and host scans).
// This is useful for monitoring and debug purposes.
func (q *JobQueue) GetQueueDepth() int {
	q.jobsMu.Lock()
	defer q.jobsMu.Unlock()
	return len(q.jobs) + len(q.hostJobs)
}

// GetHostQueueDepth returns the current number of host scan jobs in the queue.
func (q *JobQueue) GetHostQueueDepth() int {
	q.jobsMu.Lock()
	defer q.jobsMu.Unlock()
	return len(q.hostJobs)
}

// GetMetrics returns a snapshot of queue metrics
func (q *JobQueue) GetMetrics() (currentDepth, peakDepth int, totalEnqueued, totalDropped, totalProcessed int64) {
	q.metrics.mu.RLock()
	defer q.metrics.mu.RUnlock()

	return q.metrics.currentDepth, q.metrics.peakDepth,
		q.metrics.totalEnqueued, q.metrics.totalDropped, q.metrics.totalProcessed
}

// worker processes jobs from the queue serially (one at a time)
// It handles both container image scans and host scans, prioritizing image scans
func (q *JobQueue) worker() {
	defer q.wg.Done()

	log.Info("scan worker started")

	for {
		q.jobsMu.Lock()

		// Wait for jobs to be available or shutdown signal
		for len(q.jobs) == 0 && len(q.hostJobs) == 0 {
			select {
			case <-q.ctx.Done():
				q.jobsMu.Unlock()
				log.Info("scan worker shutting down")
				return
			default:
			}

			// Wait for a job to be enqueued
			q.jobsAvailable.Wait()

			// Check shutdown again after waking up
			select {
			case <-q.ctx.Done():
				q.jobsMu.Unlock()
				log.Info("scan worker shutting down")
				return
			default:
			}
		}

		// Process image scan jobs first (they're typically faster and more urgent)
		if len(q.jobs) > 0 {
			// Dequeue the first image scan job
			job := q.jobs[0]
			q.jobs = q.jobs[1:]
			currentDepth := len(q.jobs) + len(q.hostJobs)

			// Update current depth metric
			q.updateMetrics(currentDepth, 0, 0)

			// Signal that space is available (for QueueFullBlock behavior)
			q.jobsAvailable.Signal()

			q.jobsMu.Unlock()

			// Process the job outside the lock
			q.processJob(job)
		} else if len(q.hostJobs) > 0 {
			// Dequeue the first host scan job
			hostJob := q.hostJobs[0]
			q.hostJobs = q.hostJobs[1:]
			currentDepth := len(q.jobs) + len(q.hostJobs)

			// Update current depth metric
			q.updateMetrics(currentDepth, 0, 0)

			// Signal that space is available
			q.jobsAvailable.Signal()

			q.jobsMu.Unlock()

			// Process the host scan job outside the lock
			q.processHostJob(hostJob)
		} else {
			q.jobsMu.Unlock()
			continue
		}

		// Update processed count
		q.metrics.mu.Lock()
		q.metrics.totalProcessed++
		q.metrics.mu.Unlock()
	}
}

// processJob handles a single scan job
func (q *JobQueue) processJob(job ScanJob) {
	log := log.With("image", job.Image.Reference, "digest", job.Image.Digest)

	log.Info("processing scan job", "force_scan", job.ForceScan)

	// Check if we already have scan results
	status, err := q.db.GetImageStatus(job.Image.Digest)
	if err != nil {
		log.Error("error checking status", slog.Any("error", err))
	}

	// If ForceScan is requested and SBOM already exists, skip directly to vulnerability scan
	// This is used by the rescan-database job when the grype database is updated
	if job.ForceScan && status.HasSBOM() {
		log.Debug("force scan with existing SBOM, running vulnerability scan only")
		q.processVulnerabilityScan(job, nil)
		return
	}

	// Skip if SBOM already exists (unless force scan without SBOM)
	if !job.ForceScan && status.HasSBOM() {
		log.Debug("image already has SBOM, skipping SBOM generation", "status", status)
		// If SBOM exists but vulnerabilities don't, continue to vulnerability scan
		if !status.HasVulnerabilities() {
			q.processVulnerabilityScan(job, nil)
		}
		return
	}

	// Mark image as generating SBOM
	if err := q.db.UpdateStatus(job.Image.Digest, database.StatusGeneratingSBOM, ""); err != nil {
		log.Error("error updating status", slog.Any("error", err))
		return
	}

	// Call the SBOM retriever callback
	ctx, cancel := context.WithTimeout(q.ctx, 5*time.Minute)
	defer cancel()

	sbomJSON, err := q.sbomRetriever(ctx, job.Image, job.NodeName, job.ContainerRuntime)
	if err != nil {
		log.Error("error retrieving SBOM", slog.Any("error", err))

		// Determine if this is a failure or unavailability
		// If no node scanner is available, mark as unavailable; otherwise failed
		// For now, assume all errors are failures
		errorStatus := database.StatusSBOMFailed

		if updateErr := q.db.UpdateStatus(job.Image.Digest, errorStatus, err.Error()); updateErr != nil {
			log.Error("error updating status to failed", "status", errorStatus, slog.Any("error", updateErr))
		}
		return
	}

	// Store the SBOM in the database for caching (enables fast API access and offline serving)
	// Note: This is the primary SBOM caching path. Direct API requests to k8s-scan-server
	// that fetch SBOMs on-demand from pod-scanner do NOT cache (see handlers/sbom.go).
	// StoreSBOM will automatically update status to StatusScanningVulnerabilities
	if err := q.db.StoreSBOM(job.Image.Digest, sbomJSON); err != nil {
		log.Error("error storing SBOM", slog.Any("error", err))

		if updateErr := q.db.UpdateStatus(job.Image.Digest, database.StatusSBOMFailed, err.Error()); updateErr != nil {
			log.Error("error updating status to failed", slog.Any("error", updateErr))
		}
		return
	}

	log.Info("successfully scanned and stored SBOM")

	// Now scan for vulnerabilities
	q.processVulnerabilityScan(job, sbomJSON)
}

// processVulnerabilityScan scans an SBOM for vulnerabilities
func (q *JobQueue) processVulnerabilityScan(job ScanJob, sbomJSON []byte) {
	log := grypeLog.With("image", job.Image.Reference, "digest", job.Image.Digest)

	log.Info("starting vulnerability scan")

	// Wait for grype DB to be ready before scanning
	if q.dbReadinessState != nil {
		log.Debug("waiting for vulnerability database")
		if !q.dbReadinessState.WaitForReady(q.ctx) {
			log.Warn("scan cancelled while waiting for database")
			return
		}
		log.Debug("vulnerability database is ready")
	}

	// Check if we already have vulnerability results (unless force scan is requested)
	if !job.ForceScan {
		status, err := q.db.GetImageStatus(job.Image.Digest)
		if err != nil {
			log.Error("error checking status", slog.Any("error", err))
		} else if status.HasVulnerabilities() {
			log.Debug("image already has vulnerabilities, skipping", "status", status)
			return
		}
	}

	// If sbomJSON is nil, retrieve it from the database
	if sbomJSON == nil {
		var err error
		sbomJSON, err = q.db.GetSBOM(job.Image.Digest)
		if err != nil {
			log.Error("error retrieving SBOM from database", slog.Any("error", err))
			if updateErr := q.db.UpdateStatus(job.Image.Digest, database.StatusVulnScanFailed, "SBOM not available: "+err.Error()); updateErr != nil {
				log.Error("error updating status to failed", slog.Any("error", updateErr))
			}
			return
		}
	}

	// Scan for vulnerabilities using Grype
	ctx, cancel := context.WithTimeout(q.ctx, 5*time.Minute)
	defer cancel()

	scanResult, err := grype.ScanVulnerabilitiesWithConfig(ctx, sbomJSON, q.grypeCfg)
	if err != nil {
		log.Error("error scanning vulnerabilities", slog.Any("error", err))

		if updateErr := q.db.UpdateStatus(job.Image.Digest, database.StatusVulnScanFailed, err.Error()); updateErr != nil {
			log.Error("error updating status to failed", slog.Any("error", updateErr))
		}
		return
	}

	// Store the vulnerability report with grype DB version info
	// StoreVulnerabilities will automatically update status to StatusCompleted
	if err := q.db.StoreVulnerabilities(job.Image.Digest, scanResult.VulnerabilityJSON, scanResult.DBStatus.Built); err != nil {
		log.Error("error storing vulnerabilities", slog.Any("error", err))

		if updateErr := q.db.UpdateStatus(job.Image.Digest, database.StatusVulnScanFailed, err.Error()); updateErr != nil {
			log.Error("error updating status to failed", slog.Any("error", updateErr))
		}
		return
	}

	log.Info("successfully scanned and stored vulnerabilities")
}

// processHostJob handles a single host scan job
func (q *JobQueue) processHostJob(job HostScanJob) {
	log := nodesLog.With("node", job.NodeName)

	log.Info("processing host scan job", "force_scan", job.ForceScan)

	if q.hostSBOMRetriever == nil {
		log.Error("host SBOM retriever not configured")
		if updateErr := q.db.UpdateNodeStatus(job.NodeName, database.StatusSBOMFailed, "Host SBOM retriever not configured"); updateErr != nil {
			log.Error("error updating node status", slog.Any("error", updateErr))
		}
		return
	}

	// Skip if already completed (unless force scan)
	if !job.ForceScan {
		status, err := q.db.GetNodeScanStatus(job.NodeName)
		if err != nil {
			log.Error("error checking status", slog.Any("error", err))
		} else if status == "completed" || status == "scanned" {
			log.Debug("node already scanned, skipping", "status", status)
			return
		}
	}

	// Mark node as generating SBOM
	if err := q.db.UpdateNodeStatus(job.NodeName, database.StatusGeneratingSBOM, ""); err != nil {
		log.Error("error updating status", slog.Any("error", err))
		return
	}

	// Call the host SBOM retriever callback
	ctx, cancel := context.WithTimeout(q.ctx, 15*time.Minute) // Host scans take longer
	defer cancel()

	sbomJSON, err := q.hostSBOMRetriever(ctx, job.NodeName)
	if err != nil {
		log.Error("error retrieving host SBOM", slog.Any("error", err))

		if updateErr := q.db.UpdateNodeStatus(job.NodeName, database.StatusSBOMFailed, err.Error()); updateErr != nil {
			log.Error("error updating node status to failed", slog.Any("error", updateErr))
		}
		return
	}

	// Store the SBOM in the database
	if err := q.db.StoreNodeSBOM(job.NodeName, sbomJSON); err != nil {
		log.Error("error storing host SBOM", slog.Any("error", err))

		if updateErr := q.db.UpdateNodeStatus(job.NodeName, database.StatusSBOMFailed, err.Error()); updateErr != nil {
			log.Error("error updating node status to failed", slog.Any("error", updateErr))
		}
		return
	}

	log.Info("successfully scanned and stored host SBOM")

	// Now scan for vulnerabilities
	q.processHostVulnerabilityScan(job, sbomJSON)
}

// processHostVulnerabilityScan scans a host SBOM for vulnerabilities
func (q *JobQueue) processHostVulnerabilityScan(job HostScanJob, sbomJSON []byte) {
	log := grypeLog.With("node", job.NodeName)

	log.Info("starting host vulnerability scan")

	// Wait for grype DB to be ready before scanning
	if q.dbReadinessState != nil {
		log.Debug("waiting for vulnerability database")
		if !q.dbReadinessState.WaitForReady(q.ctx) {
			log.Warn("host scan cancelled while waiting for database")
			// Update status to failed instead of silently returning
			if updateErr := q.db.UpdateNodeStatus(job.NodeName, database.StatusVulnScanFailed, "cancelled while waiting for vulnerability database"); updateErr != nil {
				log.Error("error updating node status to failed", slog.Any("error", updateErr))
			}
			return
		}
		log.Debug("vulnerability database is ready")
	}

	// If sbomJSON is nil, retrieve it from the database
	if sbomJSON == nil {
		var err error
		sbomJSON, err = q.db.GetNodeSBOM(job.NodeName)
		if err != nil {
			log.Error("error retrieving SBOM from database", slog.Any("error", err))
			if updateErr := q.db.UpdateNodeStatus(job.NodeName, database.StatusVulnScanFailed, "SBOM not available: "+err.Error()); updateErr != nil {
				log.Error("error updating node status to failed", slog.Any("error", updateErr))
			}
			return
		}
	}

	// Scan for vulnerabilities using Grype
	ctx, cancel := context.WithTimeout(q.ctx, 10*time.Minute)
	defer cancel()

	scanResult, err := grype.ScanVulnerabilitiesWithConfig(ctx, sbomJSON, q.grypeCfg)
	if err != nil {
		log.Error("error scanning host vulnerabilities", slog.Any("error", err))

		if updateErr := q.db.UpdateNodeStatus(job.NodeName, database.StatusVulnScanFailed, err.Error()); updateErr != nil {
			log.Error("error updating node status to failed", slog.Any("error", updateErr))
		}
		return
	}

	// Store the vulnerability report
	if err := q.db.StoreNodeVulnerabilities(job.NodeName, scanResult.VulnerabilityJSON, scanResult.DBStatus.Built); err != nil {
		log.Error("error storing host vulnerabilities", slog.Any("error", err))

		if updateErr := q.db.UpdateNodeStatus(job.NodeName, database.StatusVulnScanFailed, err.Error()); updateErr != nil {
			log.Error("error updating node status to failed", slog.Any("error", updateErr))
		}
		return
	}

	log.Info("successfully scanned and stored host vulnerabilities")
}

// Shutdown gracefully shuts down the queue, waiting for current job to complete
func (q *JobQueue) Shutdown() {
	log.Info("shutting down scan queue")
	q.cancel()

	// Wake up the worker so it can see the shutdown signal
	q.jobsAvailable.Broadcast()

	q.wg.Wait()
	log.Info("scan queue shut down")
}

// QueueJob represents a job in the queue for external visibility
type QueueJob struct {
	Type       string `json:"type"`                  // "image" or "host"
	Image      string `json:"image,omitempty"`       // Image reference (for image jobs)
	Digest     string `json:"digest,omitempty"`      // Image digest (for image jobs)
	NodeName   string `json:"node_name,omitempty"`   // Node name
	ForceScan  bool   `json:"force_scan"`            // Force scan flag
	FullRescan bool   `json:"full_rescan,omitempty"` // Full rescan flag (for host jobs)
}

// QueueContents represents the current state of the queue
type QueueContents struct {
	CurrentDepth   int        `json:"current_depth"`
	PeakDepth      int        `json:"peak_depth"`
	TotalEnqueued  int64      `json:"total_enqueued"`
	TotalDropped   int64      `json:"total_dropped"`
	TotalProcessed int64      `json:"total_processed"`
	JobCount       int        `json:"job_count"`      // Number of image scan jobs
	HostJobCount   int        `json:"host_job_count"` // Number of host scan jobs
	Jobs           []QueueJob `json:"jobs"`
}

// GetQueueContents returns a snapshot of all jobs currently in the queue
func (q *JobQueue) GetQueueContents() QueueContents {
	q.jobsMu.Lock()
	defer q.jobsMu.Unlock()

	q.metrics.mu.RLock()
	defer q.metrics.mu.RUnlock()

	// Build list of all jobs (images first, then hosts - matching processing order)
	jobs := make([]QueueJob, 0, len(q.jobs)+len(q.hostJobs))

	for _, job := range q.jobs {
		jobs = append(jobs, QueueJob{
			Type:      "image",
			Image:     job.Image.Reference,
			Digest:    job.Image.Digest,
			NodeName:  job.NodeName,
			ForceScan: job.ForceScan,
		})
	}

	for _, job := range q.hostJobs {
		jobs = append(jobs, QueueJob{
			Type:       "host",
			NodeName:   job.NodeName,
			ForceScan:  job.ForceScan,
			FullRescan: job.FullRescan,
		})
	}

	return QueueContents{
		CurrentDepth:   len(q.jobs) + len(q.hostJobs),
		PeakDepth:      q.metrics.peakDepth,
		TotalEnqueued:  q.metrics.totalEnqueued,
		TotalDropped:   q.metrics.totalDropped,
		TotalProcessed: q.metrics.totalProcessed,
		JobCount:       len(q.jobs),
		HostJobCount:   len(q.hostJobs),
		Jobs:           jobs,
	}
}
