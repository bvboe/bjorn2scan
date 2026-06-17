package containers

import (
	"log/slog"
	"sync"

	"github.com/bvboe/b2s-go/scanner-core/logging"
)

var log = logging.For(logging.ComponentContainers)

// ReconciliationStats holds statistics about a reconciliation operation
type ReconciliationStats struct {
	ContainersAdded   int // Number of new containers added
	ContainersRemoved int // Number of containers removed
	ImagesAdded       int // Number of new images discovered
}

// DatabaseInterface defines the interface for database operations
type DatabaseInterface interface {
	AddContainer(c Container) (bool, error)
	RemoveContainer(id ContainerID) error
	SetContainers(containers []Container) (*ReconciliationStats, error)
	GetImageScanStatus(digest string) (string, error)
	GetImageScanStatusBulk(digests []string) (map[string]string, error)
	IsScanDataComplete(digest string) (bool, error)
	IsScanDataCompleteBulk(digests []string) (map[string]bool, error)
}

// ScanQueueInterface defines the interface for enqueuing scan jobs
type ScanQueueInterface interface {
	EnqueueScan(image ImageID, nodeName string, containerRuntime string)
	EnqueueForceScan(image ImageID, nodeName string, containerRuntime string)
}

// RefreshTrigger defines the interface for triggering container refreshes
// This is implemented by the agent or k8s-scan-server to provide running container data
type RefreshTrigger interface {
	// TriggerRefresh signals that scanner-core wants updated container data
	// The implementation should gather current container data and call SetContainers
	TriggerRefresh() error
}

// Manager handles container lifecycle management
type Manager struct {
	mu         sync.RWMutex
	containers map[string]Container // key: namespace/pod/name
	db         DatabaseInterface    // optional database persistence
	scanQueue  ScanQueueInterface   // optional scan queue for SBOM generation
}

// NewManager creates a new container manager
func NewManager() *Manager {
	return &Manager{
		containers: make(map[string]Container),
	}
}

// SetDatabase configures the manager to use a database for persistence
func (m *Manager) SetDatabase(db DatabaseInterface) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.db = db
	log.Info("database persistence enabled")
}

// SetScanQueue configures the manager to use a scan queue for SBOM generation
// After setting the queue, it enqueues scans for any images that were discovered
// before the queue was connected (catch-up for initial sync)
func (m *Manager) SetScanQueue(queue ScanQueueInterface) {
	m.mu.Lock()
	m.scanQueue = queue
	log.Info("scan queue enabled")

	// Catch-up: enqueue scans for images discovered before queue was connected
	// This handles images from initial sync that couldn't be enqueued
	if m.db != nil && len(m.containers) > 0 {
		containerCount := len(m.containers)
		log.Info("checking containers for pending scans", "count", containerCount)

		// Build map of digest -> container (first container per digest for scan context)
		digestToContainer := make(map[string]Container)
		for _, c := range m.containers {
			if c.Image.Digest == "" {
				continue
			}
			if _, exists := digestToContainer[c.Image.Digest]; !exists {
				digestToContainer[c.Image.Digest] = c
			}
		}
		m.mu.Unlock()

		// Collect unique digests
		digests := make([]string, 0, len(digestToContainer))
		for digest := range digestToContainer {
			digests = append(digests, digest)
		}

		if len(digests) == 0 {
			log.Debug("no images to check for pending scans")
			return
		}

		// Get status for all images in a single bulk query
		scanStatuses, err := m.db.GetImageScanStatusBulk(digests)
		if err != nil {
			log.Error("failed to fetch bulk scan status", slog.Any("error", err))
			return
		}

		// Identify digests that need completeness check (those marked as "scanned")
		scannedDigests := make([]string, 0)
		for digest, status := range scanStatuses {
			if status == "scanned" {
				scannedDigests = append(scannedDigests, digest)
			}
		}

		// Get completeness status for scanned images in a single bulk query
		var completenessStatus map[string]bool
		if len(scannedDigests) > 0 {
			completenessStatus, err = m.db.IsScanDataCompleteBulk(scannedDigests)
			if err != nil {
				log.Error("failed to fetch bulk completeness status", slog.Any("error", err))
				completenessStatus = make(map[string]bool)
			}
		} else {
			completenessStatus = make(map[string]bool)
		}

		// Enqueue scans based on status
		log := log
		enqueuedCount := 0
		for digest, status := range scanStatuses {
			c := digestToContainer[digest]

			switch status {
			case "pending":
				// New image, enqueue normal scan
				log.Debug("enqueuing scan for new image", "image", c.Image.Reference, "digest", c.Image.Digest)
				m.scanQueue.EnqueueScan(c.Image, c.NodeName, c.ContainerRuntime)
				enqueuedCount++

			case "failed":
				// Previous scan failed, retry with force scan
				log.Debug("retrying failed scan", "image", c.Image.Reference, "digest", c.Image.Digest)
				m.scanQueue.EnqueueForceScan(c.Image, c.NodeName, c.ContainerRuntime)
				enqueuedCount++

			case "scanned":
				// Check if data is actually complete
				if !completenessStatus[digest] {
					log.Debug("retrying scan for incomplete data", "image", c.Image.Reference, "digest", c.Image.Digest)
					m.scanQueue.EnqueueForceScan(c.Image, c.NodeName, c.ContainerRuntime)
					enqueuedCount++
				}

			case "scanning":
				// Image is in an intermediate state (previous scan was interrupted)
				log.Debug("retrying interrupted scan", "image", c.Image.Reference, "digest", c.Image.Digest)
				m.scanQueue.EnqueueForceScan(c.Image, c.NodeName, c.ContainerRuntime)
				enqueuedCount++
			}
		}

		log.Info("queued catch-up scans", "enqueued", enqueuedCount, "total", len(digests))
		return
	}
	m.mu.Unlock()
}

// makeKey creates a unique key for a container
func makeKey(namespace, pod, name string) string {
	return namespace + "/" + pod + "/" + name
}

// AddContainer adds a single container to the manager
func (m *Manager) AddContainer(c Container) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := makeKey(c.ID.Namespace, c.ID.Pod, c.ID.Name)
	m.containers[key] = c

	log.Info("add container",
		"namespace", c.ID.Namespace, "pod", c.ID.Pod, "name", c.ID.Name,
		"image", c.Image.Reference, "digest", c.Image.Digest)

	// Persist to database if configured
	if m.db != nil {
		if _, err := m.db.AddContainer(c); err != nil {
			log.Error("failed to add container to database",
				"container", c.ID.Name, slog.Any("error", err))
			return
		}

		// Check if this image needs scanning or retrying
		if m.scanQueue != nil && c.Image.Digest != "" {
			m.checkAndEnqueueScan(c)
		}
	}
}

// RemoveContainer removes a single container from the manager
func (m *Manager) RemoveContainer(id ContainerID) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := makeKey(id.Namespace, id.Pod, id.Name)
	delete(m.containers, key)

	log.Info("remove container",
		"namespace", id.Namespace, "pod", id.Pod, "name", id.Name)

	// Remove from database if configured
	if m.db != nil {
		if err := m.db.RemoveContainer(id); err != nil {
			log.Error("failed to remove container from database",
				"container", id.Name, slog.Any("error", err))
		}
	}
}

// SetContainers replaces the entire collection of containers
func (m *Manager) SetContainers(containers []Container) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear existing containers
	m.containers = make(map[string]Container)

	// Add all new containers
	for _, c := range containers {
		key := makeKey(c.ID.Namespace, c.ID.Pod, c.ID.Name)
		m.containers[key] = c
	}

	// Log summary instead of every container (to reduce noise in large clusters)
	uniqueImages := make(map[string]bool)
	uniqueNodes := make(map[string]bool)
	for _, c := range containers {
		if c.Image.Digest != "" {
			uniqueImages[c.Image.Digest] = true
		}
		if c.NodeName != "" {
			uniqueNodes[c.NodeName] = true
		}
	}

	log := log
	log.Info("set containers", "containers", len(containers), "unique_images", len(uniqueImages), "nodes", len(uniqueNodes))

	// Log first 3 containers as samples for debugging (only if we have containers)
	if len(containers) > 0 {
		sampleCount := 3
		if len(containers) < sampleCount {
			sampleCount = len(containers)
		}
		log.Debug("sample containers:")
		for i := 0; i < sampleCount; i++ {
			c := containers[i]
			log.Debug("sample container", "index", i,
				"namespace", c.ID.Namespace, "pod", c.ID.Pod, "name", c.ID.Name,
				"image", c.Image.Reference, "node", c.NodeName)
		}
		if len(containers) > sampleCount {
			log.Debug("additional containers not shown", "count", len(containers)-sampleCount)
		}
	}

	// Update database if configured
	if m.db != nil {
		stats, err := m.db.SetContainers(containers)
		if err != nil {
			log.Error("failed to set containers in database", slog.Any("error", err))
			return
		}

		// Log reconciliation summary
		if stats != nil {
			log.Info("reconciliation summary",
				"added", stats.ContainersAdded,
				"removed", stats.ContainersRemoved,
				"new_images", stats.ImagesAdded)
		}

		// Enqueue scan jobs for images that need scanning or retrying
		if m.scanQueue != nil {
			// Track unique images to avoid duplicate scan jobs
			seenDigests := make(map[string]bool)

			for _, c := range containers {
				if c.Image.Digest == "" {
					continue // Skip containers without digest
				}

				// Skip if we've already processed this digest
				if seenDigests[c.Image.Digest] {
					continue
				}
				seenDigests[c.Image.Digest] = true

				// Check and enqueue scan with retry logic
				m.checkAndEnqueueScan(c)
			}
		}
	}
}

// GetAllContainers returns all containers (thread-safe copy)
func (m *Manager) GetAllContainers() []Container {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Container, 0, len(m.containers))
	for _, c := range m.containers {
		result = append(result, c)
	}
	return result
}

// GetContainerCount returns the number of containers
func (m *Manager) GetContainerCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.containers)
}

// GetActiveContainerIDs returns the IDs of all containers currently known to the manager
func (m *Manager) GetActiveContainerIDs() []ContainerID {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]ContainerID, 0, len(m.containers))
	for _, c := range m.containers {
		ids = append(ids, c.ID)
	}
	return ids
}

// GetContainer retrieves a specific container
func (m *Manager) GetContainer(namespace, pod, name string) (Container, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key := makeKey(namespace, pod, name)
	c, exists := m.containers[key]
	return c, exists
}

// CatchUpScans enqueues scans for all known images that need processing.
// Called after the K8s pod informer cache has synced to catch images that
// arrived via AddContainer after SetScanQueue ran its initial catch-up.
func (m *Manager) CatchUpScans() {
	m.mu.Lock()
	if m.db == nil || m.scanQueue == nil || len(m.containers) == 0 {
		m.mu.Unlock()
		return
	}
	digestToContainer := make(map[string]Container)
	for _, c := range m.containers {
		if c.Image.Digest == "" {
			continue
		}
		if _, exists := digestToContainer[c.Image.Digest]; !exists {
			digestToContainer[c.Image.Digest] = c
		}
	}
	m.mu.Unlock()

	digests := make([]string, 0, len(digestToContainer))
	for digest := range digestToContainer {
		digests = append(digests, digest)
	}
	if len(digests) == 0 {
		return
	}

	scanStatuses, err := m.db.GetImageScanStatusBulk(digests)
	if err != nil {
		log.Error("catch-up: failed to fetch image scan statuses", slog.Any("error", err))
		return
	}

	scannedDigests := make([]string, 0)
	for digest, status := range scanStatuses {
		if status == "scanned" {
			scannedDigests = append(scannedDigests, digest)
		}
	}
	completenessStatus := make(map[string]bool)
	if len(scannedDigests) > 0 {
		completenessStatus, err = m.db.IsScanDataCompleteBulk(scannedDigests)
		if err != nil {
			log.Error("catch-up: failed to fetch image completeness", slog.Any("error", err))
		}
	}

	enqueuedCount := 0
	for digest, status := range scanStatuses {
		c := digestToContainer[digest]
		switch status {
		case "pending", "scanning", "failed":
			m.scanQueue.EnqueueForceScan(c.Image, c.NodeName, c.ContainerRuntime)
			enqueuedCount++
		case "scanned":
			if !completenessStatus[digest] {
				m.scanQueue.EnqueueForceScan(c.Image, c.NodeName, c.ContainerRuntime)
				enqueuedCount++
			}
		}
	}

	if enqueuedCount > 0 {
		log.Info("catch-up after informer sync: enqueued scans",
			"enqueued", enqueuedCount, "total", len(digests))
	}
}

// ReconcileDB synchronizes the database container table with the current in-memory state.
// Call this after the K8s informer cache has fully synced to remove rows for pods
// that terminated while the scan-server was down (missed delete events).
func (m *Manager) ReconcileDB() {
	m.mu.RLock()
	current := make([]Container, 0, len(m.containers))
	for _, c := range m.containers {
		current = append(current, c)
	}
	m.mu.RUnlock()

	if m.db == nil {
		return
	}

	stats, err := m.db.SetContainers(current)
	if err != nil {
		log.Error("failed to reconcile container database", slog.Any("error", err))
		return
	}
	if stats != nil && (stats.ContainersAdded > 0 || stats.ContainersRemoved > 0) {
		log.Info("startup reconciliation complete",
			"added", stats.ContainersAdded,
			"removed", stats.ContainersRemoved,
			"new_images", stats.ImagesAdded)
	}
}

// checkAndEnqueueScan checks if an image needs scanning and enqueues it with appropriate flags
// This method handles retrying failed or incomplete scans
func (m *Manager) checkAndEnqueueScan(c Container) {
	log := log
	scanStatus, err := m.db.GetImageScanStatus(c.Image.Digest)
	if err != nil {
		log.Error("failed to check scan status", "digest", c.Image.Digest, slog.Any("error", err))
		return
	}

	// Handle different scan statuses
	switch scanStatus {
	case "pending":
		// New image, enqueue normal scan
		log.Debug("enqueuing scan for new image", "image", c.Image.Reference, "digest", c.Image.Digest)
		m.scanQueue.EnqueueScan(c.Image, c.NodeName, c.ContainerRuntime)

	case "failed":
		// Previous scan failed, retry with force scan
		log.Debug("retrying failed scan", "image", c.Image.Reference, "digest", c.Image.Digest)
		m.scanQueue.EnqueueForceScan(c.Image, c.NodeName, c.ContainerRuntime)

	case "scanned":
		// Check if data is actually complete
		isComplete, err := m.db.IsScanDataComplete(c.Image.Digest)
		if err != nil {
			log.Error("failed to check scan data completeness", "digest", c.Image.Digest, slog.Any("error", err))
			return
		}
		if !isComplete {
			// Data is incomplete, retry with force scan
			log.Debug("retrying scan for incomplete data", "image", c.Image.Reference, "digest", c.Image.Digest)
			m.scanQueue.EnqueueForceScan(c.Image, c.NodeName, c.ContainerRuntime)
		}
		// If complete, no action needed

	case "scanning":
		// Image is in an intermediate state (generating_sbom).
		// This typically means a previous scan was interrupted (e.g., pod restart).
		// Re-enqueue with force scan to resume/restart the scan.
		log.Debug("retrying interrupted scan", "image", c.Image.Reference, "digest", c.Image.Digest)
		m.scanQueue.EnqueueForceScan(c.Image, c.NodeName, c.ContainerRuntime)
	}
}
