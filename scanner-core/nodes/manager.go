package nodes

import (
	"log/slog"
	"sync"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/logging"
)

var log = logging.For(logging.ComponentNodes)

// NodeDatabaseInterface defines the interface for node database operations
type NodeDatabaseInterface interface {
	AddNode(n Node) (bool, error)
	UpdateNode(n Node) error
	RemoveNode(name string) error
	GetNode(name string) (*NodeWithStatus, error)
	GetAllNodes() ([]NodeWithStatus, error)
	GetNodeScanStatus(name string) (string, error)
	GetNodeScanStatusBulk(names []string) (map[string]string, error)
	IsNodeScanComplete(name string) (bool, error)
	IsNodeScanCompleteBulk(names []string) (map[string]bool, error)
}

// NodeScanQueueInterface defines the interface for enqueuing node scan jobs
type NodeScanQueueInterface interface {
	EnqueueHostScan(nodeName string)
	EnqueueHostForceScan(nodeName string)
}

// Manager handles node lifecycle management
type Manager struct {
	mu        sync.RWMutex
	nodes     map[string]Node // key: node name
	db        NodeDatabaseInterface
	scanQueue NodeScanQueueInterface
}

// NewManager creates a new node manager
func NewManager() *Manager {
	return &Manager{
		nodes: make(map[string]Node),
	}
}

// SetDatabase configures the manager to use a database for persistence
func (m *Manager) SetDatabase(db NodeDatabaseInterface) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.db = db
	log.Info("database persistence enabled")
}

// SetScanQueue configures the manager to use a scan queue for host SBOM generation.
// Catch-up scanning (enqueuing scans for existing nodes on startup) is handled
// exclusively by CatchUpScans, which is called after the informer cache is fully
// synced and all nodes are guaranteed to be in memory.
func (m *Manager) SetScanQueue(queue NodeScanQueueInterface) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanQueue = queue
	log.Info("scan queue enabled")
}

// CatchUpScans enqueues scans for all known nodes that need processing.
// Called after the K8s node informer cache has synced to catch nodes that
// arrived via AddNode after SetScanQueue ran its initial catch-up.
func (m *Manager) CatchUpScans() {
	m.mu.Lock()
	if m.db == nil || m.scanQueue == nil || len(m.nodes) == 0 {
		m.mu.Unlock()
		return
	}
	nodeNames := make([]string, 0, len(m.nodes))
	for _, n := range m.nodes {
		nodeNames = append(nodeNames, n.Name)
	}
	m.mu.Unlock()

	scanStatuses, err := m.db.GetNodeScanStatusBulk(nodeNames)
	if err != nil {
		log.Error("catch-up: failed to fetch node scan statuses", slog.Any("error", err))
		return
	}

	scannedNodes := make([]string, 0)
	for name, status := range scanStatuses {
		if status == "completed" {
			scannedNodes = append(scannedNodes, name)
		}
	}
	completenessStatus := make(map[string]bool)
	if len(scannedNodes) > 0 {
		completenessStatus, err = m.db.IsNodeScanCompleteBulk(scannedNodes)
		if err != nil {
			log.Error("catch-up: failed to fetch node completeness", slog.Any("error", err))
		}
	}

	enqueuedCount := 0
	for name, status := range scanStatuses {
		switch status {
		case "pending", "generating_sbom", "scanning_vulnerabilities",
			"sbom_failed", "sbom_unavailable", "vuln_scan_failed":
			m.scanQueue.EnqueueHostForceScan(name)
			enqueuedCount++
		case "completed":
			if !completenessStatus[name] {
				m.scanQueue.EnqueueHostForceScan(name)
				enqueuedCount++
			}
		}
	}

	if enqueuedCount > 0 {
		log.Info("catch-up after informer sync: enqueued scans",
			"enqueued", enqueuedCount, "total", len(nodeNames))
	}
}

// RescueStuckNodes re-enqueues nodes that are stuck in a terminal-less idle state.
// Unlike CatchUpScans (which is safe at startup because ResetInterruptedScans has
// already moved in-progress states → pending), this method is safe to call while
// scans are actively running: it skips generating_sbom and scanning_vulnerabilities
// so it never triggers a double-scan on a node that is already being processed.
func (m *Manager) RescueStuckNodes() {
	m.mu.Lock()
	if m.db == nil || m.scanQueue == nil || len(m.nodes) == 0 {
		m.mu.Unlock()
		return
	}
	nodeNames := make([]string, 0, len(m.nodes))
	for _, n := range m.nodes {
		nodeNames = append(nodeNames, n.Name)
	}
	m.mu.Unlock()

	scanStatuses, err := m.db.GetNodeScanStatusBulk(nodeNames)
	if err != nil {
		log.Error("rescue: failed to fetch node scan statuses", slog.Any("error", err))
		return
	}

	enqueuedCount := 0
	for name, status := range scanStatuses {
		switch status {
		case "pending", "sbom_failed", "sbom_unavailable", "vuln_scan_failed":
			m.scanQueue.EnqueueHostForceScan(name)
			enqueuedCount++
		// generating_sbom and scanning_vulnerabilities are intentionally skipped:
		// those nodes are actively being processed and must not be double-enqueued.
		}
	}

	if enqueuedCount > 0 {
		log.Info("rescued stuck nodes", "enqueued", enqueuedCount, "total", len(nodeNames))
	}
}

// AddNode adds or updates a node in the manager
func (m *Manager) AddNode(n Node) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nodes[n.Name] = n

	log.Info("add node",
		"name", n.Name, "hostname", n.Hostname, "os", n.OSRelease, "arch", n.Architecture)

	// Persist to database if configured
	if m.db != nil {
		isNew, err := m.db.AddNode(n)
		if err != nil {
			log.Error("failed to add node to database",
				"node", n.Name, slog.Any("error", err))
			return
		}

		// Only enqueue scan for NEW nodes. Existing nodes are handled by:
		// - CatchUpScans() at startup (retries failed/interrupted scans)
		// - RescanNodesOnDBUpdate() when grype DB updates
		// This avoids unnecessary retries on every K8s node event (~every 30-90s)
		if isNew && m.scanQueue != nil {
			m.scanQueue.EnqueueHostScan(n.Name)
		}
	}
}

// UpdateNode updates an existing node
func (m *Manager) UpdateNode(n Node) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if node exists
	_, exists := m.nodes[n.Name]
	if !exists {
		log.Debug("node not found, adding instead", "node", n.Name)
	}

	m.nodes[n.Name] = n

	log.Info("update node",
		"name", n.Name, "hostname", n.Hostname, "os", n.OSRelease, "arch", n.Architecture)

	// Update in database if configured
	if m.db != nil {
		if err := m.db.UpdateNode(n); err != nil {
			log.Error("failed to update node in database",
				"node", n.Name, slog.Any("error", err))
		}
	}
}

// RemoveNode removes a node from the manager
func (m *Manager) RemoveNode(name string) {
	m.mu.Lock()
	delete(m.nodes, name)
	m.mu.Unlock()

	log.Info("remove node", "name", name)

	// Remove from database if configured. The DB call is outside the mutex
	// since it doesn't need in-memory state. We retry on transient SQLITE_BUSY
	// errors (which can occur when a write transaction is in progress).
	if m.db == nil {
		return
	}
	const maxAttempts = 4
	for attempt := range maxAttempts {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		err := m.db.RemoveNode(name)
		if err == nil {
			return
		}
		log.Error("failed to remove node from database",
			"node", name, "attempt", attempt+1, slog.Any("error", err))
	}
	log.Error("giving up removing node from database after retries", "node", name)
}

// SetNodes replaces the entire collection of nodes
func (m *Manager) SetNodes(nodeList []Node) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear existing nodes
	m.nodes = make(map[string]Node)

	// Add all new nodes
	for _, n := range nodeList {
		m.nodes[n.Name] = n
	}

	log := log
	log.Info("set nodes", "count", len(nodeList))

	// Log first 3 nodes as samples for debugging
	if len(nodeList) > 0 {
		sampleCount := 3
		if len(nodeList) < sampleCount {
			sampleCount = len(nodeList)
		}
		log.Debug("sample nodes:")
		for i := 0; i < sampleCount; i++ {
			n := nodeList[i]
			log.Debug("sample node", "index", i,
				"name", n.Name, "hostname", n.Hostname, "os", n.OSRelease, "arch", n.Architecture)
		}
		if len(nodeList) > sampleCount {
			log.Debug("additional nodes not shown", "count", len(nodeList)-sampleCount)
		}
	}

	// Note: We don't enqueue scans here. CatchUpScans() handles all retry logic at startup.
	// This avoids duplicating work and keeps the retry logic in one place.
}

// GetAllNodes returns all nodes (thread-safe copy)
func (m *Manager) GetAllNodes() []Node {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Node, 0, len(m.nodes))
	for _, n := range m.nodes {
		result = append(result, n)
	}
	return result
}

// GetNodeCount returns the number of nodes
func (m *Manager) GetNodeCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.nodes)
}

// GetNode retrieves a specific node
func (m *Manager) GetNode(name string) (Node, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	n, exists := m.nodes[name]
	return n, exists
}
