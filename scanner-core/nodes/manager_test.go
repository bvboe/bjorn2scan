package nodes

import (
	"errors"
	"sync"
	"testing"
)

// mockNodeDatabase implements NodeDatabaseInterface for testing
type mockNodeDatabase struct {
	mu           sync.Mutex
	nodes        map[string]bool   // tracks which nodes exist
	addNodeCalls []string          // tracks AddNode calls
	statuses     map[string]string // per-node scan status (defaults to "pending")
	returnError  error             // error to return from AddNode
}

func newMockNodeDatabase() *mockNodeDatabase {
	return &mockNodeDatabase{
		nodes:        make(map[string]bool),
		addNodeCalls: make([]string, 0),
		statuses:     make(map[string]string),
	}
}

func (m *mockNodeDatabase) setStatus(name, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statuses[name] = status
}

func (m *mockNodeDatabase) AddNode(n Node) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.addNodeCalls = append(m.addNodeCalls, n.Name)

	if m.returnError != nil {
		return false, m.returnError
	}

	if m.nodes[n.Name] {
		// Node already exists
		return false, nil
	}

	// New node
	m.nodes[n.Name] = true
	return true, nil
}

func (m *mockNodeDatabase) UpdateNode(n Node) error {
	return nil
}

func (m *mockNodeDatabase) RemoveNode(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.nodes, name)
	return nil
}

func (m *mockNodeDatabase) GetNode(name string) (*NodeWithStatus, error) {
	return nil, nil
}

func (m *mockNodeDatabase) GetAllNodes() ([]NodeWithStatus, error) {
	return nil, nil
}

func (m *mockNodeDatabase) GetNodeScanStatus(name string) (string, error) {
	return "pending", nil
}

func (m *mockNodeDatabase) GetNodeScanStatusBulk(names []string) (map[string]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make(map[string]string)
	for _, name := range names {
		if s, ok := m.statuses[name]; ok {
			result[name] = s
		} else {
			result[name] = "pending"
		}
	}
	return result, nil
}

func (m *mockNodeDatabase) IsNodeScanComplete(name string) (bool, error) {
	return true, nil
}

func (m *mockNodeDatabase) IsNodeScanCompleteBulk(names []string) (map[string]bool, error) {
	result := make(map[string]bool)
	for _, name := range names {
		result[name] = true
	}
	return result, nil
}

// mockScanQueue implements NodeScanQueueInterface for testing
type mockScanQueue struct {
	mu              sync.Mutex
	enqueuedScans   []string // tracks EnqueueHostScan calls
	enqueuedForce   []string // tracks EnqueueHostForceScan calls
}

func newMockScanQueue() *mockScanQueue {
	return &mockScanQueue{
		enqueuedScans: make([]string, 0),
		enqueuedForce: make([]string, 0),
	}
}

func (m *mockScanQueue) EnqueueHostScan(nodeName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enqueuedScans = append(m.enqueuedScans, nodeName)
}

func (m *mockScanQueue) EnqueueHostForceScan(nodeName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enqueuedForce = append(m.enqueuedForce, nodeName)
}

func (m *mockScanQueue) getEnqueuedScans() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]string, len(m.enqueuedScans))
	copy(result, m.enqueuedScans)
	return result
}

func (m *mockScanQueue) getEnqueuedForceScans() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]string, len(m.enqueuedForce))
	copy(result, m.enqueuedForce)
	return result
}

// TestAddNode_EnqueuesScanForNewNode verifies that AddNode enqueues a scan
// only for new nodes, not for existing ones
func TestAddNode_EnqueuesScanForNewNode(t *testing.T) {
	manager := NewManager()
	db := newMockNodeDatabase()
	queue := newMockScanQueue()

	manager.SetDatabase(db)
	manager.SetScanQueue(queue)

	// Add a new node
	node := Node{
		Name:     "test-node-1",
		Hostname: "test-node-1.local",
	}
	manager.AddNode(node)

	// Verify scan was enqueued for new node
	scans := queue.getEnqueuedScans()
	if len(scans) != 1 {
		t.Errorf("Expected 1 scan enqueued, got %d", len(scans))
	}
	if len(scans) > 0 && scans[0] != "test-node-1" {
		t.Errorf("Expected scan for 'test-node-1', got '%s'", scans[0])
	}
}

// TestAddNode_DoesNotEnqueueScanForExistingNode verifies that AddNode does NOT
// enqueue a scan for a node that already exists in the database
func TestAddNode_DoesNotEnqueueScanForExistingNode(t *testing.T) {
	manager := NewManager()
	db := newMockNodeDatabase()
	queue := newMockScanQueue()

	manager.SetDatabase(db)
	manager.SetScanQueue(queue)

	node := Node{
		Name:     "test-node-1",
		Hostname: "test-node-1.local",
	}

	// Add node first time (new)
	manager.AddNode(node)

	// Clear the queue to check subsequent behavior
	queue.mu.Lock()
	queue.enqueuedScans = make([]string, 0)
	queue.mu.Unlock()

	// Add same node again (existing)
	manager.AddNode(node)

	// Verify NO scan was enqueued for existing node
	scans := queue.getEnqueuedScans()
	if len(scans) != 0 {
		t.Errorf("Expected 0 scans enqueued for existing node, got %d", len(scans))
	}
}

// TestAddNode_MultipleNodeEvents verifies that repeated node events for the
// same node do not cause multiple scans to be enqueued (the rescan loop bug)
func TestAddNode_MultipleNodeEvents(t *testing.T) {
	manager := NewManager()
	db := newMockNodeDatabase()
	queue := newMockScanQueue()

	manager.SetDatabase(db)
	manager.SetScanQueue(queue)

	node := Node{
		Name:     "test-node-1",
		Hostname: "test-node-1.local",
	}

	// Simulate multiple K8s node events (heartbeats, updates, etc.)
	for i := 0; i < 10; i++ {
		manager.AddNode(node)
	}

	// Verify only 1 scan was enqueued (for the first/new event)
	scans := queue.getEnqueuedScans()
	if len(scans) != 1 {
		t.Errorf("Expected 1 scan enqueued despite 10 events, got %d", len(scans))
	}
}

// TestAddNode_NoScanWithoutQueue verifies that AddNode doesn't panic
// when scan queue is not configured
func TestAddNode_NoScanWithoutQueue(t *testing.T) {
	manager := NewManager()
	db := newMockNodeDatabase()

	manager.SetDatabase(db)
	// Note: NOT setting scan queue

	node := Node{
		Name:     "test-node-1",
		Hostname: "test-node-1.local",
	}

	// Should not panic
	manager.AddNode(node)

	// Verify node was added to database
	if len(db.addNodeCalls) != 1 {
		t.Errorf("Expected 1 AddNode call, got %d", len(db.addNodeCalls))
	}
}

// TestAddNode_DatabaseError verifies that AddNode handles database errors gracefully
func TestAddNode_DatabaseError(t *testing.T) {
	manager := NewManager()
	db := newMockNodeDatabase()
	queue := newMockScanQueue()

	db.returnError = errors.New("database error")

	manager.SetDatabase(db)
	manager.SetScanQueue(queue)

	node := Node{
		Name:     "test-node-1",
		Hostname: "test-node-1.local",
	}

	// Should not panic
	manager.AddNode(node)

	// Verify no scan was enqueued (due to error)
	scans := queue.getEnqueuedScans()
	if len(scans) != 0 {
		t.Errorf("Expected 0 scans enqueued on error, got %d", len(scans))
	}
}

// TestSetNodes_DoesNotEnqueueScans verifies that SetNodes does NOT enqueue
// any scans (CatchUpScans handles this at startup)
func TestRescueStuckNodes_EnqueuesStuckNodes(t *testing.T) {
	manager := NewManager()
	db := newMockNodeDatabase()
	queue := newMockScanQueue()
	manager.SetDatabase(db)

	// Add nodes to manager in-memory
	for _, name := range []string{"node-pending", "node-failed", "node-completed"} {
		manager.nodes[name] = Node{Name: name}
		db.nodes[name] = true
	}
	db.setStatus("node-pending", "pending")
	db.setStatus("node-failed", "sbom_failed")
	db.setStatus("node-completed", "completed")

	manager.SetScanQueue(queue)
	queue.mu.Lock()
	queue.enqueuedScans = nil
	queue.enqueuedForce = nil
	queue.mu.Unlock()

	manager.RescueStuckNodes()

	force := queue.getEnqueuedForceScans()
	if len(force) != 2 {
		t.Fatalf("Expected 2 force scans (pending + failed), got %d: %v", len(force), force)
	}
	forceSet := make(map[string]bool)
	for _, n := range force {
		forceSet[n] = true
	}
	if !forceSet["node-pending"] {
		t.Error("Expected node-pending to be enqueued")
	}
	if !forceSet["node-failed"] {
		t.Error("Expected node-failed to be enqueued")
	}
	if forceSet["node-completed"] {
		t.Error("node-completed should not be enqueued")
	}
}

func TestRescueStuckNodes_SkipsInProgressNodes(t *testing.T) {
	manager := NewManager()
	db := newMockNodeDatabase()
	queue := newMockScanQueue()
	manager.SetDatabase(db)

	for _, name := range []string{"node-gen-sbom", "node-scan-vulns"} {
		manager.nodes[name] = Node{Name: name}
		db.nodes[name] = true
	}
	db.setStatus("node-gen-sbom", "generating_sbom")
	db.setStatus("node-scan-vulns", "scanning_vulnerabilities")

	manager.SetScanQueue(queue)
	queue.mu.Lock()
	queue.enqueuedScans = nil
	queue.enqueuedForce = nil
	queue.mu.Unlock()

	manager.RescueStuckNodes()

	if got := queue.getEnqueuedForceScans(); len(got) != 0 {
		t.Errorf("Expected no scans enqueued for in-progress nodes, got %v", got)
	}
}

func TestSetNodes_DoesNotEnqueueScans(t *testing.T) {
	manager := NewManager()
	db := newMockNodeDatabase()
	queue := newMockScanQueue()

	manager.SetDatabase(db)
	manager.SetScanQueue(queue)

	// Clear any scans from SetScanQueue's catch-up logic
	queue.mu.Lock()
	queue.enqueuedScans = make([]string, 0)
	queue.enqueuedForce = make([]string, 0)
	queue.mu.Unlock()

	nodes := []Node{
		{Name: "node-1", Hostname: "node-1.local"},
		{Name: "node-2", Hostname: "node-2.local"},
		{Name: "node-3", Hostname: "node-3.local"},
	}

	manager.SetNodes(nodes)

	// Verify NO scans were enqueued by SetNodes
	scans := queue.getEnqueuedScans()
	forceScans := queue.getEnqueuedForceScans()

	if len(scans) != 0 {
		t.Errorf("Expected 0 regular scans from SetNodes, got %d", len(scans))
	}
	if len(forceScans) != 0 {
		t.Errorf("Expected 0 force scans from SetNodes, got %d", len(forceScans))
	}
}
