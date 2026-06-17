package jobs

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
	"github.com/bvboe/b2s-go/scanner-core/vulndb"
)

var (
	errNotFound = fmt.Errorf("not found")
	errDatabase = fmt.Errorf("database error")
)

// Mock implementations for testing

type MockDatabaseUpdater struct {
	hasChanged     bool
	err            error
	currentVersion *vulndb.DatabaseStatus
}

func (m *MockDatabaseUpdater) CheckForUpdates(ctx context.Context) (bool, error) {
	return m.hasChanged, m.err
}

func (m *MockDatabaseUpdater) GetCurrentVersion() *vulndb.DatabaseStatus {
	return m.currentVersion
}

type MockDatabase struct {
	images              []database.ContainerImage
	imagesNeedingRescan []database.ContainerImage
	instances           map[string]*database.ContainerRow
	err                 error

	reapCalled    bool
	reapMaxAge    time.Duration
	reapNodeRows  int64
	reapImageRows int64
}

func (m *MockDatabase) GetImagesByStatus(status database.Status) ([]database.ContainerImage, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.images, nil
}

func (m *MockDatabase) GetFirstContainerForImage(digest string) (*database.ContainerRow, error) {
	if m.err != nil {
		return nil, m.err
	}
	if instance, ok := m.instances[digest]; ok {
		return instance, nil
	}
	return nil, errNotFound
}

func (m *MockDatabase) GetImagesNeedingRescan(currentGrypeDBBuilt time.Time) ([]database.ContainerImage, error) {
	if m.err != nil {
		return nil, m.err
	}
	// If imagesNeedingRescan is explicitly set, use it; otherwise fall back to images
	if m.imagesNeedingRescan != nil {
		return m.imagesNeedingRescan, nil
	}
	return m.images, nil
}

func (m *MockDatabase) ReapStuckScans(maxAge time.Duration) (int64, int64, error) {
	m.reapCalled = true
	m.reapMaxAge = maxAge
	if m.err != nil {
		return 0, 0, m.err
	}
	return m.reapNodeRows, m.reapImageRows, nil
}

type MockScanQueue struct {
	enqueuedScans []EnqueuedScan
}

type EnqueuedScan struct {
	Digest           string
	Reference        string
	NodeName         string
	ContainerRuntime string
}

func (m *MockScanQueue) EnqueueForceScan(image containers.ImageID, nodeName string, containerRuntime string) {
	m.enqueuedScans = append(m.enqueuedScans, EnqueuedScan{
		Digest:           image.Digest,
		Reference:        image.Reference,
		NodeName:         nodeName,
		ContainerRuntime: containerRuntime,
	})
}

// Test: images needing rescan are enqueued
func TestRescanDatabaseJob_Integration(t *testing.T) {
	// Setup: mock database updater with a current version
	mockDBUpdater := &MockDatabaseUpdater{
		hasChanged: true,
		currentVersion: &vulndb.DatabaseStatus{
			Built:         time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
			SchemaVersion: "v6.1.3",
			Path:          "/test/path",
		},
	}

	// Setup: mock database with completed images
	mockDB := &MockDatabase{
		images: []database.ContainerImage{
			{
				ID:     1,
				Digest: "sha256:abc123",
				Status: "completed",
			},
			{
				ID:     2,
				Digest: "sha256:def456",
				Status: "completed",
			},
		},
		instances: map[string]*database.ContainerRow{
			"sha256:abc123": {
				Namespace:        "default",
				Pod:              "pod1",
				Name:             "container1",
				Reference:        "nginx:latest",
				NodeName:         "node1",
				ContainerRuntime: "docker",
			},
			"sha256:def456": {
				Namespace:        "default",
				Pod:              "pod2",
				Name:             "container2",
				Reference:        "redis:7.0",
				NodeName:         "node2",
				ContainerRuntime: "containerd",
			},
		},
	}

	// Setup: mock scan queue
	mockQueue := &MockScanQueue{}

	// Create job
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)

	// Run job
	err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("Job failed: %v", err)
	}

	// Verify: 2 images were enqueued
	if len(mockQueue.enqueuedScans) != 2 {
		t.Errorf("Expected 2 rescans, got %d", len(mockQueue.enqueuedScans))
	}

	// Verify: correct images enqueued
	expectedScans := map[string]EnqueuedScan{
		"sha256:abc123": {
			Digest:           "sha256:abc123",
			Reference:        "nginx:latest",
			NodeName:         "node1",
			ContainerRuntime: "docker",
		},
		"sha256:def456": {
			Digest:           "sha256:def456",
			Reference:        "redis:7.0",
			NodeName:         "node2",
			ContainerRuntime: "containerd",
		},
	}

	for _, scan := range mockQueue.enqueuedScans {
		expected, ok := expectedScans[scan.Digest]
		if !ok {
			t.Errorf("Unexpected digest enqueued: %s", scan.Digest)
			continue
		}

		if scan.Reference != expected.Reference {
			t.Errorf("Expected reference %s, got %s", expected.Reference, scan.Reference)
		}
		if scan.NodeName != expected.NodeName {
			t.Errorf("Expected node %s, got %s", expected.NodeName, scan.NodeName)
		}
		if scan.ContainerRuntime != expected.ContainerRuntime {
			t.Errorf("Expected runtime %s, got %s", expected.ContainerRuntime, scan.ContainerRuntime)
		}
	}
}

// Test: no grype database available, no rescans triggered
func TestRescanDatabaseJob_NoGrypeDatabase(t *testing.T) {
	// Setup: mock database updater with no current version (nil)
	mockDBUpdater := &MockDatabaseUpdater{
		hasChanged:     false,
		currentVersion: nil, // No grype database available
	}

	// Setup: mock database with completed images
	mockDB := &MockDatabase{
		images: []database.ContainerImage{
			{ID: 1, Digest: "sha256:abc123", Status: "completed"},
		},
		instances: map[string]*database.ContainerRow{
			"sha256:abc123": {NodeName: "node1", ContainerRuntime: "docker", Reference: "nginx:latest"},
		},
	}

	// Setup: mock scan queue
	mockQueue := &MockScanQueue{}

	// Create job
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)

	// Run job
	err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("Job failed: %v", err)
	}

	// Verify: no rescans enqueued (no grype DB to scan with)
	if len(mockQueue.enqueuedScans) != 0 {
		t.Errorf("Expected 0 rescans, got %d", len(mockQueue.enqueuedScans))
	}
}

// Test: no images needing rescan, job succeeds with no work
func TestRescanDatabaseJob_NoImagesNeedingRescan(t *testing.T) {
	// Setup: mock database updater with current version
	mockDBUpdater := &MockDatabaseUpdater{
		hasChanged: true,
		currentVersion: &vulndb.DatabaseStatus{
			Built:         time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
			SchemaVersion: "v6.1.3",
			Path:          "/test/path",
		},
	}

	// Setup: mock database with no images needing rescan
	mockDB := &MockDatabase{
		imagesNeedingRescan: []database.ContainerImage{}, // Empty - all images up to date
		instances:           map[string]*database.ContainerRow{},
	}

	// Setup: mock scan queue
	mockQueue := &MockScanQueue{}

	// Create job
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)

	// Run job
	err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("Job should succeed with no images, got error: %v", err)
	}

	// Verify: no rescans enqueued
	if len(mockQueue.enqueuedScans) != 0 {
		t.Errorf("Expected 0 rescans, got %d", len(mockQueue.enqueuedScans))
	}
}

// Test: missing container instances, orphaned images skipped
func TestRescanDatabaseJob_MissingInstances(t *testing.T) {
	// Setup: mock database updater with current version
	mockDBUpdater := &MockDatabaseUpdater{
		hasChanged: true,
		currentVersion: &vulndb.DatabaseStatus{
			Built:         time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
			SchemaVersion: "v6.1.3",
			Path:          "/test/path",
		},
	}

	// Setup: mock database with images needing rescan but missing instances
	mockDB := &MockDatabase{
		imagesNeedingRescan: []database.ContainerImage{
			{ID: 1, Digest: "sha256:abc123", Status: "completed"},
			{ID: 2, Digest: "sha256:def456", Status: "completed"}, // No instance
			{ID: 3, Digest: "sha256:ghi789", Status: "completed"},
		},
		instances: map[string]*database.ContainerRow{
			"sha256:abc123": {NodeName: "node1", ContainerRuntime: "docker", Reference: "nginx:latest"},
			// sha256:def456 is missing (orphaned)
			"sha256:ghi789": {NodeName: "node3", ContainerRuntime: "containerd", Reference: "redis:7.0"},
		},
	}

	// Setup: mock scan queue
	mockQueue := &MockScanQueue{}

	// Create job
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)

	// Run job
	err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("Job failed: %v", err)
	}

	// Verify: only 2 rescans enqueued (orphaned image skipped)
	if len(mockQueue.enqueuedScans) != 2 {
		t.Errorf("Expected 2 rescans (orphaned skipped), got %d", len(mockQueue.enqueuedScans))
	}

	// Verify: orphaned digest NOT enqueued
	for _, scan := range mockQueue.enqueuedScans {
		if scan.Digest == "sha256:def456" {
			t.Error("Orphaned image should not be enqueued")
		}
	}
}

// Test: database updater error, job fails
func TestRescanDatabaseJob_UpdaterError(t *testing.T) {
	// Setup: mock database updater that returns error
	mockDBUpdater := &MockDatabaseUpdater{
		hasChanged: false,
		err:        errDatabase,
	}

	mockDB := &MockDatabase{
		images:    []database.ContainerImage{},
		instances: map[string]*database.ContainerRow{},
	}

	mockQueue := &MockScanQueue{}

	// Create job
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)

	// Run job
	err := job.Run(context.Background())
	if err == nil {
		t.Error("Expected error from database updater")
	}

	// Verify: no rescans enqueued
	if len(mockQueue.enqueuedScans) != 0 {
		t.Errorf("Expected 0 rescans on error, got %d", len(mockQueue.enqueuedScans))
	}
}

// Test: database error when getting images needing rescan
func TestRescanDatabaseJob_DatabaseError(t *testing.T) {
	// Setup: mock database updater with current version
	mockDBUpdater := &MockDatabaseUpdater{
		hasChanged: true,
		currentVersion: &vulndb.DatabaseStatus{
			Built:         time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
			SchemaVersion: "v6.1.3",
			Path:          "/test/path",
		},
	}

	// Setup: mock database that returns error
	mockDB := &MockDatabase{
		imagesNeedingRescan: nil,
		instances:           nil,
		err:                 errDatabase,
	}

	mockQueue := &MockScanQueue{}

	// Create job
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)

	// Run job
	err := job.Run(context.Background())
	if err == nil {
		t.Error("Expected error from database")
	}

	// Verify: no rescans enqueued
	if len(mockQueue.enqueuedScans) != 0 {
		t.Errorf("Expected 0 rescans on error, got %d", len(mockQueue.enqueuedScans))
	}
}

// Test: context cancellation during job execution
func TestRescanDatabaseJob_ContextCancellation(t *testing.T) {
	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	// Setup: mock database updater (will be called with cancelled context)
	mockDBUpdater := &MockDatabaseUpdater{hasChanged: false}

	mockDB := &MockDatabase{
		images:    []database.ContainerImage{},
		instances: map[string]*database.ContainerRow{},
	}

	mockQueue := &MockScanQueue{}

	// Create job
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)

	// Run job with cancelled context
	// Note: Our current implementation doesn't explicitly check context in CheckForUpdates,
	// but the database updater's HTTP client will respect the context
	err := job.Run(ctx)

	// The database updater should handle context cancellation
	// For this test, we just verify the job doesn't panic
	_ = err // Error handling depends on database updater implementation
}

// Test: job name
func TestRescanDatabaseJob_Name(t *testing.T) {
	mockDBUpdater := &MockDatabaseUpdater{}
	mockDB := &MockDatabase{}
	mockQueue := &MockScanQueue{}

	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)

	if job.Name() != "rescan-database" {
		t.Errorf("Expected name 'rescan-database', got '%s'", job.Name())
	}
}

// Test: panic on nil dependencies
func TestNewRescanDatabaseJob_NilDependencies(t *testing.T) {
	mockDBUpdater := &MockDatabaseUpdater{}
	mockDB := &MockDatabase{}
	mockQueue := &MockScanQueue{}

	// Test nil database updater
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for nil dbUpdater")
		}
	}()
	NewRescanDatabaseJob(nil, mockDB, mockQueue)

	// Test nil database
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for nil database")
		}
	}()
	NewRescanDatabaseJob(mockDBUpdater, nil, mockQueue)

	// Test nil scan queue
	defer func() {
		if r := recover(); r == nil {
			t.Error("Expected panic for nil scan queue")
		}
	}()
	NewRescanDatabaseJob(mockDBUpdater, mockDB, nil)
}

// Mock implementations for node rescanning tests

type MockNodeDatabase struct {
	nodesNeedingRescan []nodes.NodeWithStatus
	err                error
}

func (m *MockNodeDatabase) GetAllNodes() ([]nodes.NodeWithStatus, error) {
	return nil, m.err
}

func (m *MockNodeDatabase) GetNodesNeedingRescan(currentGrypeDBBuilt time.Time) ([]nodes.NodeWithStatus, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.nodesNeedingRescan, nil
}

type MockNodeScanQueue struct {
	enqueuedNodes []string
}

func (m *MockNodeScanQueue) EnqueueHostForceScan(nodeName string) {
	m.enqueuedNodes = append(m.enqueuedNodes, nodeName)
}

// Test: SetNodeScanning enables node rescanning on grype DB update
func TestRescanDatabaseJob_WithNodeScanning(t *testing.T) {
	// Setup: mock database updater with a new grype DB version
	grypeDBBuilt := time.Date(2026, 3, 17, 6, 0, 0, 0, time.UTC)
	mockDBUpdater := &MockDatabaseUpdater{
		hasChanged: true,
		currentVersion: &vulndb.DatabaseStatus{
			Built:         grypeDBBuilt,
			SchemaVersion: "v6.1.4",
			Path:          "/test/path",
		},
	}

	// Setup: mock image database (no images need rescan)
	mockDB := &MockDatabase{
		imagesNeedingRescan: []database.ContainerImage{},
		instances:           map[string]*database.ContainerRow{},
	}

	// Setup: mock image scan queue
	mockQueue := &MockScanQueue{}

	// Setup: mock node database with nodes needing rescan
	mockNodeDB := &MockNodeDatabase{
		nodesNeedingRescan: []nodes.NodeWithStatus{
			{Node: nodes.Node{Name: "node-1"}},
			{Node: nodes.Node{Name: "node-2"}},
		},
	}

	// Setup: mock node scan queue
	mockNodeQueue := &MockNodeScanQueue{}

	// Create job and configure node scanning
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)
	job.SetNodeScanning(mockNodeDB, mockNodeQueue)

	// Run job
	err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("Job failed: %v", err)
	}

	// Verify: both nodes were enqueued for rescan
	if len(mockNodeQueue.enqueuedNodes) != 2 {
		t.Errorf("Expected 2 nodes enqueued, got %d", len(mockNodeQueue.enqueuedNodes))
	}

	// Verify: correct nodes were enqueued
	expectedNodes := map[string]bool{"node-1": true, "node-2": true}
	for _, nodeName := range mockNodeQueue.enqueuedNodes {
		if !expectedNodes[nodeName] {
			t.Errorf("Unexpected node enqueued: %s", nodeName)
		}
		delete(expectedNodes, nodeName)
	}
	if len(expectedNodes) > 0 {
		t.Errorf("Some expected nodes were not enqueued: %v", expectedNodes)
	}
}

// Test: Without SetNodeScanning, nodes are not rescanned
func TestRescanDatabaseJob_WithoutNodeScanning(t *testing.T) {
	// Setup: mock database updater with a new grype DB version
	mockDBUpdater := &MockDatabaseUpdater{
		hasChanged: true,
		currentVersion: &vulndb.DatabaseStatus{
			Built:         time.Date(2026, 3, 17, 6, 0, 0, 0, time.UTC),
			SchemaVersion: "v6.1.4",
			Path:          "/test/path",
		},
	}

	// Setup: mock image database (no images need rescan)
	mockDB := &MockDatabase{
		imagesNeedingRescan: []database.ContainerImage{},
		instances:           map[string]*database.ContainerRow{},
	}

	// Setup: mock image scan queue
	mockQueue := &MockScanQueue{}

	// Create job WITHOUT calling SetNodeScanning
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)

	// Run job
	err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("Job failed: %v", err)
	}

	// Verify: job completes successfully without node scanning
	// (nodeDB and nodeScanQueue are nil, so RescanNodesOnDBUpdate is skipped)
}

// Test: Node database error doesn't fail the job (nodes are optional)
func TestRescanDatabaseJob_NodeDatabaseError(t *testing.T) {
	// Setup: mock database updater with a new grype DB version
	mockDBUpdater := &MockDatabaseUpdater{
		hasChanged: true,
		currentVersion: &vulndb.DatabaseStatus{
			Built:         time.Date(2026, 3, 17, 6, 0, 0, 0, time.UTC),
			SchemaVersion: "v6.1.4",
			Path:          "/test/path",
		},
	}

	// Setup: mock image database (no images need rescan)
	mockDB := &MockDatabase{
		imagesNeedingRescan: []database.ContainerImage{},
		instances:           map[string]*database.ContainerRow{},
	}

	// Setup: mock image scan queue
	mockQueue := &MockScanQueue{}

	// Setup: mock node database that returns an error
	mockNodeDB := &MockNodeDatabase{
		err: fmt.Errorf("node database error"),
	}

	// Setup: mock node scan queue
	mockNodeQueue := &MockNodeScanQueue{}

	// Create job and configure node scanning
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, mockQueue)
	job.SetNodeScanning(mockNodeDB, mockNodeQueue)

	// Run job - should succeed even though node DB fails
	err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("Job should not fail due to node database error: %v", err)
	}

	// Verify: no nodes were enqueued (due to error)
	if len(mockNodeQueue.enqueuedNodes) != 0 {
		t.Errorf("Expected 0 nodes enqueued on error, got %d", len(mockNodeQueue.enqueuedNodes))
	}
}

// Test: the job reaps stuck scans every cycle with the configured max age
func TestRescanDatabaseJob_ReapsStuckScans(t *testing.T) {
	mockDBUpdater := &MockDatabaseUpdater{
		hasChanged: true,
		currentVersion: &vulndb.DatabaseStatus{
			Built:         time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC),
			SchemaVersion: "v6.1.3",
			Path:          "/test/path",
		},
	}
	mockDB := &MockDatabase{}
	job := NewRescanDatabaseJob(mockDBUpdater, mockDB, &MockScanQueue{})

	if err := job.Run(context.Background()); err != nil {
		t.Fatalf("Job failed: %v", err)
	}

	if !mockDB.reapCalled {
		t.Error("expected ReapStuckScans to be called during the job cycle")
	}
	if mockDB.reapMaxAge != stuckScanMaxAge {
		t.Errorf("expected reaper maxAge %v, got %v", stuckScanMaxAge, mockDB.reapMaxAge)
	}
}
