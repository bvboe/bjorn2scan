package integration_test

import (
	"os"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	_ "github.com/bvboe/b2s-go/scanner-core/sqlitedriver"
)

// MockScanQueue implements ScanQueueInterface for testing
type MockScanQueue struct {
	enqueuedScans      []EnqueuedScan
	enqueuedForceScans []EnqueuedScan
}

type EnqueuedScan struct {
	Image            containers.ImageID
	NodeName         string
	ContainerRuntime string
}

func (m *MockScanQueue) EnqueueScan(image containers.ImageID, nodeName string, containerRuntime string) {
	m.enqueuedScans = append(m.enqueuedScans, EnqueuedScan{
		Image:            image,
		NodeName:         nodeName,
		ContainerRuntime: containerRuntime,
	})
}

func (m *MockScanQueue) EnqueueForceScan(image containers.ImageID, nodeName string, containerRuntime string) {
	m.enqueuedForceScans = append(m.enqueuedForceScans, EnqueuedScan{
		Image:            image,
		NodeName:         nodeName,
		ContainerRuntime: containerRuntime,
	})
}

func TestManagerWithDatabase(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_db_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager and set database
	manager := containers.NewManager()
	manager.SetDatabase(db)

	// Add container
	c := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "test-pod",
			Name: "nginx",
		},
		Image: containers.ImageID{
			Reference: "nginx:1.21",
			Digest:    "sha256:abc123",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	manager.AddContainer(c)

	// Verify container is in manager
	if manager.GetContainerCount() != 1 {
		t.Errorf("Expected 1 container in manager, got %d", manager.GetContainerCount())
	}

	// Verify container is in database
	allContainers, err := db.GetAllContainers()
	if err != nil {
		t.Fatalf("Failed to get containers from database: %v", err)
	}

	containerRows := allContainers.([]database.ContainerRow)
	if len(containerRows) != 1 {
		t.Errorf("Expected 1 container in database, got %d", len(containerRows))
	}

	if containerRows[0].Namespace != "default" || containerRows[0].Pod != "test-pod" {
		t.Errorf("Container in database has wrong values: %+v", containerRows[0])
	}
}

func TestManagerWithScanQueue(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_queue_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database and scan queue
	manager := containers.NewManager()
	manager.SetDatabase(db)

	mockQueue := &MockScanQueue{
		enqueuedScans: []EnqueuedScan{},
	}
	manager.SetScanQueue(mockQueue)

	// Add container with new image
	c := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "test-pod",
			Name: "nginx",
		},
		Image: containers.ImageID{
			Reference: "nginx:1.21",
			Digest:    "sha256:abc123",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	manager.AddContainer(c)

	// Give it a moment to process
	time.Sleep(100 * time.Millisecond)

	// Verify scan was enqueued
	if len(mockQueue.enqueuedScans) != 1 {
		t.Fatalf("Expected 1 scan to be enqueued, got %d", len(mockQueue.enqueuedScans))
	}

	enqueuedScan := mockQueue.enqueuedScans[0]
	if enqueuedScan.Image.Digest != "sha256:abc123" {
		t.Errorf("Expected digest sha256:abc123, got %s", enqueuedScan.Image.Digest)
	}
	if enqueuedScan.NodeName != "worker-1" {
		t.Errorf("Expected node worker-1, got %s", enqueuedScan.NodeName)
	}
	if enqueuedScan.ContainerRuntime != "containerd" {
		t.Errorf("Expected runtime containerd, got %s", enqueuedScan.ContainerRuntime)
	}
}

func TestManagerDoesNotEnqueueDuplicateScans(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_no_dup_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database and scan queue
	manager := containers.NewManager()
	manager.SetDatabase(db)

	mockQueue := &MockScanQueue{
		enqueuedScans: []EnqueuedScan{},
	}
	manager.SetScanQueue(mockQueue)

	// Add first container
	c1 := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "test-pod-1",
			Name: "nginx",
		},
		Image: containers.ImageID{
			Reference: "nginx:1.21",
			Digest:    "sha256:same",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	manager.AddContainer(c1)
	time.Sleep(100 * time.Millisecond)

	if len(mockQueue.enqueuedScans) != 1 {
		t.Fatalf("Expected 1 scan after first container, got %d", len(mockQueue.enqueuedScans))
	}

	// Mark the scan as completed
	sbomJSON := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`)
	err = db.StoreSBOM("sha256:same", sbomJSON)
	if err != nil {
		t.Fatalf("Failed to store SBOM: %v", err)
	}

	// Add second container with same image (should not trigger new scan)
	c2 := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "test-pod-2",
			Name: "nginx",
		},
		Image: containers.ImageID{
			Reference: "nginx:1.21",
			Digest:    "sha256:same",
		},
		NodeName:         "worker-2",
		ContainerRuntime: "docker",
	}

	manager.AddContainer(c2)
	time.Sleep(100 * time.Millisecond)

	// Should still be only 1 enqueued scan
	if len(mockQueue.enqueuedScans) != 1 {
		t.Errorf("Expected 1 scan total (no duplicate), got %d", len(mockQueue.enqueuedScans))
	}
}

func TestManagerSetContainersEnqueuesMultipleScans(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_set_multi_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database and scan queue
	manager := containers.NewManager()
	manager.SetDatabase(db)

	mockQueue := &MockScanQueue{
		enqueuedScans: []EnqueuedScan{},
	}
	manager.SetScanQueue(mockQueue)

	// Set multiple containers with different images
	containers := []containers.Container{
		{
			ID: containers.ContainerID{
				Namespace: "default",
				Pod:       "pod-1",
				Name: "nginx",
			},
			Image: containers.ImageID{
				Reference: "nginx:1.21",
				Digest:    "sha256:image1",
			},
			NodeName:         "worker-1",
			ContainerRuntime: "containerd",
		},
		{
			ID: containers.ContainerID{
				Namespace: "default",
				Pod:       "pod-2",
				Name: "envoy",
			},
			Image: containers.ImageID{
				Reference: "envoy:v1.20",
				Digest:    "sha256:image2",
			},
			NodeName:         "worker-2",
			ContainerRuntime: "docker",
		},
		{
			ID: containers.ContainerID{
				Namespace: "kube-system",
				Pod:       "pod-3",
				Name: "coredns",
			},
			Image: containers.ImageID{
				Reference: "coredns:v1.9",
				Digest:    "sha256:image3",
			},
			NodeName:         "worker-3",
			ContainerRuntime: "containerd",
		},
	}

	manager.SetContainers(containers)
	time.Sleep(100 * time.Millisecond)

	// Should have enqueued 3 scans
	if len(mockQueue.enqueuedScans) != 3 {
		t.Errorf("Expected 3 scans to be enqueued, got %d", len(mockQueue.enqueuedScans))
	}

	// Verify all unique digests were enqueued
	digests := make(map[string]bool)
	for _, scan := range mockQueue.enqueuedScans {
		digests[scan.Image.Digest] = true
	}

	if len(digests) != 3 {
		t.Errorf("Expected 3 unique digests, got %d", len(digests))
	}
}

func TestManagerSetContainersDeduplicatesScans(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_set_dedup_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database and scan queue
	manager := containers.NewManager()
	manager.SetDatabase(db)

	mockQueue := &MockScanQueue{
		enqueuedScans: []EnqueuedScan{},
	}
	manager.SetScanQueue(mockQueue)

	// Set multiple containers with same image (should only enqueue once)
	containers := []containers.Container{
		{
			ID: containers.ContainerID{
				Namespace: "default",
				Pod:       "pod-1",
				Name: "nginx",
			},
			Image: containers.ImageID{
				Reference: "nginx:1.21",
				Digest:    "sha256:shared",
			},
			NodeName:         "worker-1",
			ContainerRuntime: "containerd",
		},
		{
			ID: containers.ContainerID{
				Namespace: "default",
				Pod:       "pod-2",
				Name: "nginx",
			},
			Image: containers.ImageID{
				Reference: "nginx:1.21",
				Digest:    "sha256:shared",
			},
			NodeName:         "worker-2",
			ContainerRuntime: "docker",
		},
		{
			ID: containers.ContainerID{
				Namespace: "kube-system",
				Pod:       "pod-3",
				Name: "nginx",
			},
			Image: containers.ImageID{
				Reference: "nginx:1.21",
				Digest:    "sha256:shared",
			},
			NodeName:         "worker-3",
			ContainerRuntime: "containerd",
		},
	}

	manager.SetContainers(containers)
	time.Sleep(100 * time.Millisecond)

	// Should only enqueue 1 scan (deduplicated)
	if len(mockQueue.enqueuedScans) != 1 {
		t.Errorf("Expected 1 scan (deduplicated), got %d", len(mockQueue.enqueuedScans))
	}

	if mockQueue.enqueuedScans[0].Image.Digest != "sha256:shared" {
		t.Errorf("Expected digest sha256:shared, got %s", mockQueue.enqueuedScans[0].Image.Digest)
	}
}

func TestManagerRemoveContainer(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_remove_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database
	manager := containers.NewManager()
	manager.SetDatabase(db)

	// Add container
	c := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "test-pod",
			Name: "nginx",
		},
		Image: containers.ImageID{
			Reference: "nginx:1.21",
			Digest:    "sha256:abc123",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	manager.AddContainer(c)

	// Verify container exists
	if manager.GetContainerCount() != 1 {
		t.Fatalf("Expected 1 container, got %d", manager.GetContainerCount())
	}

	// Remove container
	manager.RemoveContainer(c.ID)

	// Verify container is removed from manager
	if manager.GetContainerCount() != 0 {
		t.Errorf("Expected 0 containers in manager after removal, got %d", manager.GetContainerCount())
	}

	// Verify container is removed from database
	allContainers, err := db.GetAllContainers()
	if err != nil {
		t.Fatalf("Failed to get containers from database: %v", err)
	}

	containerRows := allContainers.([]database.ContainerRow)
	if len(containerRows) != 0 {
		t.Errorf("Expected 0 containers in database after removal, got %d", len(containerRows))
	}
}

func TestManagerWithoutDatabase(t *testing.T) {
	// Create manager without database
	manager := containers.NewManager()

	// Add container (should work without database)
	c := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "test-pod",
			Name: "nginx",
		},
		Image: containers.ImageID{
			Reference: "nginx:1.21",
			Digest:    "sha256:abc123",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	manager.AddContainer(c)

	// Verify container is in manager
	if manager.GetContainerCount() != 1 {
		t.Errorf("Expected 1 container in manager, got %d", manager.GetContainerCount())
	}

	// This should work fine without database
	retrieved, exists := manager.GetContainer("default", "test-pod", "nginx")
	if !exists {
		t.Error("Container not found in manager")
	}
	if retrieved.Image.Digest != "sha256:abc123" {
		t.Errorf("Retrieved container has wrong digest: %s", retrieved.Image.Digest)
	}
}

func TestManagerWithoutScanQueue(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_no_queue_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database but no scan queue
	manager := containers.NewManager()
	manager.SetDatabase(db)

	// Add container (should work without scan queue)
	c := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "test-pod",
			Name: "nginx",
		},
		Image: containers.ImageID{
			Reference: "nginx:1.21",
			Digest:    "sha256:abc123",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	manager.AddContainer(c)

	// Verify container is in manager
	if manager.GetContainerCount() != 1 {
		t.Errorf("Expected 1 container in manager, got %d", manager.GetContainerCount())
	}

	// Verify container is in database
	allContainers, err := db.GetAllContainers()
	if err != nil {
		t.Fatalf("Failed to get containers from database: %v", err)
	}

	containerRows := allContainers.([]database.ContainerRow)
	if len(containerRows) != 1 {
		t.Errorf("Expected 1 container in database, got %d", len(containerRows))
	}
}

func TestManagerRetryFailedScan(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_retry_failed_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database and scan queue
	manager := containers.NewManager()
	manager.SetDatabase(db)

	mockQueue := &MockScanQueue{
		enqueuedScans:      []EnqueuedScan{},
		enqueuedForceScans: []EnqueuedScan{},
	}
	manager.SetScanQueue(mockQueue)

	// Add first container (should enqueue normal scan)
	c := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "test-pod",
			Name: "nginx",
		},
		Image: containers.ImageID{
			Reference: "nginx:1.21",
			Digest:    "sha256:failed",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	manager.AddContainer(c)
	time.Sleep(100 * time.Millisecond)

	// Verify normal scan was enqueued
	if len(mockQueue.enqueuedScans) != 1 {
		t.Fatalf("Expected 1 normal scan, got %d", len(mockQueue.enqueuedScans))
	}

	// Mark the scan as failed
	err = db.UpdateScanStatus("sha256:failed", "failed", "test error")
	if err != nil {
		t.Fatalf("Failed to update scan status: %v", err)
	}

	// Add same container again (should enqueue force scan)
	manager.AddContainer(c)
	time.Sleep(100 * time.Millisecond)

	// Verify force scan was enqueued
	if len(mockQueue.enqueuedForceScans) != 1 {
		t.Errorf("Expected 1 force scan for failed image, got %d", len(mockQueue.enqueuedForceScans))
	}
	if mockQueue.enqueuedForceScans[0].Image.Digest != "sha256:failed" {
		t.Errorf("Expected digest sha256:failed, got %s", mockQueue.enqueuedForceScans[0].Image.Digest)
	}
}

func TestManagerRetryIncompleteData(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_retry_incomplete_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database and scan queue
	manager := containers.NewManager()
	manager.SetDatabase(db)

	mockQueue := &MockScanQueue{
		enqueuedScans:      []EnqueuedScan{},
		enqueuedForceScans: []EnqueuedScan{},
	}
	manager.SetScanQueue(mockQueue)

	// Add first container
	c := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "test-pod",
			Name: "nginx",
		},
		Image: containers.ImageID{
			Reference: "nginx:1.21",
			Digest:    "sha256:incomplete",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	manager.AddContainer(c)
	time.Sleep(100 * time.Millisecond)

	// Verify normal scan was enqueued
	if len(mockQueue.enqueuedScans) != 1 {
		t.Fatalf("Expected 1 normal scan, got %d", len(mockQueue.enqueuedScans))
	}

	// Store SBOM but mark as scanned (simulating incomplete data - missing vulnerabilities)
	sbomJSON := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`)
	err = db.StoreSBOM("sha256:incomplete", sbomJSON)
	if err != nil {
		t.Fatalf("Failed to store SBOM: %v", err)
	}

	// Verify data is incomplete
	isComplete, err := db.IsScanDataComplete("sha256:incomplete")
	if err != nil {
		t.Fatalf("Failed to check data completeness: %v", err)
	}
	if isComplete {
		t.Fatal("Expected data to be incomplete (missing vulnerabilities)")
	}

	// Add same container again (should enqueue force scan because data is incomplete)
	manager.AddContainer(c)
	time.Sleep(100 * time.Millisecond)

	// Verify force scan was enqueued
	if len(mockQueue.enqueuedForceScans) != 1 {
		t.Errorf("Expected 1 force scan for incomplete data, got %d", len(mockQueue.enqueuedForceScans))
	}
	if mockQueue.enqueuedForceScans[0].Image.Digest != "sha256:incomplete" {
		t.Errorf("Expected digest sha256:incomplete, got %s", mockQueue.enqueuedForceScans[0].Image.Digest)
	}
}

func TestManagerNoRetryForCompleteData(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_manager_no_retry_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Create manager with database and scan queue
	manager := containers.NewManager()
	manager.SetDatabase(db)

	mockQueue := &MockScanQueue{
		enqueuedScans:      []EnqueuedScan{},
		enqueuedForceScans: []EnqueuedScan{},
	}
	manager.SetScanQueue(mockQueue)

	// Add first container
	c := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "test-pod",
			Name: "nginx",
		},
		Image: containers.ImageID{
			Reference: "nginx:1.21",
			Digest:    "sha256:complete",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	manager.AddContainer(c)
	time.Sleep(100 * time.Millisecond)

	// Verify normal scan was enqueued
	if len(mockQueue.enqueuedScans) != 1 {
		t.Fatalf("Expected 1 normal scan, got %d", len(mockQueue.enqueuedScans))
	}

	// Store complete data (SBOM and vulnerabilities)
	sbomJSON := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`)
	err = db.StoreSBOM("sha256:complete", sbomJSON)
	if err != nil {
		t.Fatalf("Failed to store SBOM: %v", err)
	}

	vulnJSON := []byte(`{"vulnerabilities":[]}`)
	err = db.StoreVulnerabilities("sha256:complete", vulnJSON, time.Time{})
	if err != nil {
		t.Fatalf("Failed to store vulnerabilities: %v", err)
	}

	// Verify data is complete
	isComplete, err := db.IsScanDataComplete("sha256:complete")
	if err != nil {
		t.Fatalf("Failed to check data completeness: %v", err)
	}
	if !isComplete {
		t.Fatal("Expected data to be complete")
	}

	// Add same container again (should NOT enqueue any scan - data is complete)
	manager.AddContainer(c)
	time.Sleep(100 * time.Millisecond)

	// Verify no additional scans were enqueued
	if len(mockQueue.enqueuedScans) != 1 {
		t.Errorf("Expected still 1 normal scan (no retry), got %d", len(mockQueue.enqueuedScans))
	}
	if len(mockQueue.enqueuedForceScans) != 0 {
		t.Errorf("Expected 0 force scans for complete data, got %d", len(mockQueue.enqueuedForceScans))
	}
}
