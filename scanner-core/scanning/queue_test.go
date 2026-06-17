package scanning

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/grype"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
	// Note: SQLite driver is imported via Grype's dependencies
	// DO NOT import sqlitedriver here to avoid duplicate registration
)

// TestJobQueueIntegration tests the complete scanning workflow
func TestJobQueueIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode (requires Grype database download)")
	}

	// Create temporary database
	dbPath := "/tmp/test_queue_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Track which images were scanned
	scannedImages := make(map[string]bool)
	retrieverCalled := make(chan containers.ImageID, 10)

	// Mock SBOM retriever
	mockRetriever := func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error) {
		retrieverCalled <- image
		scannedImages[image.Digest] = true
		return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`), nil
	}

	// Create job queue (with default grype config for this test)
	queue := NewJobQueue(db, mockRetriever, grype.Config{}, QueueConfig{MaxDepth: 0})
	defer queue.Shutdown()

	// Create a test image
	testImage := containers.ImageID{
		Reference: "nginx:1.21",
		Digest:    "sha256:abc123",
	}

	// Create a container to initialize the image record in the database
	testContainer := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "test-pod",
			Name:      "nginx",
		},
		Image:            testImage,
		NodeName:         "test-node",
		ContainerRuntime: "containerd",
	}

	// Add the container to the database (this creates the image record with status='pending')
	_, err = db.AddContainer(testContainer)
	if err != nil {
		t.Fatalf("Failed to add container: %v", err)
	}

	// Enqueue a scan job
	job := ScanJob{
		Image:            testImage,
		NodeName:         "test-node",
		ContainerRuntime: "containerd",
		ForceScan:        false,
	}

	queue.Enqueue(job)

	// Wait for the job to be processed
	select {
	case scannedImage := <-retrieverCalled:
		if scannedImage.Digest != testImage.Digest {
			t.Errorf("Expected digest %s, got %s", testImage.Digest, scannedImage.Digest)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout waiting for SBOM retriever to be called")
	}

	// Give the worker time to update the database
	time.Sleep(100 * time.Millisecond)

	// Verify the SBOM was stored
	sbom, err := db.GetSBOM(testImage.Digest)
	if err != nil {
		t.Fatalf("Failed to get SBOM: %v", err)
	}
	if len(sbom) == 0 {
		t.Error("SBOM was not stored")
	}

	// Verify scan status
	status, err := db.GetImageScanStatus(testImage.Digest)
	if err != nil {
		t.Fatalf("Failed to get scan status: %v", err)
	}
	if status != "scanned" {
		t.Errorf("Expected status 'scanned', got '%s'", status)
	}
}

// TestJobQueueErrorHandling tests error scenarios
func TestJobQueueErrorHandling(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_queue_error_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Mock SBOM retriever that fails
	mockRetriever := func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error) {
		return nil, errors.New("scan failed: image not found")
	}

	// Create job queue (with default grype config for this test)
	queue := NewJobQueue(db, mockRetriever, grype.Config{}, QueueConfig{MaxDepth: 0})
	defer queue.Shutdown()

	// Create a test image
	testImage := containers.ImageID{
		Reference: "nginx:1.21",
		Digest:    "sha256:def456",
	}

	// Create a container to initialize the image record
	testContainer := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "test-pod",
			Name:      "nginx",
		},
		Image:            testImage,
		NodeName:         "test-node",
		ContainerRuntime: "containerd",
	}

	// Add the container to the database
	_, err = db.AddContainer(testContainer)
	if err != nil {
		t.Fatalf("Failed to add container: %v", err)
	}

	// Enqueue a scan job
	job := ScanJob{
		Image:            testImage,
		NodeName:         "test-node",
		ContainerRuntime: "containerd",
		ForceScan:        false,
	}

	queue.Enqueue(job)

	// Wait for the job to be processed
	time.Sleep(1 * time.Second)

	// Verify scan status is 'failed'
	status, err := db.GetImageScanStatus(testImage.Digest)
	if err != nil {
		t.Fatalf("Failed to get scan status: %v", err)
	}
	if status != "failed" {
		t.Errorf("Expected status 'failed', got '%s'", status)
	}

	// Verify SBOM is not available (GetSBOM should return an error)
	sbom, err := db.GetSBOM(testImage.Digest)
	if err == nil {
		t.Error("Expected error when retrieving SBOM for failed scan")
	}
	if sbom != nil {
		t.Error("SBOM should be nil for failed scan")
	}
}

// TestJobQueueSkipAlreadyScanned tests that already-scanned images are skipped
func TestJobQueueSkipAlreadyScanned(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode (requires Grype database download)")
	}

	// Create temporary database
	dbPath := "/tmp/test_queue_skip_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	var retrieverCallCount atomic.Int32

	// Mock SBOM retriever
	mockRetriever := func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error) {
		retrieverCallCount.Add(1)
		return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`), nil
	}

	// Create job queue (with default grype config for this test)
	queue := NewJobQueue(db, mockRetriever, grype.Config{}, QueueConfig{MaxDepth: 0})
	defer queue.Shutdown()

	// Create a test image
	testImage := containers.ImageID{
		Reference: "nginx:1.21",
		Digest:    "sha256:ghi789",
	}

	// Create a container to initialize the image record
	testContainer := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "test-pod",
			Name:      "nginx",
		},
		Image:            testImage,
		NodeName:         "test-node",
		ContainerRuntime: "containerd",
	}

	// Add the container to the database
	_, err = db.AddContainer(testContainer)
	if err != nil {
		t.Fatalf("Failed to add container: %v", err)
	}

	// First scan
	job := ScanJob{
		Image:            testImage,
		NodeName:         "test-node",
		ContainerRuntime: "containerd",
		ForceScan:        false,
	}
	queue.Enqueue(job)

	// Wait for first scan to complete
	time.Sleep(1 * time.Second)

	if retrieverCallCount.Load() != 1 {
		t.Errorf("Expected retriever to be called once, got %d", retrieverCallCount.Load())
	}

	// Second scan of the same image (should be skipped)
	queue.Enqueue(job)

	// Wait to see if second scan happens
	time.Sleep(1 * time.Second)

	if retrieverCallCount.Load() != 1 {
		t.Errorf("Expected retriever to still be called once, got %d", retrieverCallCount.Load())
	}
}

// TestJobQueueForceScan tests that ForceScan re-runs vulnerability scan using cached SBOM
func TestJobQueueForceScan(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode (requires Grype database download)")
	}

	// Create temporary database
	dbPath := "/tmp/test_queue_force_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	var retrieverCallCount atomic.Int32

	// Mock SBOM retriever
	mockRetriever := func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error) {
		retrieverCallCount.Add(1)
		return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`), nil
	}

	// Create job queue (with default grype config for this test)
	queue := NewJobQueue(db, mockRetriever, grype.Config{}, QueueConfig{MaxDepth: 0})
	defer queue.Shutdown()

	// Create a test image
	testImage := containers.ImageID{
		Reference: "nginx:1.21",
		Digest:    "sha256:jkl012",
	}

	// Create a container to initialize the image record
	testContainer := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "test-pod",
			Name:      "nginx",
		},
		Image:            testImage,
		NodeName:         "test-node",
		ContainerRuntime: "containerd",
	}

	// Add the container to the database
	_, err = db.AddContainer(testContainer)
	if err != nil {
		t.Fatalf("Failed to add container: %v", err)
	}

	// First scan
	job := ScanJob{
		Image:            testImage,
		NodeName:         "test-node",
		ContainerRuntime: "containerd",
		ForceScan:        false,
	}
	queue.Enqueue(job)

	// Wait for first scan to complete
	time.Sleep(1 * time.Second)

	if retrieverCallCount.Load() != 1 {
		t.Errorf("Expected retriever to be called once, got %d", retrieverCallCount.Load())
	}

	// Force rescan of the same image - should use cached SBOM, NOT call retriever again
	job.ForceScan = true
	queue.Enqueue(job)

	// Wait for rescan to complete
	time.Sleep(1 * time.Second)

	// ForceScan with existing SBOM should NOT call retriever again - it uses cached SBOM
	// and just re-runs the vulnerability scan
	if retrieverCallCount.Load() != 1 {
		t.Errorf("Expected retriever to still be called once (ForceScan uses cached SBOM), got %d", retrieverCallCount.Load())
	}

	// Verify the image was rescanned by checking status is still completed
	status, err := db.GetImageStatus(testImage.Digest)
	if err != nil {
		t.Fatalf("Failed to get image status: %v", err)
	}
	if !status.HasVulnerabilities() {
		t.Errorf("Expected image to have vulnerability scan results after force scan")
	}
}

// TestJobQueueMaxDepthDrop tests that jobs are dropped when queue is full with QueueFullDrop behavior
func TestJobQueueMaxDepthDrop(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping queue test in short mode (requires Grype database download)")
	}

	// Create temporary database
	dbPath := "/tmp/test_queue_maxdepth_drop_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	var enqueueCount atomic.Int32

	// Mock SBOM retriever that counts calls
	mockRetriever := func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error) {
		enqueueCount.Add(1)
		// Slow down processing to fill the queue
		time.Sleep(100 * time.Millisecond)
		return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`), nil
	}

	// Create job queue with max depth of 2 and drop behavior
	config := QueueConfig{
		MaxDepth:     2,
		FullBehavior: QueueFullDrop,
	}
	queue := NewJobQueue(db, mockRetriever, grype.Config{}, config)
	defer queue.Shutdown()

	// Create test images
	for i := 1; i <= 5; i++ {
		image := containers.ImageID{
			Reference: "nginx:1.21",
			Digest:    "sha256:test" + string(rune('0'+i)),
		}

		container := containers.Container{
			ID: containers.ContainerID{
				Namespace: "default",
				Pod:       "test-pod-" + string(rune('a'+i-1)),
				Name:      "nginx",
			},
			Image:            image,
			NodeName:         "test-node",
			ContainerRuntime: "containerd",
		}

		// Add instance to DB first
		_, err := db.AddContainer(container)
		if err != nil {
			t.Fatalf("Failed to add container: %v", err)
		}

		// Enqueue scan job
		queue.Enqueue(ScanJob{
			Image:            image,
			NodeName:         "test-node",
			ContainerRuntime: "containerd",
		})
	}

	// Wait for processing
	time.Sleep(1 * time.Second)

	// Check metrics
	currentDepth, peakDepth, totalEnqueued, totalDropped, totalProcessed := queue.GetMetrics()

	t.Logf("Metrics: currentDepth=%d, peakDepth=%d, enqueued=%d, dropped=%d, processed=%d",
		currentDepth, peakDepth, totalEnqueued, totalDropped, totalProcessed)

	// Should have dropped some jobs
	if totalDropped == 0 {
		t.Error("Expected some jobs to be dropped, got 0")
	}

	// Total enqueued should be less than 5 (some were dropped)
	if totalEnqueued >= 5 {
		t.Errorf("Expected fewer than 5 jobs enqueued (some dropped), got %d", totalEnqueued)
	}

	// Peak depth should not exceed max depth
	if peakDepth > 2 {
		t.Errorf("Peak depth %d exceeded max depth 2", peakDepth)
	}
}

// TestJobQueueMaxDepthDropOldest tests that oldest jobs are evicted when queue is full
func TestJobQueueMaxDepthDropOldest(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping queue test in short mode (requires Grype database download)")
	}

	// Create temporary database
	dbPath := "/tmp/test_queue_drop_oldest_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	var processedJobs []string
	var mu sync.Mutex

	// Mock SBOM retriever that tracks which jobs were processed
	mockRetriever := func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error) {
		mu.Lock()
		processedJobs = append(processedJobs, image.Digest)
		mu.Unlock()
		time.Sleep(200 * time.Millisecond) // Slow processing
		return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`), nil
	}

	// Create job queue with max depth of 2 and drop oldest behavior
	config := QueueConfig{
		MaxDepth:     2,
		FullBehavior: QueueFullDropOldest,
	}
	queue := NewJobQueue(db, mockRetriever, grype.Config{}, config)
	defer queue.Shutdown()

	// Enqueue 4 jobs quickly
	for i := 1; i <= 4; i++ {
		image := containers.ImageID{
			Reference: "nginx:1.21",
			Digest:    "sha256:job" + string(rune('0'+i)),
		}

		container := containers.Container{
			ID: containers.ContainerID{
				Namespace: "default",
				Pod:       "test-pod-" + string(rune('a'+i-1)),
				Name:      "nginx",
			},
			Image:            image,
			NodeName:         "test-node",
			ContainerRuntime: "containerd",
		}

		_, err := db.AddContainer(container)
		if err != nil {
			t.Fatalf("Failed to add container: %v", err)
		}

		queue.Enqueue(ScanJob{
			Image:            image,
			NodeName:         "test-node",
			ContainerRuntime: "containerd",
		})
		time.Sleep(10 * time.Millisecond) // Small delay between enqueues
	}

	// Wait for processing
	time.Sleep(2 * time.Second)

	// Check metrics
	_, _, totalEnqueued, totalDropped, _ := queue.GetMetrics()

	t.Logf("Enqueued: %d, Dropped: %d", totalEnqueued, totalDropped)

	// Should have dropped some jobs (oldest ones)
	if totalDropped == 0 {
		t.Error("Expected some jobs to be dropped (oldest), got 0")
	}
}

// TestJobQueueMetricsTracking tests that metrics are correctly tracked
func TestJobQueueMetricsTracking(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping queue test in short mode (requires Grype database download)")
	}

	// Create temporary database
	dbPath := "/tmp/test_queue_metrics_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Mock SBOM retriever
	mockRetriever := func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error) {
		return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`), nil
	}

	// Create job queue with unbounded config
	config := QueueConfig{MaxDepth: 0}
	queue := NewJobQueue(db, mockRetriever, grype.Config{}, config)
	defer queue.Shutdown()

	// Enqueue 3 jobs
	for i := 1; i <= 3; i++ {
		image := containers.ImageID{
			Reference: "nginx:1.21",
			Digest:    "sha256:metric" + string(rune('0'+i)),
		}

		container := containers.Container{
			ID: containers.ContainerID{
				Namespace: "default",
				Pod:       "test-pod-" + string(rune('a'+i-1)),
				Name:      "nginx",
			},
			Image:            image,
			NodeName:         "test-node",
			ContainerRuntime: "containerd",
		}

		_, err := db.AddContainer(container)
		if err != nil {
			t.Fatalf("Failed to add container: %v", err)
		}

		queue.Enqueue(ScanJob{
			Image:            image,
			NodeName:         "test-node",
			ContainerRuntime: "containerd",
		})
	}

	// Wait for processing
	time.Sleep(1 * time.Second)

	// Check metrics
	_, peakDepth, totalEnqueued, totalDropped, totalProcessed := queue.GetMetrics()

	t.Logf("Metrics: peakDepth=%d, enqueued=%d, dropped=%d, processed=%d",
		peakDepth, totalEnqueued, totalDropped, totalProcessed)

	if totalEnqueued != 3 {
		t.Errorf("Expected 3 jobs enqueued, got %d", totalEnqueued)
	}

	if totalDropped != 0 {
		t.Errorf("Expected 0 jobs dropped (unbounded queue), got %d", totalDropped)
	}

	if peakDepth < 1 {
		t.Errorf("Expected peak depth >= 1, got %d", peakDepth)
	}

	if totalProcessed == 0 {
		t.Error("Expected at least some jobs to be processed")
	}
}

// mockDBReadinessChecker implements DBReadinessChecker for testing
type mockDBReadinessChecker struct {
	ready bool
}

func (m *mockDBReadinessChecker) WaitForReady(ctx context.Context) bool {
	return m.ready
}

// TestHostVulnScanCancelled tests that node status is set to failed when
// context is cancelled while waiting for the grype database
func TestHostVulnScanCancelled(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_queue_host_cancel_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = database.Close(db) }()

	// Mock SBOM retriever (not used in this test since we're testing the vuln scan path)
	mockRetriever := func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error) {
		return []byte(`{"bomFormat":"CycloneDX","specVersion":"1.4","version":1}`), nil
	}

	// Mock host SBOM retriever that returns valid SBOM
	mockHostRetriever := func(ctx context.Context, nodeName string) ([]byte, error) {
		return []byte(`{
			"bomFormat": "CycloneDX",
			"specVersion": "1.4",
			"version": 1,
			"components": [
				{"type": "library", "name": "openssl", "version": "1.1.1"}
			]
		}`), nil
	}

	// Create job queue
	queue := NewJobQueue(db, mockRetriever, grype.Config{}, QueueConfig{MaxDepth: 0})
	queue.SetHostSBOMRetriever(mockHostRetriever)

	// Set up a mock DB readiness checker that returns false (simulates cancelled context)
	mockChecker := &mockDBReadinessChecker{ready: false}
	queue.SetDBReadinessChecker(mockChecker)

	defer queue.Shutdown()

	// Add a test node
	testNode := nodes.Node{
		Name:         "test-node-1",
		Hostname:     "test-node-1.local",
		OSRelease:    "Ubuntu 22.04",
		Architecture: "amd64",
	}
	_, err = db.AddNode(testNode)
	if err != nil {
		t.Fatalf("Failed to add node: %v", err)
	}

	// Enqueue a host scan job
	queue.EnqueueHostScan(testNode.Name)

	// Wait for the job to be processed
	time.Sleep(1 * time.Second)

	// Verify node status is 'vuln_scan_failed', not stuck at 'scanning_vulnerabilities'
	node, err := db.GetNode(testNode.Name)
	if err != nil {
		t.Fatalf("Failed to get node: %v", err)
	}

	if node.Status != "vuln_scan_failed" {
		t.Errorf("Expected node status 'vuln_scan_failed', got '%s'", node.Status)
	}

	if node.StatusError != "cancelled while waiting for vulnerability database" {
		t.Errorf("Expected status error 'cancelled while waiting for vulnerability database', got '%s'", node.StatusError)
	}
}
