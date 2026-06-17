package docker

import (
	"testing"

	"github.com/bvboe/b2s-go/scanner-core/containers"
)

// TestNewRefreshTrigger tests that NewRefreshTrigger creates a valid trigger
func TestNewRefreshTrigger(t *testing.T) {
	manager := containers.NewManager()
	trigger := NewRefreshTrigger(manager)

	if trigger == nil {
		t.Fatal("NewRefreshTrigger returned nil")
	}

	if trigger.manager != manager {
		t.Error("RefreshTrigger manager not set correctly")
	}
}

// TestRefreshTriggerImplementsInterface verifies RefreshTrigger implements containers.RefreshTrigger
func TestRefreshTriggerImplementsInterface(t *testing.T) {
	manager := containers.NewManager()
	trigger := NewRefreshTrigger(manager)

	// This will fail at compile time if RefreshTrigger doesn't implement the interface
	var _ containers.RefreshTrigger = trigger
}

// TestTriggerRefresh_NoDocker tests TriggerRefresh behavior when Docker is not available
func TestTriggerRefresh_NoDocker(t *testing.T) {
	if IsDockerAvailable() {
		t.Skip("Skipping test - Docker is available, this test is for non-Docker environments")
	}

	manager := containers.NewManager()
	trigger := NewRefreshTrigger(manager)

	err := trigger.TriggerRefresh()
	if err == nil {
		t.Error("Expected error when Docker is not available")
	}
}

// TestTriggerRefresh_WithDocker tests TriggerRefresh with a real Docker daemon
// This is an integration test that requires Docker to be running
func TestTriggerRefresh_WithDocker(t *testing.T) {
	if !IsDockerAvailable() {
		t.Skip("Skipping integration test - Docker not available")
	}

	manager := containers.NewManager()
	trigger := NewRefreshTrigger(manager)

	// Record initial container count
	initialCount := manager.GetContainerCount()

	// Trigger refresh
	err := trigger.TriggerRefresh()
	if err != nil {
		t.Fatalf("TriggerRefresh failed: %v", err)
	}

	// After refresh, container count should match running Docker containers
	// We can't predict the exact count, but the operation should succeed
	finalCount := manager.GetContainerCount()
	t.Logf("Container count: initial=%d, after refresh=%d", initialCount, finalCount)

	// Verify that a second refresh also succeeds (idempotency)
	err = trigger.TriggerRefresh()
	if err != nil {
		t.Fatalf("Second TriggerRefresh failed: %v", err)
	}

	// Count should remain stable
	secondCount := manager.GetContainerCount()
	if secondCount != finalCount {
		t.Logf("Container count changed between refreshes: %d -> %d (this may be normal if containers started/stopped)", finalCount, secondCount)
	}
}

// TestTriggerRefresh_Reconciliation tests that refresh properly reconciles containers
func TestTriggerRefresh_Reconciliation(t *testing.T) {
	if !IsDockerAvailable() {
		t.Skip("Skipping integration test - Docker not available")
	}

	manager := containers.NewManager()

	// Add a fake container that doesn't exist in Docker
	fakeContainer := containers.Container{
		ID: containers.ContainerID{
			Namespace: "fake-namespace",
			Pod:       "fake-pod",
			Name:      "fake-container-that-does-not-exist",
		},
		Image: containers.ImageID{
			Reference: "fake-image:latest",
			Digest:    "sha256:fake",
		},
		NodeName:         "fake-node",
		ContainerRuntime: "docker",
	}
	manager.AddContainer(fakeContainer)

	// Verify fake container was added
	if manager.GetContainerCount() == 0 {
		t.Fatal("Failed to add fake container")
	}

	// Trigger refresh - this should replace all containers with actual Docker containers
	trigger := NewRefreshTrigger(manager)
	err := trigger.TriggerRefresh()
	if err != nil {
		t.Fatalf("TriggerRefresh failed: %v", err)
	}

	// The fake container should be gone (replaced by actual containers)
	// We verify by checking that the specific fake container is no longer present
	allContainers := manager.GetAllContainers()
	for _, c := range allContainers {
		if c.ID.Name == "fake-container-that-does-not-exist" {
			t.Error("Fake container still present after refresh - reconciliation failed")
		}
	}

	t.Logf("Reconciliation successful: fake container removed, %d real containers found", manager.GetContainerCount())
}
