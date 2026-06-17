package containers

import (
	"testing"
)

func TestNewManager(t *testing.T) {
	m := NewManager()
	if m == nil {
		t.Fatal("NewManager returned nil")
	}
	if m.GetContainerCount() != 0 {
		t.Errorf("Expected 0 containers, got %d", m.GetContainerCount())
	}
}

func TestAddContainer(t *testing.T) {
	m := NewManager()

	c := Container{
		ID: ContainerID{
			Namespace: "default",
			Pod:       "test-pod-123",
			Name:      "app",
		},
		Image: ImageID{
			Reference: "nginx:1.21",
			Digest:    "sha256:abc123",
		},
	}

	m.AddContainer(c)

	if m.GetContainerCount() != 1 {
		t.Errorf("Expected 1 container, got %d", m.GetContainerCount())
	}

	retrieved, exists := m.GetContainer("default", "test-pod-123", "app")
	if !exists {
		t.Fatal("Container not found after adding")
	}

	if retrieved.Image.Reference != "nginx:1.21" {
		t.Errorf("Retrieved container has wrong values: %+v", retrieved)
	}
}

func TestAddMultipleContainers(t *testing.T) {
	m := NewManager()

	containers := []Container{
		{
			ID: ContainerID{
				Namespace: "default",
				Pod:       "pod-1",
				Name: "app",
			},
			Image: ImageID{
				Reference: "nginx:1.21",
				Digest:    "sha256:abc123",
			},
		},
		{
			ID: ContainerID{
				Namespace: "kube-system",
				Pod:       "pod-2",
				Name:      "proxy",
			},
			Image: ImageID{
				Reference: "envoy:v1.20",
				Digest:    "sha256:def456",
			},
		},
		{
			ID: ContainerID{
				Namespace: "default",
				Pod:       "pod-3",
				Name:      "sidecar",
			},
			Image: ImageID{
				Reference: "busybox:latest",
				Digest:    "sha256:ghi789",
			},
		},
	}

	for _, c := range containers {
		m.AddContainer(c)
	}

	if m.GetContainerCount() != 3 {
		t.Errorf("Expected 3 containers, got %d", m.GetContainerCount())
	}
}

func TestRemoveContainer(t *testing.T) {
	m := NewManager()

	c := Container{
		ID: ContainerID{
			Namespace: "default",
			Pod:       "test-pod",
			Name: "app",
		},
	}

	m.AddContainer(c)
	if m.GetContainerCount() != 1 {
		t.Fatalf("Expected 1 container after add, got %d", m.GetContainerCount())
	}

	m.RemoveContainer(c.ID)
	if m.GetContainerCount() != 0 {
		t.Errorf("Expected 0 containers after remove, got %d", m.GetContainerCount())
	}

	_, exists := m.GetContainer("default", "test-pod", "app")
	if exists {
		t.Error("Container still exists after removal")
	}
}

func TestSetContainers(t *testing.T) {
	m := NewManager()

	// Add some initial containers
	m.AddContainer(Container{
		ID: ContainerID{
			Namespace: "default",
			Pod:       "old-pod",
			Name: "old-container",
		},
	})

	if m.GetContainerCount() != 1 {
		t.Fatalf("Expected 1 container initially, got %d", m.GetContainerCount())
	}

	// Set new containers (should replace old ones)
	newContainers := []Container{
		{
			ID: ContainerID{
				Namespace: "default",
				Pod:       "new-pod-1",
				Name: "app",
			},
			Image: ImageID{
				Reference: "nginx:1.21",
				Digest:    "sha256:abc123",
			},
		},
		{
			ID: ContainerID{
				Namespace: "kube-system",
				Pod:       "new-pod-2",
				Name: "proxy",
			},
			Image: ImageID{
				Reference: "envoy:v1.20",
				Digest:    "sha256:def456",
			},
		},
	}

	m.SetContainers(newContainers)

	if m.GetContainerCount() != 2 {
		t.Errorf("Expected 2 containers after set, got %d", m.GetContainerCount())
	}

	// Old container should be gone
	_, exists := m.GetContainer("default", "old-pod", "old-container")
	if exists {
		t.Error("Old container still exists after SetContainers")
	}

	// New containers should exist
	_, exists = m.GetContainer("default", "new-pod-1", "app")
	if !exists {
		t.Error("New container 1 not found")
	}

	_, exists = m.GetContainer("kube-system", "new-pod-2", "proxy")
	if !exists {
		t.Error("New container 2 not found")
	}
}

func TestSetContainersEmpty(t *testing.T) {
	m := NewManager()

	// Add some containers
	m.AddContainer(Container{
		ID: ContainerID{
			Namespace: "default",
			Pod:       "pod-1",
			Name: "app",
		},
	})
	m.AddContainer(Container{
		ID: ContainerID{
			Namespace: "default",
			Pod:       "pod-2",
			Name: "app",
		},
	})

	if m.GetContainerCount() != 2 {
		t.Fatalf("Expected 2 containers, got %d", m.GetContainerCount())
	}

	// Set empty collection (should clear all)
	m.SetContainers([]Container{})

	if m.GetContainerCount() != 0 {
		t.Errorf("Expected 0 containers after setting empty collection, got %d", m.GetContainerCount())
	}
}

func TestGetAllContainers(t *testing.T) {
	m := NewManager()

	containers := []Container{
		{
			ID: ContainerID{
				Namespace: "default",
				Pod:       "pod-1",
				Name: "app",
			},
		},
		{
			ID: ContainerID{
				Namespace: "default",
				Pod:       "pod-2",
				Name: "app",
			},
		},
	}

	for _, c := range containers {
		m.AddContainer(c)
	}

	all := m.GetAllContainers()
	if len(all) != 2 {
		t.Errorf("Expected 2 containers from GetAllContainers, got %d", len(all))
	}
}

func TestConcurrency(t *testing.T) {
	m := NewManager()

	// Test concurrent adds
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			c := Container{
				ID: ContainerID{
					Namespace: "default",
					Pod:       "concurrent-pod",
					Name: string(rune('a' + id)),
				},
			}
			m.AddContainer(c)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	if m.GetContainerCount() != 10 {
		t.Errorf("Expected 10 containers after concurrent adds, got %d", m.GetContainerCount())
	}
}

func TestUpdateExistingContainer(t *testing.T) {
	m := NewManager()

	// Add initial container
	c := Container{
		ID: ContainerID{
			Namespace: "default",
			Pod:       "test-pod",
			Name: "app",
		},
		Image: ImageID{
			Reference: "nginx:1.20",
			Digest:    "sha256:old123",
		},
	}
	m.AddContainer(c)

	// Update with new tag and image ID
	updated := Container{
		ID: ContainerID{
			Namespace: "default",
			Pod:       "test-pod",
			Name: "app",
		},
		Image: ImageID{
			Reference: "nginx:1.21",
			Digest:    "sha256:new456",
		},
	}
	m.AddContainer(updated)

	// Should still have only 1 container (updated)
	if m.GetContainerCount() != 1 {
		t.Errorf("Expected 1 container, got %d", m.GetContainerCount())
	}

	retrieved, _ := m.GetContainer("default", "test-pod", "app")
	if retrieved.Image.Reference != "nginx:1.21" || retrieved.Image.Digest != "sha256:new456" {
		t.Errorf("Container not updated correctly: %+v", retrieved)
	}
}
