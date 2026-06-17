package database

import (
	"os"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	_ "github.com/bvboe/b2s-go/scanner-core/sqlitedriver"
)

func TestAddContainer(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_containers_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Test adding a new container
	container := containers.Container{
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

	isNew, err := db.AddContainer(container)
	if err != nil {
		t.Fatalf("Failed to add container: %v", err)
	}
	if !isNew {
		t.Error("Expected AddContainer to return true for new container")
	}

	// Verify the container was added
	allContainers, err := db.GetAllContainers()
	if err != nil {
		t.Fatalf("Failed to get all containers: %v", err)
	}

	containerRows, ok := allContainers.([]ContainerRow)
	if !ok {
		t.Fatalf("Expected []ContainerRow, got %T", allContainers)
	}

	if len(containerRows) != 1 {
		t.Errorf("Expected 1 container, got %d", len(containerRows))
	}

	if containerRows[0].Namespace != "default" || containerRows[0].Pod != "test-pod" {
		t.Errorf("Container has wrong values: %+v", containerRows[0])
	}
}

func TestAddContainerDuplicate(t *testing.T) {
	dbPath := "/tmp/test_containers_dup_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	container := containers.Container{
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

	// Add container first time
	isNew, err := db.AddContainer(container)
	if err != nil {
		t.Fatalf("Failed to add container: %v", err)
	}
	if !isNew {
		t.Error("Expected first add to return true")
	}

	// Add same container again (should not be considered new)
	isNew, err = db.AddContainer(container)
	if err != nil {
		t.Fatalf("Failed to add duplicate container: %v", err)
	}
	if isNew {
		t.Error("Expected duplicate add to return false")
	}
}

func TestAddContainerWithImageUpdate(t *testing.T) {
	dbPath := "/tmp/test_containers_update_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Add container with one image
	container := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "test-pod",
			Name: "nginx",
		},
		Image: containers.ImageID{
			Reference: "nginx:1.20",
			Digest:    "sha256:old123",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	isNew, err := db.AddContainer(container)
	if err != nil {
		t.Fatalf("Failed to add container: %v", err)
	}
	if !isNew {
		t.Error("Expected first add to return true")
	}

	// Update container with different image
	container.Image.Reference = "nginx:1.21"
	container.Image.Digest = "sha256:new456"

	isNew, err = db.AddContainer(container)
	if err != nil {
		t.Fatalf("Failed to update container: %v", err)
	}
	if !isNew {
		t.Error("Expected image update to return true")
	}

	// Verify the container was updated
	allContainers, err := db.GetAllContainers()
	if err != nil {
		t.Fatalf("Failed to get all containers: %v", err)
	}

	containerRows := allContainers.([]ContainerRow)
	if len(containerRows) != 1 {
		t.Errorf("Expected 1 container after update, got %d", len(containerRows))
	}

	if containerRows[0].Reference != "nginx:1.21" || containerRows[0].Digest != "sha256:new456" {
		t.Errorf("Container not updated correctly: reference=%s, digest=%s", containerRows[0].Reference, containerRows[0].Digest)
	}
}

func TestAddContainerValidation(t *testing.T) {
	dbPath := "/tmp/test_containers_validation_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	tests := []struct {
		name        string
		container    containers.Container
		expectError bool
	}{
		{
			name: "missing digest",
			container: containers.Container{
				ID: containers.ContainerID{
					Namespace: "default",
					Pod:       "test-pod",
					Name: "nginx",
				},
				Image: containers.ImageID{
					Reference: "nginx:1.21",
					Digest:    "", // Missing digest
				},
			},
			expectError: true,
		},
		{
			name: "missing reference",
			container: containers.Container{
				ID: containers.ContainerID{
					Namespace: "default",
					Pod:       "test-pod",
					Name: "nginx",
				},
				Image: containers.ImageID{
					Reference: "", // Missing reference
					Digest:    "sha256:abc123",
				},
			},
			expectError: true,
		},
		{
			name: "missing namespace",
			container: containers.Container{
				ID: containers.ContainerID{
					Namespace: "", // Missing namespace
					Pod:       "test-pod",
					Name: "nginx",
				},
				Image: containers.ImageID{
					Reference: "nginx:1.21",
					Digest:    "sha256:abc123",
				},
			},
			expectError: true,
		},
		{
			name: "valid container",
			container: containers.Container{
				ID: containers.ContainerID{
					Namespace: "default",
					Pod:       "test-pod",
					Name: "nginx",
				},
				Image: containers.ImageID{
					Reference: "nginx:1.21",
					Digest:    "sha256:abc123",
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := db.AddContainer(tt.container)
			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}
		})
	}
}

func TestRemoveContainer(t *testing.T) {
	dbPath := "/tmp/test_containers_remove_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Add container
	container := containers.Container{
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

	_, err = db.AddContainer(container)
	if err != nil {
		t.Fatalf("Failed to add container: %v", err)
	}

	// Remove container
	err = db.RemoveContainer(container.ID)
	if err != nil {
		t.Fatalf("Failed to remove container: %v", err)
	}

	// Verify it's gone
	allContainers, err := db.GetAllContainers()
	if err != nil {
		t.Fatalf("Failed to get all containers: %v", err)
	}

	containerRows := allContainers.([]ContainerRow)
	if len(containerRows) != 0 {
		t.Errorf("Expected 0 containers after removal, got %d", len(containerRows))
	}
}

func TestSetContainers(t *testing.T) {
	dbPath := "/tmp/test_containers_set_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Add some initial containers
	container1 := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "old-pod",
			Name: "nginx",
		},
		Image: containers.ImageID{
			Reference: "nginx:1.20",
			Digest:    "sha256:old123",
		},
		NodeName:         "worker-1",
		ContainerRuntime: "containerd",
	}

	_, err = db.AddContainer(container1)
	if err != nil {
		t.Fatalf("Failed to add initial container: %v", err)
	}

	// Set new containers (should replace old ones)
	newContainers := []containers.Container{
		{
			ID: containers.ContainerID{
				Namespace: "default",
				Pod:       "new-pod-1",
				Name: "nginx",
			},
			Image: containers.ImageID{
				Reference: "nginx:1.21",
				Digest:    "sha256:new123",
			},
			NodeName:         "worker-2",
			ContainerRuntime: "docker",
		},
		{
			ID: containers.ContainerID{
				Namespace: "kube-system",
				Pod:       "new-pod-2",
				Name: "envoy",
			},
			Image: containers.ImageID{
				Reference: "envoy:v1.20",
				Digest:    "sha256:envoy456",
			},
			NodeName:         "worker-2",
			ContainerRuntime: "containerd",
		},
	}

	stats, err := db.SetContainers(newContainers)
	if err != nil {
		t.Fatalf("Failed to set containers: %v", err)
	}
	if stats == nil {
		t.Fatal("Expected stats, got nil")
	}

	// Verify new containers
	allContainers, err := db.GetAllContainers()
	if err != nil {
		t.Fatalf("Failed to get all containers: %v", err)
	}

	containerRows := allContainers.([]ContainerRow)
	if len(containerRows) != 2 {
		t.Errorf("Expected 2 containers after SetContainers, got %d", len(containerRows))
	}

	// Verify old container is gone and new containers exist
	foundNewPod1 := false
	foundNewPod2 := false
	foundOldPod := false

	for _, row := range containerRows {
		if row.Pod == "old-pod" {
			foundOldPod = true
		}
		if row.Pod == "new-pod-1" {
			foundNewPod1 = true
		}
		if row.Pod == "new-pod-2" {
			foundNewPod2 = true
		}
	}

	if foundOldPod {
		t.Error("Old container still exists after SetContainers")
	}
	if !foundNewPod1 || !foundNewPod2 {
		t.Error("New containers not found after SetContainers")
	}
}

func TestSetContainersValidation(t *testing.T) {
	dbPath := "/tmp/test_containers_set_validation_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Try to set containers with one invalid container
	containers := []containers.Container{
		{
			ID: containers.ContainerID{
				Namespace: "default",
				Pod:       "valid-pod",
				Name: "nginx",
			},
			Image: containers.ImageID{
				Reference: "nginx:1.21",
				Digest:    "sha256:valid123",
			},
		},
		{
			ID: containers.ContainerID{
				Namespace: "default",
				Pod:       "invalid-pod",
				Name: "nginx",
			},
			Image: containers.ImageID{
				Reference: "nginx:1.21",
				Digest:    "", // Missing digest
			},
		},
	}

	_, err = db.SetContainers(containers)
	if err == nil {
		t.Error("Expected error when setting containers with invalid data")
	}

	// Verify no containers were added (transaction should have rolled back)
	allContainers, err := db.GetAllContainers()
	if err != nil {
		t.Fatalf("Failed to get all containers: %v", err)
	}

	containerRows := allContainers.([]ContainerRow)
	if len(containerRows) != 0 {
		t.Errorf("Expected 0 containers after failed SetContainers, got %d", len(containerRows))
	}
}
