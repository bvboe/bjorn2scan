package database

import (
	"os"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	_ "github.com/bvboe/b2s-go/scanner-core/sqlitedriver"
)

func TestCleanupOrphanedImages(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_cleanup_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Create some test images and instances
	image1 := containers.ImageID{
		Reference: "nginx:latest",
		Digest:    "sha256:orphaned1",
	}
	image2 := containers.ImageID{
		Reference: "redis:7",
		Digest:    "sha256:active1",
	}
	image3 := containers.ImageID{
		Reference: "postgres:15",
		Digest:    "sha256:orphaned2",
	}

	// Add instances - only image2 has an active instance
	instance1 := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "pod1",
			Name: "container1",
		},
		Image:            image1,
		NodeName:         "node1",
		ContainerRuntime: "containerd",
	}

	instance2 := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "pod2",
			Name: "container2",
		},
		Image:            image2,
		NodeName:         "node1",
		ContainerRuntime: "containerd",
	}

	instance3 := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "pod3",
			Name: "container3",
		},
		Image:            image3,
		NodeName:         "node1",
		ContainerRuntime: "containerd",
	}

	// Add all instances
	_, err = db.AddContainer(instance1)
	if err != nil {
		t.Fatalf("Failed to add instance1: %v", err)
	}
	_, err = db.AddContainer(instance2)
	if err != nil {
		t.Fatalf("Failed to add instance2: %v", err)
	}
	_, err = db.AddContainer(instance3)
	if err != nil {
		t.Fatalf("Failed to add instance3: %v", err)
	}

	// Verify all images exist
	var imageCount int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM images").Scan(&imageCount)
	if err != nil {
		t.Fatalf("Failed to count images: %v", err)
	}
	if imageCount != 3 {
		t.Errorf("Expected 3 images, got %d", imageCount)
	}

	// Remove instance1 and instance3 to make their images orphaned
	err = db.RemoveContainer(instance1.ID)
	if err != nil {
		t.Fatalf("Failed to remove instance1: %v", err)
	}
	err = db.RemoveContainer(instance3.ID)
	if err != nil {
		t.Fatalf("Failed to remove instance3: %v", err)
	}

	// Verify only 1 instance remains
	var instanceCount int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM containers").Scan(&instanceCount)
	if err != nil {
		t.Fatalf("Failed to count instances: %v", err)
	}
	if instanceCount != 1 {
		t.Errorf("Expected 1 instance, got %d", instanceCount)
	}

	// Run cleanup
	stats, err := db.CleanupOrphanedImages()
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Verify stats
	if stats.ImagesRemoved != 2 {
		t.Errorf("Expected 2 images removed, got %d", stats.ImagesRemoved)
	}

	// Verify only 1 image remains (the one with an active instance)
	err = db.conn.QueryRow("SELECT COUNT(*) FROM images").Scan(&imageCount)
	if err != nil {
		t.Fatalf("Failed to count images after cleanup: %v", err)
	}
	if imageCount != 1 {
		t.Errorf("Expected 1 image after cleanup, got %d", imageCount)
	}

	// Verify the remaining image is image2 (redis)
	var digest string
	err = db.conn.QueryRow("SELECT digest FROM images LIMIT 1").Scan(&digest)
	if err != nil {
		t.Fatalf("Failed to get remaining image: %v", err)
	}
	if digest != image2.Digest {
		t.Errorf("Expected remaining image to be %s, got %s", image2.Digest, digest)
	}
}

func TestCleanupOrphanedImages_NoOrphans(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_cleanup_noorphans_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Create an image with an active instance
	image := containers.ImageID{
		Reference: "nginx:latest",
		Digest:    "sha256:active1",
	}

	instance := containers.Container{
		ID: containers.ContainerID{
			Namespace: "default",
			Pod:       "pod1",
			Name: "container1",
		},
		Image:            image,
		NodeName:         "node1",
		ContainerRuntime: "containerd",
	}

	_, err = db.AddContainer(instance)
	if err != nil {
		t.Fatalf("Failed to add instance: %v", err)
	}

	// Run cleanup
	stats, err := db.CleanupOrphanedImages()
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Verify no images were removed
	if stats.ImagesRemoved != 0 {
		t.Errorf("Expected 0 images removed, got %d", stats.ImagesRemoved)
	}
	if stats.PackagesRemoved != 0 {
		t.Errorf("Expected 0 packages removed, got %d", stats.PackagesRemoved)
	}
	if stats.VulnerabilitiesRemoved != 0 {
		t.Errorf("Expected 0 vulnerabilities removed, got %d", stats.VulnerabilitiesRemoved)
	}
}

func TestCleanupOrphanedImages_EmptyDatabase(t *testing.T) {
	// Create temporary database
	dbPath := "/tmp/test_cleanup_empty_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Run cleanup on empty database
	stats, err := db.CleanupOrphanedImages()
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// Verify no errors and zero stats
	if stats.ImagesRemoved != 0 {
		t.Errorf("Expected 0 images removed, got %d", stats.ImagesRemoved)
	}
}
