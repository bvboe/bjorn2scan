package database

import (
	"os"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"
)

// TestGetOrCreateImage_CreatesNew tests that a new image is created
func TestGetOrCreateImage_CreatesNew(t *testing.T) {
	dbPath := "/tmp/test_images_create_" + time.Now().Format("20060102150405") + ".db"
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer func() {
		_ = Close(db)
		_ = os.Remove(dbPath)
	}()

	image := containers.ImageID{
		Reference: "nginx:1.21",
		Digest:     "sha256:abcdef1234567890",
	}

	id, created, err := db.GetOrCreateImage(image)
	if err != nil {
		t.Fatalf("GetOrCreateImage failed: %v", err)
	}

	if !created {
		t.Error("Expected created=true for new image")
	}

	if id == 0 {
		t.Error("Expected non-zero image ID")
	}

	// Verify image exists in database
	var digest string
	err = db.conn.QueryRow("SELECT digest FROM images WHERE id = ?", id).Scan(&digest)
	if err != nil {
		t.Fatalf("Failed to query image: %v", err)
	}

	if digest != image.Digest {
		t.Errorf("Digest = %v, want %v", digest, image.Digest)
	}
}

// TestGetOrCreateImage_ReturnsExisting tests that existing image is returned
func TestGetOrCreateImage_ReturnsExisting(t *testing.T) {
	dbPath := "/tmp/test_images_existing_" + time.Now().Format("20060102150405") + ".db"
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer func() {
		_ = Close(db)
		_ = os.Remove(dbPath)
	}()

	image := containers.ImageID{
		Reference: "nginx:1.21",
		Digest:     "sha256:abcdef1234567890",
	}

	// Create first time
	id1, created1, err := db.GetOrCreateImage(image)
	if err != nil {
		t.Fatalf("First GetOrCreateImage failed: %v", err)
	}

	if !created1 {
		t.Error("Expected created=true for first call")
	}

	// Try to create again with same digest (different reference)
	image.Reference = "nginx:latest"
	id2, created2, err := db.GetOrCreateImage(image)
	if err != nil {
		t.Fatalf("Second GetOrCreateImage failed: %v", err)
	}

	if created2 {
		t.Error("Expected created=false for existing image")
	}

	if id1 != id2 {
		t.Errorf("IDs should match: id1=%d, id2=%d", id1, id2)
	}
}

// TestGetOrCreateImage_EmptyDigestError tests that empty digest returns error
func TestGetOrCreateImage_EmptyDigestError(t *testing.T) {
	dbPath := "/tmp/test_images_empty_" + time.Now().Format("20060102150405") + ".db"
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer func() {
		_ = Close(db)
		_ = os.Remove(dbPath)
	}()

	image := containers.ImageID{
		Reference: "nginx:1.21",
		Digest:     "", // Empty digest
	}

	_, _, err = db.GetOrCreateImage(image)
	if err == nil {
		t.Error("Expected error for empty digest, got nil")
	}
}

// TestGetAllImages tests retrieving all images
func TestGetAllImages(t *testing.T) {
	dbPath := "/tmp/test_images_all_" + time.Now().Format("20060102150405") + ".db"
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer func() {
		_ = Close(db)
		_ = os.Remove(dbPath)
	}()

	// Create test images
	images := []containers.ImageID{
		{Reference: "nginx:1.21", Digest: "sha256:digest1"},
		{Reference: "redis:6.2", Digest: "sha256:digest2"},
		{Reference: "postgres:13", Digest: "sha256:digest3"},
	}

	for _, img := range images {
		_, _, err := db.GetOrCreateImage(img)
		if err != nil {
			t.Fatalf("Failed to create image: %v", err)
		}
	}

	// Retrieve all images
	result, err := db.GetAllImages()
	if err != nil {
		t.Fatalf("GetAllImages failed: %v", err)
	}

	resultImages, ok := result.([]ContainerImage)
	if !ok {
		t.Fatalf("Expected []ContainerImage, got %T", result)
	}

	if len(resultImages) != 3 {
		t.Errorf("Expected 3 images, got %d", len(resultImages))
	}

	// Verify default status value
	for _, img := range resultImages {
		if img.Status == "" {
			t.Error("Status should have default value")
		}
	}
}

// TestGetImageByID tests retrieving a specific image by ID
func TestGetImageByID(t *testing.T) {
	dbPath := "/tmp/test_images_by_id_" + time.Now().Format("20060102150405") + ".db"
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer func() {
		_ = Close(db)
		_ = os.Remove(dbPath)
	}()

	image := containers.ImageID{
		Reference: "nginx:1.21",
		Digest:     "sha256:test123",
	}

	id, _, err := db.GetOrCreateImage(image)
	if err != nil {
		t.Fatalf("Failed to create image: %v", err)
	}

	// Retrieve by ID
	retrieved, err := db.GetImageByID(id)
	if err != nil {
		t.Fatalf("GetImageByID failed: %v", err)
	}

	if retrieved.ID != id {
		t.Errorf("ID = %d, want %d", retrieved.ID, id)
	}

	if retrieved.Digest != image.Digest {
		t.Errorf("Digest = %v, want %v", retrieved.Digest, image.Digest)
	}
}

// TestGetImageByID_NotFound tests error for non-existent image
func TestGetImageByID_NotFound(t *testing.T) {
	dbPath := "/tmp/test_images_not_found_" + time.Now().Format("20060102150405") + ".db"
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer func() {
		_ = Close(db)
		_ = os.Remove(dbPath)
	}()

	_, err = db.GetImageByID(99999)
	if err == nil {
		t.Error("Expected error for non-existent image, got nil")
	}
}

// TestGetOrCreateImage_Concurrent tests concurrent access
// Note: SQLite has limited concurrent write support, so some operations may fail with UNIQUE constraint errors
// This is expected behavior and applications should handle it (retry or ignore)
func TestGetOrCreateImage_Concurrent(t *testing.T) {
	dbPath := "/tmp/test_images_concurrent_" + time.Now().Format("20060102150405") + ".db"
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer func() {
		_ = Close(db)
		_ = os.Remove(dbPath)
	}()

	image := containers.ImageID{
		Reference: "nginx:1.21",
		Digest:     "sha256:concurrent123",
	}

	// Launch 10 concurrent goroutines trying to create the same image
	type result struct {
		id  int64
		err error
	}
	results := make(chan result, 10)

	for i := 0; i < 10; i++ {
		go func() {
			id, _, err := db.GetOrCreateImage(image)
			results <- result{id: id, err: err}
		}()
	}

	// Collect results
	var successfulIDs []int64
	var errors []error
	for i := 0; i < 10; i++ {
		r := <-results
		if r.err != nil {
			errors = append(errors, r.err)
		} else {
			successfulIDs = append(successfulIDs, r.id)
		}
	}

	// At least one should succeed
	if len(successfulIDs) == 0 {
		t.Fatal("All concurrent operations failed")
	}

	// All successful IDs should be the same
	firstID := successfulIDs[0]
	for i, id := range successfulIDs {
		if id != firstID {
			t.Errorf("ID mismatch at index %d: got %d, want %d", i, id, firstID)
		}
	}

	// Verify only one image was created (despite concurrent attempts)
	var count int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM images WHERE digest = ?",
		image.Digest).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count images: %v", err)
	}

	if count != 1 {
		t.Errorf("Expected 1 image in database, got %d", count)
	}

	// Some operations may have failed due to UNIQUE constraint - this is expected with SQLite
	if len(errors) > 0 {
		t.Logf("Note: %d/%d operations failed due to concurrent access (expected with SQLite)", len(errors), 10)
	}
}

// TestGetOrCreateImage_TransactionBehavior tests that transaction rollback works
func TestGetOrCreateImage_TransactionBehavior(t *testing.T) {
	dbPath := "/tmp/test_images_tx_" + time.Now().Format("20060102150405") + ".db"
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer func() {
		_ = Close(db)
		_ = os.Remove(dbPath)
	}()

	// Start transaction
	tx, err := db.conn.Begin()
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}

	image := containers.ImageID{
		Reference: "nginx:1.21",
		Digest:     "sha256:tx123",
	}

	// Use transaction-aware version
	id, created, err := db.getOrCreateImageTx(tx, image)
	if err != nil {
		t.Fatalf("getOrCreateImageTx failed: %v", err)
	}

	if !created {
		t.Error("Expected created=true")
	}

	// Rollback transaction
	if err := tx.Rollback(); err != nil {
		t.Fatalf("Failed to rollback: %v", err)
	}

	// Verify image was NOT created (rollback worked)
	var count int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM images WHERE id = ?", id).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count images: %v", err)
	}

	if count != 0 {
		t.Errorf("Expected 0 images after rollback, got %d", count)
	}
}
