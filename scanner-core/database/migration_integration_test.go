package database

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	_ "github.com/bvboe/b2s-go/scanner-core/sqlitedriver"
)

// TestMigrationV25WithRealisticData tests the v25 migration (populate architecture from SBOMs)
// with realistic data to catch deadlock issues that only occur with actual rows.
// This addresses the production incident where v25 caused 30k+ pod restarts.
func TestMigrationV25WithRealisticData(t *testing.T) {
	// Create temporary test database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_v25.db")

	// Create database at v24 (before architecture population)
	conn, err := createDatabaseAtVersion(dbPath, 24)
	if err != nil {
		t.Fatalf("Failed to create database at v24: %v", err)
	}

	// Insert realistic test data - many images with SBOMs
	numImages := 100 // Simulate production-like data volume
	t.Logf("Inserting %d images with SBOMs...", numImages)

	for i := 0; i < numImages; i++ {
		digest := fmt.Sprintf("sha256:test%d%d%d", i, i*2, i*3)
		sbom := generateTestSBOM("amd64")
		if i%3 == 0 {
			sbom = generateTestSBOM("arm64")
		}
		if i%10 == 0 {
			sbom = generateTestSBOM("") // Some without architecture
		}

		_, err := conn.Exec(`
			INSERT INTO container_images (digest, sbom, status, created_at, updated_at)
			VALUES (?, ?, 'completed', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		`, digest, sbom)
		if err != nil {
			t.Fatalf("Failed to insert test image %d: %v", i, err)
		}
	}

	// Also add some containers referencing these images
	for i := 0; i < numImages/2; i++ {
		_, err := conn.Exec(`
			INSERT INTO container_instances (namespace, pod, container, repository, tag, image_id, created_at)
			VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		`, "default", fmt.Sprintf("pod-%d", i), "main", "nginx", "latest", i+1)
		if err != nil {
			t.Fatalf("Failed to insert test container %d: %v", i, err)
		}
	}

	// Verify data was inserted
	var count int
	err = conn.QueryRow("SELECT COUNT(*) FROM container_images WHERE sbom IS NOT NULL").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count images: %v", err)
	}
	t.Logf("Inserted %d images with SBOMs", count)

	// Close the connection before running migration
	if err := conn.Close(); err != nil {
		t.Fatalf("Failed to close connection: %v", err)
	}

	// Now open with full migration - this should run v25
	// Use a channel to detect if migration hangs (deadlock)
	done := make(chan error, 1)
	var db *DB

	go func() {
		var err error
		db, err = New(dbPath)
		done <- err
	}()

	// Wait for migration with timeout
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Migration failed: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Migration timed out - possible deadlock detected!")
	}

	defer func() {
		if err := Close(db); err != nil {
			t.Logf("Warning: failed to close database: %v", err)
		}
	}()

	// Verify migration results
	var withArch, withoutArch int
	err = db.conn.QueryRow(`
		SELECT
			SUM(CASE WHEN architecture IS NOT NULL AND architecture != '' THEN 1 ELSE 0 END),
			SUM(CASE WHEN architecture IS NULL OR architecture = '' THEN 1 ELSE 0 END)
		FROM images
	`).Scan(&withArch, &withoutArch)
	if err != nil {
		t.Fatalf("Failed to query architecture counts: %v", err)
	}

	t.Logf("Images with architecture: %d, without: %d", withArch, withoutArch)

	// Most images should have architecture populated
	if withArch < numImages*8/10 { // At least 80% should have architecture
		t.Errorf("Expected at least %d images with architecture, got %d", numImages*8/10, withArch)
	}
}

// TestMigrationV27WithRealisticData tests the v27 migration (add reference column)
// which also processes existing data and could deadlock.
func TestMigrationV27WithRealisticData(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_v27.db")

	// Create database at v26
	conn, err := createDatabaseAtVersion(dbPath, 26)
	if err != nil {
		t.Fatalf("Failed to create database at v26: %v", err)
	}

	// Insert realistic test data
	numContainers := 200
	t.Logf("Inserting %d containers...", numContainers)

	// First insert images
	for i := 0; i < numContainers/2; i++ {
		_, err := conn.Exec(`
			INSERT INTO container_images (digest, status, created_at, updated_at)
			VALUES (?, 'completed', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		`, fmt.Sprintf("sha256:img%d", i))
		if err != nil {
			t.Fatalf("Failed to insert image %d: %v", i, err)
		}
	}

	// Then insert containers
	for i := 0; i < numContainers; i++ {
		imageID := (i % (numContainers / 2)) + 1
		_, err := conn.Exec(`
			INSERT INTO container_instances (namespace, pod, container, repository, tag, image_id, created_at)
			VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		`, "default", fmt.Sprintf("pod-%d", i), "main", fmt.Sprintf("nginx%d", i), "v1.0", imageID)
		if err != nil {
			t.Fatalf("Failed to insert container %d: %v", i, err)
		}
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Failed to close connection: %v", err)
	}

	// Run migration with timeout
	done := make(chan error, 1)
	var db *DB

	go func() {
		var err error
		db, err = New(dbPath)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Migration failed: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Migration timed out - possible deadlock detected!")
	}

	defer func() {
		if err := Close(db); err != nil {
			t.Logf("Warning: failed to close database: %v", err)
		}
	}()

	// Verify reference column was populated
	var withRef int
	err = db.conn.QueryRow(`
		SELECT COUNT(*) FROM containers WHERE reference IS NOT NULL AND reference != ''
	`).Scan(&withRef)
	if err != nil {
		t.Fatalf("Failed to query reference counts: %v", err)
	}

	t.Logf("Containers with reference: %d", withRef)
	if withRef != numContainers {
		t.Errorf("Expected %d containers with reference, got %d", numContainers, withRef)
	}
}

// TestConcurrentReadWriteAfterMigration tests that concurrent read/write access
// works correctly after migrations are complete.
// Note: SQLite only supports one writer at a time, so concurrent migrations are
// not supported. This test verifies concurrent access patterns post-migration.
func TestConcurrentReadWriteAfterMigration(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_concurrent.db")

	// Create and migrate database first (single connection)
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	// Insert some test data
	for i := 0; i < 50; i++ {
		_, err := db.conn.Exec(`
			INSERT INTO images (digest, status, created_at, updated_at)
			VALUES (?, 'completed', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		`, fmt.Sprintf("sha256:concurrent%d", i))
		if err != nil {
			t.Fatalf("Failed to insert test image: %v", err)
		}
	}

	// Now test concurrent reads
	var wg sync.WaitGroup
	errors := make(chan error, 10)

	// Spawn multiple goroutines doing concurrent reads
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				var count int
				err := db.conn.QueryRow("SELECT COUNT(*) FROM images").Scan(&count)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d read %d: %w", id, j, err)
					return
				}
			}
		}(i)
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(30 * time.Second):
		t.Fatal("Concurrent read test timed out!")
	}

	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent access error: %v", err)
	}

	if err := Close(db); err != nil {
		t.Logf("Warning: failed to close database: %v", err)
	}
}

// TestMigrationWithLargeDataset tests migrations with a larger dataset
// to catch performance issues and ensure migrations scale.
func TestMigrationWithLargeDataset(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large dataset test in short mode")
	}

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_large.db")

	// Create database at v24
	conn, err := createDatabaseAtVersion(dbPath, 24)
	if err != nil {
		t.Fatalf("Failed to create database at v24: %v", err)
	}

	// Insert a large dataset (simulating production)
	numImages := 1000
	t.Logf("Inserting %d images (this may take a moment)...", numImages)

	start := time.Now()
	for i := 0; i < numImages; i++ {
		sbom := generateTestSBOM("amd64")
		_, err := conn.Exec(`
			INSERT INTO container_images (digest, sbom, status, created_at, updated_at)
			VALUES (?, ?, 'completed', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		`, fmt.Sprintf("sha256:large%d", i), sbom)
		if err != nil {
			t.Fatalf("Failed to insert test image %d: %v", i, err)
		}

		// Add some containers too
		if i%2 == 0 {
			_, err = conn.Exec(`
				INSERT INTO container_instances (namespace, pod, container, repository, tag, image_id, created_at)
				VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
			`, "production", fmt.Sprintf("app-%d", i), "main", "myapp", "v1.0", i+1)
			if err != nil {
				t.Fatalf("Failed to insert container: %v", err)
			}
		}
	}
	insertDuration := time.Since(start)
	t.Logf("Inserted %d images in %v", numImages, insertDuration)

	if err := conn.Close(); err != nil {
		t.Fatalf("Failed to close connection: %v", err)
	}

	// Run migration
	start = time.Now()
	done := make(chan error, 1)
	var db *DB

	go func() {
		var err error
		db, err = New(dbPath)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Migration failed: %v", err)
		}
	case <-time.After(120 * time.Second):
		t.Fatal("Migration timed out on large dataset - possible deadlock or performance issue!")
	}

	migrationDuration := time.Since(start)
	t.Logf("Migration completed in %v", migrationDuration)

	defer func() {
		if err := Close(db); err != nil {
			t.Logf("Warning: failed to close database: %v", err)
		}
	}()

	// Verify data integrity
	var imageCount, containerCount int
	err = db.conn.QueryRow("SELECT COUNT(*) FROM images").Scan(&imageCount)
	if err != nil {
		t.Fatalf("Failed to count images: %v", err)
	}
	err = db.conn.QueryRow("SELECT COUNT(*) FROM containers").Scan(&containerCount)
	if err != nil {
		t.Fatalf("Failed to count containers: %v", err)
	}

	t.Logf("Final counts - Images: %d, Containers: %d", imageCount, containerCount)

	if imageCount != numImages {
		t.Errorf("Expected %d images, got %d", numImages, imageCount)
	}
}

// createDatabaseAtVersion creates a new database and migrates it to a specific version.
// This allows testing migrations with pre-existing data.
func createDatabaseAtVersion(dbPath string, targetVersion int) (*sql.DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure SQLite
	_, err = conn.Exec(`
		PRAGMA journal_mode = WAL;
		PRAGMA busy_timeout = 5000;
		PRAGMA synchronous = NORMAL;
	`)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to configure database: %w", err)
	}

	// Create schema_migrations table
	_, err = conn.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to create schema_migrations: %w", err)
	}

	// Apply migrations up to target version
	for _, m := range migrations {
		if m.version > targetVersion {
			break
		}

		if err := m.up(conn); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("failed to apply migration %d: %w", m.version, err)
		}

		_, err = conn.Exec(`INSERT INTO schema_migrations (version, name) VALUES (?, ?)`,
			m.version, m.name)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("failed to record migration %d: %w", m.version, err)
		}
	}

	return conn, nil
}

// generateTestSBOM generates a minimal SBOM JSON with the given architecture.
func generateTestSBOM(arch string) string {
	if arch == "" {
		return `{"source":{"metadata":{}},"artifacts":[]}`
	}
	return fmt.Sprintf(`{"source":{"metadata":{"architecture":"%s"}},"artifacts":[]}`, arch)
}
