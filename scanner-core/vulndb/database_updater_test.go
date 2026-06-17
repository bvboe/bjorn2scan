package vulndb

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	// Note: sqlite driver is already registered by the production code
)

// mockTimestampStore implements TimestampStore for testing
type mockTimestampStore struct {
	timestamp time.Time
	loadErr   error
	saveErr   error
}

func (m *mockTimestampStore) LoadGrypeDBTimestamp() (time.Time, error) {
	if m.loadErr != nil {
		return time.Time{}, m.loadErr
	}
	return m.timestamp, nil
}

func (m *mockTimestampStore) SaveGrypeDBTimestamp(t time.Time) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.timestamp = t
	return nil
}

func TestNewDatabaseUpdater(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	// Verify grype directory was created
	grypeDir := filepath.Join(tmpDir, "grype")
	if _, err := os.Stat(grypeDir); os.IsNotExist(err) {
		t.Error("grype directory should be created")
	}

	// Verify currentVersion is nil initially
	if du.GetCurrentVersion() != nil {
		t.Error("currentVersion should be nil initially")
	}
}

func TestNewDatabaseUpdater_EmptyDir(t *testing.T) {
	_, err := NewDatabaseUpdater("")
	if err == nil {
		t.Error("Expected error for empty dbRootDir")
	}
}

func TestDatabaseUpdater_GetCurrentVersion(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	// Initially nil
	if du.GetCurrentVersion() != nil {
		t.Error("GetCurrentVersion should return nil before any database load")
	}

	// Mock loader sets the version
	mockBuilt := time.Date(2025, 12, 27, 0, 0, 0, 0, time.UTC)
	du.SetLoader(func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
		return &DatabaseStatus{
			Built:         mockBuilt,
			SchemaVersion: "v6.1.3",
			Path:          "/test/path",
		}, nil
	})

	// Call CheckForUpdates to populate the version
	_, _ = du.CheckForUpdates(context.Background())

	// Now it should return the version
	version := du.GetCurrentVersion()
	if version == nil {
		t.Fatal("GetCurrentVersion should return non-nil after CheckForUpdates")
	}

	if !version.Built.Equal(mockBuilt) {
		t.Errorf("Expected built time %v, got %v", mockBuilt, version.Built)
	}

	if version.SchemaVersion != "v6.1.3" {
		t.Errorf("Expected schema version v6.1.3, got %s", version.SchemaVersion)
	}
}

func TestDatabaseUpdater_CheckForUpdates_FirstRun(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	// Mock loader returns a database status
	mockBuilt := time.Date(2025, 12, 27, 0, 0, 0, 0, time.UTC)
	du.SetLoader(func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
		return &DatabaseStatus{
			Built:         mockBuilt,
			SchemaVersion: "v6.1.3",
			Path:          "/test/path",
		}, nil
	})

	// First run should return false (no database existed, so no change to detect)
	hasChanged, err := du.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdates failed: %v", err)
	}

	if hasChanged {
		t.Error("Expected hasChanged=false on first run (no previous database)")
	}

	// Version should be stored in memory
	version := du.GetCurrentVersion()
	if version == nil {
		t.Fatal("Version should be stored after CheckForUpdates")
	}

	if !version.Built.Equal(mockBuilt) {
		t.Errorf("Expected built time %v, got %v", mockBuilt, version.Built)
	}
}

func TestDatabaseUpdater_CheckForUpdates_LoaderError(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	// Mock loader returns error
	du.SetLoader(func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
		return nil, fmt.Errorf("network error")
	})

	hasChanged, err := du.CheckForUpdates(context.Background())
	if err == nil {
		t.Error("Expected error when loader fails")
	}

	if hasChanged {
		t.Error("Expected hasChanged=false on error")
	}

	// Version should remain nil on error
	if du.GetCurrentVersion() != nil {
		t.Error("Version should be nil after loader error")
	}
}

func TestDatabaseUpdater_GetCurrentStatus(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	mockBuilt := time.Date(2025, 12, 27, 0, 0, 0, 0, time.UTC)
	du.SetLoader(func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
		// Verify update=false is passed
		if update {
			t.Error("GetCurrentStatus should call loader with update=false")
		}
		return &DatabaseStatus{
			Built:         mockBuilt,
			SchemaVersion: "v6.1.3",
			Path:          "/test/path",
		}, nil
	})

	status, err := du.GetCurrentStatus(context.Background())
	if err != nil {
		t.Fatalf("GetCurrentStatus failed: %v", err)
	}

	if !status.Built.Equal(mockBuilt) {
		t.Errorf("Expected built time %v, got %v", mockBuilt, status.Built)
	}

	// GetCurrentStatus should also update in-memory version
	version := du.GetCurrentVersion()
	if version == nil {
		t.Fatal("GetCurrentVersion should return non-nil after GetCurrentStatus")
	}

	if !version.Built.Equal(mockBuilt) {
		t.Errorf("Expected in-memory built time %v, got %v", mockBuilt, version.Built)
	}
}

func TestDatabaseUpdater_GetCurrentVersion_ReturnsCopy(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	mockBuilt := time.Date(2025, 12, 27, 0, 0, 0, 0, time.UTC)
	du.SetLoader(func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
		return &DatabaseStatus{
			Built:         mockBuilt,
			SchemaVersion: "v6.1.3",
			Path:          "/test/path",
		}, nil
	})

	// Populate version
	_, _ = du.CheckForUpdates(context.Background())

	// Get two copies
	v1 := du.GetCurrentVersion()
	v2 := du.GetCurrentVersion()

	// Modify v1
	v1.SchemaVersion = "modified"

	// v2 should not be affected (they should be independent copies)
	if v2.SchemaVersion == "modified" {
		t.Error("GetCurrentVersion should return a copy, not the same pointer")
	}
}

func TestNewDatabaseUpdaterWithConfig(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := DatabaseUpdaterConfig{
		LatestURL: "https://custom.example.com/grype/db",
	}

	du, err := NewDatabaseUpdaterWithConfig(tmpDir, cfg)
	if err != nil {
		t.Fatalf("NewDatabaseUpdaterWithConfig failed: %v", err)
	}

	// Verify grype directory was created
	grypeDir := filepath.Join(tmpDir, "grype")
	if _, err := os.Stat(grypeDir); os.IsNotExist(err) {
		t.Error("grype directory should be created")
	}

	// Verify the custom URL was set (we can check via the distCfg)
	if du.distCfg.LatestURL != cfg.LatestURL {
		t.Errorf("Expected LatestURL '%s', got '%s'", cfg.LatestURL, du.distCfg.LatestURL)
	}
}

// TestDatabaseUpdater_ShouldUseActualDbTimestamp is a TDD test that FAILS with the current
// implementation and will PASS once we fix the stale timestamp bug.
//
// The bug: grype.LoadVulnerabilityDB returns a stale timestamp from grype_db_state.json
// instead of reading the actual Built timestamp from vulnerability.db.
//
// The fix: After loading, re-read the database description to get the actual timestamp.
//
// This test verifies that GetCurrentVersion returns the timestamp from the actual
// database file, not from what the loader returns.
func TestDatabaseUpdater_ShouldUseActualDbTimestamp(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	// Timestamps representing the bug scenario
	staleTimestamp := time.Date(2026, 1, 8, 8, 20, 13, 0, time.UTC)  // What loader returns (stale)
	actualTimestamp := time.Date(2026, 1, 10, 8, 19, 2, 0, time.UTC) // What's in the actual db file

	dbPath := filepath.Join(tmpDir, "grype", "6", "vulnerability.db")

	// Mock loader returns stale timestamp (simulating the grype bug)
	// but we also set up a mock description reader that returns the actual timestamp
	du.SetLoader(func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
		return &DatabaseStatus{
			Built:         staleTimestamp, // Stale! The bug we're fixing.
			SchemaVersion: "v6.1.3",
			Path:          dbPath,
		}, nil
	})

	// Mock the description reader to return the actual timestamp
	// (simulating what v6.ReadDescription would return from the real db file)
	du.SetDescriptionReader(func(path string) (time.Time, error) {
		return actualTimestamp, nil
	})

	// Call CheckForUpdates
	_, err = du.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdates failed: %v", err)
	}

	// THE KEY ASSERTION: GetCurrentVersion should return the ACTUAL timestamp
	// from the database file, not the stale timestamp from the loader.
	version := du.GetCurrentVersion()
	if version == nil {
		t.Fatal("Version should not be nil")
	}

	// This test FAILS with current implementation (returns staleTimestamp)
	// This test PASSES after fix (returns actualTimestamp)
	if !version.Built.Equal(actualTimestamp) {
		t.Errorf("GetCurrentVersion should return actual db timestamp %v, got %v (stale from loader)",
			actualTimestamp, version.Built)
	}
}

// TestDatabaseUpdater_ShouldDetectChangeWhenLoaderReturnsStale tests that
// database changes are detected even when grype's loader returns stale timestamps.
//
// Scenario:
// 1. First call: db doesn't exist, loader returns Jan 8, stored to persistent store
// 2. Second call: db now exists with Jan 10, but loader still returns Jan 8 (bug)
// 3. Expected: hasChanged=true because actual db (Jan 10) != persistent store (Jan 8)
// 4. Previous bug: hasChanged=false because comparison used in-memory values
func TestDatabaseUpdater_ShouldDetectChangeWhenLoaderReturnsStale(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a mock timestamp store to simulate persistent storage
	store := &mockTimestampStore{}

	du, err := NewDatabaseUpdaterWithConfig(tmpDir, DatabaseUpdaterConfig{
		TimestampStore: store,
	})
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	oldTimestamp := time.Date(2026, 1, 8, 8, 20, 13, 0, time.UTC)
	newTimestamp := time.Date(2026, 1, 10, 8, 19, 2, 0, time.UTC)

	grypeDir := filepath.Join(tmpDir, "grype", "6")
	dbPath := filepath.Join(grypeDir, "vulnerability.db")

	descReaderCalls := 0

	// Loader always returns old timestamp (simulating grype's caching bug)
	du.SetLoader(func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
		return &DatabaseStatus{
			Built:         oldTimestamp, // Always stale
			SchemaVersion: "v6.1.3",
			Path:          dbPath,
		}, nil
	})

	// Description reader simulates the actual db file content
	du.SetDescriptionReader(func(path string) (time.Time, error) {
		descReaderCalls++
		if descReaderCalls == 1 {
			// First read: old database
			return oldTimestamp, nil
		}
		// After "update": new database
		return newTimestamp, nil
	})

	// First call: establishes baseline (no db file exists yet)
	hasChanged, err := du.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("First CheckForUpdates failed: %v", err)
	}
	if hasChanged {
		t.Error("First call should return hasChanged=false (initial)")
	}

	// Verify baseline is stored in persistent store
	if !store.timestamp.Equal(oldTimestamp) {
		t.Fatalf("Expected persistent store to have %v, got %v", oldTimestamp, store.timestamp)
	}

	// Verify in-memory version is also updated
	version := du.GetCurrentVersion()
	if version == nil || !version.Built.Equal(oldTimestamp) {
		t.Fatalf("Expected in-memory timestamp %v, got %v", oldTimestamp, version)
	}

	// Simulate: database file now exists (after first download)
	// This makes dbExisted=true on the second call
	if err := os.MkdirAll(grypeDir, 0755); err != nil {
		t.Fatalf("Failed to create grype dir: %v", err)
	}
	if err := os.WriteFile(dbPath, []byte("placeholder"), 0644); err != nil {
		t.Fatalf("Failed to create placeholder db file: %v", err)
	}

	// Second call: db file now exists with newTimestamp, but loader returns oldTimestamp
	hasChanged, err = du.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("Second CheckForUpdates failed: %v", err)
	}

	// THE KEY ASSERTION: Should detect the change by comparing against persistent store
	// The description reader returns newTimestamp (actual db content)
	// The persistent store has oldTimestamp (from first call)
	// Therefore hasChanged should be true
	if !hasChanged {
		t.Error("Should detect database change even when loader returns stale timestamp")
		t.Logf("Loader returned: %v", oldTimestamp)
		t.Logf("Actual db has (from descReader): %v", newTimestamp)
		t.Logf("Persistent store has: %v", store.timestamp)
	}

	// Verify the in-memory version was updated to the actual timestamp
	version = du.GetCurrentVersion()
	if version == nil || !version.Built.Equal(newTimestamp) {
		t.Errorf("Expected updated timestamp %v, got %v", newTimestamp, version.Built)
	}

	// Verify persistent store was updated
	if !store.timestamp.Equal(newTimestamp) {
		t.Errorf("Expected persistent store to have %v, got %v", newTimestamp, store.timestamp)
	}
}

// TestDatabaseUpdater_IncrementalUpdateFails_RetriesWithFullDownload tests that when
// an incremental update fails with an existing database (e.g. grype DB schema changed),
// the updater deletes the existing DB and retries with a full download.
//
// This reproduces the production failure where K8s pods have a persistent NFS volume
// with yesterday's grype DB, and today's new DB listing has no compatible delta update.
// TestDatabaseUpdater_LoaderError_OnDiskFresh_AcceptsIt covers the regression
// fix: grype's loader can return errors (e.g. its post-update validateAge in
// Status() returning a stale timestamp) AFTER successfully downloading and
// activating a fresh DB. We must trust the on-disk file rather than treating
// the loader's error as fatal.
func TestDatabaseUpdater_LoaderError_OnDiskFresh_AcceptsIt(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	// Pretend the loader downloaded a fresh DB but still returned an error.
	schemaDir := filepath.Join(tmpDir, "grype", "6")
	dbPath := filepath.Join(schemaDir, "vulnerability.db")
	if err := os.MkdirAll(schemaDir, 0o755); err != nil {
		t.Fatalf("failed to create schema dir: %v", err)
	}
	if err := os.WriteFile(dbPath, []byte("placeholder"), 0o644); err != nil {
		t.Fatalf("failed to create db file: %v", err)
	}

	freshTimestamp := time.Now().UTC().Add(-1 * time.Hour) // fresh, < 5 days

	calls := 0
	du.SetLoader(func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
		calls++
		return nil, fmt.Errorf("the vulnerability database was built 1 week ago (max allowed age is 5 days)")
	})
	du.SetDescriptionReader(func(path string) (time.Time, error) {
		return freshTimestamp, nil
	})

	_, err = du.CheckForUpdates(context.Background())
	if err != nil {
		t.Fatalf("CheckForUpdates should accept fresh on-disk DB despite loader error, got: %v", err)
	}

	if calls != 1 {
		t.Errorf("expected exactly 1 loader call (no retry), got %d", calls)
	}

	// Schema dir must still exist — we no longer delete it on loader error.
	if _, err := os.Stat(schemaDir); err != nil {
		t.Errorf("schema dir was removed; on loader error we must trust the on-disk DB, not delete it: %v", err)
	}

	version := du.GetCurrentVersion()
	if version == nil {
		t.Fatal("version should be set after accepting on-disk DB")
	}
	if !version.Built.Equal(freshTimestamp) {
		t.Errorf("expected built %v (from disk), got %v", freshTimestamp, version.Built)
	}
}

// TestDatabaseUpdater_LoaderError_NoOnDiskDB_Fails covers the case where the
// loader fails and there's nothing usable on disk — that's a real error.
func TestDatabaseUpdater_LoaderError_NoOnDiskDB_Fails(t *testing.T) {
	tmpDir := t.TempDir()

	du, err := NewDatabaseUpdater(tmpDir)
	if err != nil {
		t.Fatalf("NewDatabaseUpdater failed: %v", err)
	}

	calls := 0
	du.SetLoader(func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
		calls++
		return nil, fmt.Errorf("network error")
	})
	du.SetDescriptionReader(func(path string) (time.Time, error) {
		return time.Time{}, fmt.Errorf("no DB on disk")
	})

	_, err = du.CheckForUpdates(context.Background())
	if err == nil {
		t.Error("expected error when both loader and on-disk read fail")
	}

	if calls != 1 {
		t.Errorf("expected exactly 1 loader call (no retry), got %d", calls)
	}
}

// TestReadGrypeDBTimestampFromSQLite_RFC3339Format tests that the timestamp parsing
// correctly handles RFC3339 format (2026-01-16T06:16:58Z) which grype v6 now uses.
// This was a bug where the code only handled the old format (2006-01-02 15:04:05+00:00).
func TestReadGrypeDBTimestampFromSQLite_RFC3339Format(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	// Create a test SQLite database with RFC3339 timestamp format
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	// Create the db_metadata table as grype v6 does
	_, err = db.Exec(`CREATE TABLE db_metadata (build_timestamp TEXT)`)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Insert RFC3339 format timestamp (the format grype v6 now uses)
	rfc3339Timestamp := "2026-01-16T06:16:58Z"
	_, err = db.Exec(`INSERT INTO db_metadata (build_timestamp) VALUES (?)`, rfc3339Timestamp)
	if err != nil {
		t.Fatalf("Failed to insert timestamp: %v", err)
	}
	_ = db.Close()

	// Now test that readGrypeDBTimestampFromSQLite can parse it
	got, err := readGrypeDBTimestampFromSQLite(dbPath)
	if err != nil {
		t.Fatalf("readGrypeDBTimestampFromSQLite failed: %v", err)
	}

	expected := time.Date(2026, 1, 16, 6, 16, 58, 0, time.UTC)
	if !got.Equal(expected) {
		t.Errorf("Expected timestamp %v, got %v", expected, got)
	}
}

// TestReadGrypeDBTimestampFromSQLite_LegacyFormat tests that the timestamp parsing
// still handles the legacy format (2006-01-02 15:04:05+00:00) for backwards compatibility.
func TestReadGrypeDBTimestampFromSQLite_LegacyFormat(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE db_metadata (build_timestamp TEXT)`)
	if err != nil {
		t.Fatalf("Failed to create table: %v", err)
	}

	// Insert legacy format timestamp
	legacyTimestamp := "2026-01-13 08:06:41+00:00"
	_, err = db.Exec(`INSERT INTO db_metadata (build_timestamp) VALUES (?)`, legacyTimestamp)
	if err != nil {
		t.Fatalf("Failed to insert timestamp: %v", err)
	}
	_ = db.Close()

	got, err := readGrypeDBTimestampFromSQLite(dbPath)
	if err != nil {
		t.Fatalf("readGrypeDBTimestampFromSQLite failed: %v", err)
	}

	expected := time.Date(2026, 1, 13, 8, 6, 41, 0, time.UTC)
	if !got.Equal(expected) {
		t.Errorf("Expected timestamp %v, got %v", expected, got)
	}
}
