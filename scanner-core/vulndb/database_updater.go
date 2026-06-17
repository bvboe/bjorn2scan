package vulndb

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/bvboe/b2s-go/scanner-core/logging"
	// Note: sqlite driver is registered by grype's dependencies (modernc.org/sqlite)
)

var log = logging.For(logging.ComponentVulnDB)

// DatabaseLoader is the function signature for loading the vulnerability database
// This allows mocking in tests
type DatabaseLoader func(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error)

// DescriptionReader is the function signature for reading the database description
// This allows mocking in tests to simulate reading the actual db file timestamp
type DescriptionReader func(dbPath string) (time.Time, error)

// TimestampStore is the interface for persisting the last known grype DB timestamp
// This is used to track database changes across process restarts
type TimestampStore interface {
	LoadGrypeDBTimestamp() (time.Time, error)
	SaveGrypeDBTimestamp(t time.Time) error
}

// DatabaseStatus mirrors the relevant fields from grype's ProviderStatus
type DatabaseStatus struct {
	Built         time.Time
	SchemaVersion string
	Path          string
}

// readGrypeDBTimestampFromSQLite reads the database build timestamp directly from
// the grype SQLite database file, bypassing grype's library which may cache stale values.
// This is the authoritative source for the database timestamp.
// Uses the pure Go SQLite driver (modernc.org/sqlite) which doesn't require CGO.
func readGrypeDBTimestampFromSQLite(dbPath string) (time.Time, error) {
	// Use the pure Go SQLite driver (registered as "sqlite" by modernc.org/sqlite)
	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to open grype database: %w", err)
	}
	defer func() { _ = db.Close() }()

	var builtStr string
	err = db.QueryRow("SELECT build_timestamp FROM db_metadata LIMIT 1").Scan(&builtStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to read db_metadata: %w", err)
	}

	// Parse the timestamp - grype v6 uses RFC3339 format like "2026-01-16T06:16:58Z"
	// but older versions used "2026-01-13 08:06:41+00:00"
	t, err := time.Parse(time.RFC3339, builtStr)
	if err != nil {
		// Try legacy format with space separator
		t, err = time.Parse("2006-01-02 15:04:05-07:00", builtStr)
		if err != nil {
			t, err = time.Parse("2006-01-02 15:04:05+00:00", builtStr)
			if err != nil {
				return time.Time{}, fmt.Errorf("failed to parse timestamp %q: %w", builtStr, err)
			}
		}
	}

	return t.UTC(), nil
}

// readOnDiskBuilt returns the build timestamp from the on-disk grype DB at
// dbPath, preferring an injected descriptionReader (for tests), falling back to
// a direct SQLite read, then to grype's v6.ReadDescription. Returns an error
// only if all readers fail (e.g. the file is missing or unreadable).
func (du *DatabaseUpdater) readOnDiskBuilt(dbPath string) (time.Time, error) {
	if du.descriptionReader != nil {
		return du.descriptionReader(dbPath)
	}
	if t, err := readGrypeDBTimestampFromSQLite(dbPath); err == nil {
		return t, nil
	} else {
		log.Debug("direct SQLite read failed, falling back to v6.ReadDescription", "error", err)
	}
	desc, err := v6.ReadDescription(dbPath)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to read on-disk DB description: %w", err)
	}
	return desc.Built.UTC(), nil
}

// defaultDatabaseLoader wraps grype.LoadVulnerabilityDB
func defaultDatabaseLoader(distCfg distribution.Config, installCfg installation.Config, update bool) (*DatabaseStatus, error) {
	_, dbStatus, err := grype.LoadVulnerabilityDB(distCfg, installCfg, update)
	if err != nil {
		return nil, err
	}
	return &DatabaseStatus{
		Built:         dbStatus.Built,
		SchemaVersion: dbStatus.SchemaVersion,
		Path:          dbStatus.Path,
	}, nil
}

// DatabaseUpdater uses grype's native update mechanism to check for database updates
type DatabaseUpdater struct {
	dbRootDir         string
	distCfg           distribution.Config
	installCfg        installation.Config
	loader            DatabaseLoader    // injectable for testing
	descriptionReader DescriptionReader // injectable for testing (reads actual db timestamp)
	timestampStore    TimestampStore    // persistent storage for tracking DB changes
	mu                sync.RWMutex
	currentVersion    *DatabaseStatus // in-memory current version for metrics
}

// DatabaseUpdaterConfig holds optional configuration for DatabaseUpdater
type DatabaseUpdaterConfig struct {
	// LatestURL overrides the default grype database feed URL
	// If empty, uses the official Anchore feed
	LatestURL string
	// TimestampStore is used to persist the last known grype DB timestamp
	// This enables reliable change detection across process restarts
	TimestampStore TimestampStore
}

// NewDatabaseUpdater creates a new database updater
// dbRootDir is the root directory where grype stores its database (e.g., /var/lib/bjorn2scan)
func NewDatabaseUpdater(dbRootDir string) (*DatabaseUpdater, error) {
	return NewDatabaseUpdaterWithConfig(dbRootDir, DatabaseUpdaterConfig{})
}

// NewDatabaseUpdaterWithConfig creates a new database updater with custom configuration
func NewDatabaseUpdaterWithConfig(dbRootDir string, cfg DatabaseUpdaterConfig) (*DatabaseUpdater, error) {
	if dbRootDir == "" {
		return nil, fmt.Errorf("dbRootDir cannot be empty")
	}

	// Ensure directory exists
	grypeDir := filepath.Join(dbRootDir, "grype")
	if err := os.MkdirAll(grypeDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create grype directory: %w", err)
	}

	identification := clio.Identification{
		Name:    "bjorn2scan-grype",
		Version: "1.0.0",
	}

	distCfg := distribution.DefaultConfig()
	distCfg.ID = identification
	if cfg.LatestURL != "" {
		distCfg.LatestURL = cfg.LatestURL
	}

	installCfg := installation.DefaultConfig(identification)
	installCfg.DBRootDir = grypeDir

	return &DatabaseUpdater{
		dbRootDir:      dbRootDir,
		distCfg:        distCfg,
		installCfg:     installCfg,
		loader:         defaultDatabaseLoader,
		timestampStore: cfg.TimestampStore,
	}, nil
}

// SetTimestampStore sets the timestamp store for persistent tracking
func (du *DatabaseUpdater) SetTimestampStore(store TimestampStore) {
	du.timestampStore = store
}

// SetLoader sets a custom database loader (for testing)
func (du *DatabaseUpdater) SetLoader(loader DatabaseLoader) {
	du.loader = loader
}

// SetDescriptionReader sets a custom description reader (for testing)
// This allows tests to mock the actual database file timestamp
func (du *DatabaseUpdater) SetDescriptionReader(reader DescriptionReader) {
	du.descriptionReader = reader
}

// GetCurrentVersion returns the current database version from memory (thread-safe)
// Returns nil if no database has been loaded yet
func (du *DatabaseUpdater) GetCurrentVersion() *DatabaseStatus {
	du.mu.RLock()
	defer du.mu.RUnlock()
	if du.currentVersion == nil {
		return nil
	}
	// Return a copy to avoid race conditions
	return &DatabaseStatus{
		Built:         du.currentVersion.Built,
		SchemaVersion: du.currentVersion.SchemaVersion,
		Path:          du.currentVersion.Path,
	}
}

// CheckForUpdates checks if the vulnerability database has been updated
// Returns: (hasChanged bool, error)
// - If no database exists, downloads one and returns (false, nil) - nothing to rescan yet
// - If database exists and gets updated, returns (true, nil)
// - If database exists and no update available, returns (false, nil)
func (du *DatabaseUpdater) CheckForUpdates(ctx context.Context) (bool, error) {
	du.mu.Lock()
	defer du.mu.Unlock()

	log.Info("checking for vulnerability database updates")

	grypeDir := filepath.Join(du.dbRootDir, "grype")
	dbPath := filepath.Join(grypeDir, "6", "vulnerability.db")

	// 1. Get the last known timestamp from persistent storage
	// This is more reliable than reading from the grype library which may cache stale values
	var lastKnownTimestamp time.Time
	if du.timestampStore != nil {
		if t, err := du.timestampStore.LoadGrypeDBTimestamp(); err == nil && !t.IsZero() {
			lastKnownTimestamp = t
			log.Debug("loaded last known database timestamp from persistent store",
				"timestamp", lastKnownTimestamp.Format(time.RFC3339))
		} else if err != nil {
			log.Warn("failed to load last known timestamp", "error", err)
		}
	}

	// 2. Check if database file exists
	dbExisted := false
	if _, err := os.Stat(dbPath); err == nil {
		dbExisted = true
	} else {
		log.Info("no existing database found, will download")
	}

	// 3. Load/download the database
	startTime := time.Now()

	// Progress indicator for long downloads
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				elapsed := time.Since(startTime).Round(time.Second)
				log.Debug("still updating database",
					"elapsed", elapsed)
			}
		}
	}()

	dbStatus, loaderErr := du.loader(du.distCfg, du.installCfg, true)
	close(done)

	// Trust the on-disk DB as the source of truth. grype's LoadVulnerabilityDB
	// can return errors (e.g. its post-update validateAge in Status() returning a
	// stale timestamp) AFTER successfully downloading and activating a fresh DB.
	// Don't delete the schema dir on error — that throws away grype's good work.
	// Instead, read the file on disk and accept it if it's usable.
	actualBuilt, diskErr := du.readOnDiskBuilt(dbPath)

	switch {
	case loaderErr == nil && diskErr == nil:
		// Both succeeded; prefer disk timestamp (it's the authoritative source).
	case loaderErr == nil && diskErr != nil:
		// Loader succeeded, disk read failed (e.g. unit test with mock path);
		// fall back to the loader-reported timestamp.
		log.Debug("on-disk read failed, falling back to loader timestamp", "error", diskErr)
		actualBuilt = dbStatus.Built
	case loaderErr != nil && diskErr == nil:
		// Loader complained but the file on disk is readable. Trust the disk.
		log.Warn("loader returned error but on-disk DB is readable, accepting it",
			"error", loaderErr,
			"actual_built", actualBuilt.Format(time.RFC3339))
	default:
		// Both failed — genuine failure.
		return false, fmt.Errorf("failed to update vulnerability database: %w (also unable to read on-disk DB: %v)", loaderErr, diskErr)
	}

	if dbStatus == nil {
		// Synthesise dbStatus from on-disk metadata when loader didn't produce one.
		dbStatus = &DatabaseStatus{
			Built: actualBuilt,
			Path:  dbPath,
		}
	}

	log.Debug("database loaded",
		"loader_built", dbStatus.Built.Format(time.RFC3339),
		"actual_built", actualBuilt.Format(time.RFC3339),
		"schema", dbStatus.SchemaVersion,
		"duration", time.Since(startTime).Round(time.Millisecond))

	// Store current version in memory for metrics (using actual on-disk timestamp
	// when available, loader timestamp as fallback).
	du.currentVersion = &DatabaseStatus{
		Built:         actualBuilt,
		SchemaVersion: dbStatus.SchemaVersion,
		Path:          dbStatus.Path,
	}

	log.Info("database ready",
		"built", actualBuilt.Format(time.RFC3339),
		"schema", dbStatus.SchemaVersion)

	// 5. Determine if database changed by comparing against persistent timestamp
	// This is more reliable than comparing against in-memory values which may be stale
	var hasChanged bool
	if !dbExisted && lastKnownTimestamp.IsZero() {
		// First run - database was just downloaded, nothing to rescan yet
		log.Info("initial database download complete, no rescan needed")
		hasChanged = false
	} else if lastKnownTimestamp.IsZero() {
		// Database existed but we have no persistent record - this is a migration scenario
		// Don't trigger rescan, just record the current timestamp
		log.Info("no persistent timestamp record, initializing tracking")
		hasChanged = false
	} else {
		// Compare actual timestamp against persisted last known timestamp
		hasChanged = !actualBuilt.Equal(lastKnownTimestamp)
		if hasChanged {
			log.Info("database updated",
				"previous", lastKnownTimestamp.Format(time.RFC3339),
				"current", actualBuilt.Format(time.RFC3339))
		} else {
			log.Debug("no database changes (persistent comparison)")
		}
	}

	// 6. Save the current timestamp to persistent storage
	if du.timestampStore != nil {
		if err := du.timestampStore.SaveGrypeDBTimestamp(actualBuilt); err != nil {
			log.Warn("failed to save timestamp to persistent store", "error", err)
		} else {
			log.Debug("saved database timestamp to persistent store",
				"timestamp", actualBuilt.Format(time.RFC3339))
		}
	}

	return hasChanged, nil
}

// GetCurrentStatus returns the current database status without triggering an update
// Note: Prefer GetCurrentVersion() for quick in-memory access
func (du *DatabaseUpdater) GetCurrentStatus(ctx context.Context) (*DatabaseStatus, error) {
	du.mu.Lock()
	defer du.mu.Unlock()

	dbStatus, err := du.loader(du.distCfg, du.installCfg, false)
	if err != nil {
		return nil, fmt.Errorf("failed to load database status: %w", err)
	}

	// Also update in-memory version
	du.currentVersion = dbStatus

	return dbStatus, nil
}
