package grype

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/logging"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dotnet"
	"github.com/anchore/grype/grype/matcher/golang"
	"github.com/anchore/grype/grype/matcher/java"
	"github.com/anchore/grype/grype/matcher/javascript"
	"github.com/anchore/grype/grype/matcher/python"
	"github.com/anchore/grype/grype/matcher/ruby"
	"github.com/anchore/grype/grype/matcher/rust"
	"github.com/anchore/grype/grype/matcher/stock"
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/grype/grype/vulnerability"
)

var log = logging.For(logging.ComponentGrype)

// Config holds configuration for the Grype scanner
type Config struct {
	// DBRootDir is the root directory where Grype stores its vulnerability database
	// If empty, uses the default location (~/.cache/grype/db)
	DBRootDir string
}

// logDirectoryContents logs the contents of a directory for debugging
func logDirectoryContents(dir string, phase string) {
	log := log
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			log.Debug("directory does not exist", "phase", phase, "dir", dir)
		} else {
			log.Error("failed to read directory", "phase", phase, "dir", dir, slog.Any("error", err))
		}
		return
	}

	if len(entries) == 0 {
		log.Debug("directory is empty", "phase", phase, "dir", dir)
		return
	}

	log.Debug("directory contents", "phase", phase, "dir", dir, "entries", len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			log.Debug("entry info error", "phase", phase, "name", entry.Name(), slog.Any("error", err))
			continue
		}
		if info.IsDir() {
			log.Debug("directory entry", "phase", phase, "name", entry.Name()+"/")
		} else {
			log.Debug("file entry", "phase", phase, "name", entry.Name(), "size", info.Size())
		}
	}
}

// DatabaseStatus represents the current state of the vulnerability database
type DatabaseStatus struct {
	Available     bool      `json:"available"`
	Built         time.Time `json:"built,omitempty"`
	SchemaVersion string    `json:"schema_version,omitempty"`
	Path          string    `json:"path,omitempty"`
	Error         string    `json:"error,omitempty"`
}

// ScanResult contains the results of a vulnerability scan
type ScanResult struct {
	VulnerabilityJSON []byte         // The raw vulnerability scan JSON output
	DBStatus          DatabaseStatus // Information about the vulnerability database used
}

// InitializeDatabase ensures the vulnerability database is downloaded and ready.
// This should be called at startup before accepting scan requests.
// Returns the database status and any error encountered.
func InitializeDatabase(cfg Config) (*DatabaseStatus, error) {
	log := log
	log.Info("initializing vulnerability database")

	identification := clio.Identification{
		Name:    "bjorn2scan-grype",
		Version: "1.0.0",
	}
	distCfg := distribution.DefaultConfig()
	distCfg.ID = identification

	installCfg := installation.DefaultConfig(identification)

	if cfg.DBRootDir != "" {
		dbDir := filepath.Join(cfg.DBRootDir, "grype")
		if err := os.MkdirAll(dbDir, 0755); err != nil {
			return &DatabaseStatus{Available: false, Error: err.Error()},
				fmt.Errorf("failed to create database directory %s: %w", dbDir, err)
		}
		installCfg.DBRootDir = dbDir
		log.Info("using database directory", "dir", dbDir)
	}

	// Log directory contents before initialization
	logDirectoryContents(installCfg.DBRootDir, "init-pre")

	log.Info("loading/downloading vulnerability database")
	startTime := time.Now()

	// Progress indicator
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				elapsed := time.Since(startTime).Round(time.Second)
				log.Info("still initializing database", "elapsed", elapsed)
			}
		}
	}()

	_, dbStatus, err := grype.LoadVulnerabilityDB(distCfg, installCfg, true)
	close(done)

	loadDuration := time.Since(startTime).Round(time.Millisecond)

	// Trust-the-disk fallback (mirrors database_updater.go): grype's Status()
	// can return "the vulnerability database was built 1 week ago" even when
	// the file on disk is fresh. If we can read a build_timestamp from disk,
	// accept it as authoritative.
	if err != nil {
		dbFile := filepath.Join(installCfg.DBRootDir, "6", "vulnerability.db")
		if actualBuilt, diskErr := readActualDBTimestamp(dbFile); diskErr == nil {
			log.Warn("loader returned error but on-disk DB is readable, accepting it",
				"error", err, "actual_built", actualBuilt)
			logDirectoryContents(installCfg.DBRootDir, "init-post")
			return &DatabaseStatus{Available: true, Path: dbFile, Built: actualBuilt}, nil
		}
		log.Error("failed to initialize database", "duration", loadDuration, slog.Any("error", err))
		logDirectoryContents(installCfg.DBRootDir, "init-fail")

		status := &DatabaseStatus{Available: false, Error: err.Error()}
		if dbStatus != nil {
			status.Path = dbStatus.Path
		}
		return status, fmt.Errorf("failed to initialize vulnerability database: %w", err)
	}

	log.Info("database initialized successfully", "duration", loadDuration)
	logDirectoryContents(installCfg.DBRootDir, "init-post")

	status := &DatabaseStatus{
		Available:     true,
		SchemaVersion: dbStatus.SchemaVersion,
		Path:          dbStatus.Path,
		Built:         dbStatus.Built,
	}

	log.Info("database ready", "schema", status.SchemaVersion, "built", status.Built)
	return status, nil
}

// CheckDatabase verifies the vulnerability database is available and valid.
// This is a lightweight check suitable for readiness probes.
func CheckDatabase(cfg Config) (*DatabaseStatus, error) {
	dbDir := cfg.DBRootDir
	if dbDir != "" {
		dbDir = filepath.Join(dbDir, "grype")
	} else {
		// Default grype location
		homeDir, _ := os.UserHomeDir()
		dbDir = filepath.Join(homeDir, ".cache", "grype", "db")
	}

	// Check if the database directory exists and has files
	entries, err := os.ReadDir(dbDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &DatabaseStatus{Available: false, Error: "database directory does not exist"}, nil
		}
		return &DatabaseStatus{Available: false, Error: err.Error()}, err
	}

	if len(entries) == 0 {
		return &DatabaseStatus{Available: false, Error: "database directory is empty"}, nil
	}

	// Look for the vulnerability database file
	// Grype v6 uses a schema version subdirectory structure: /grype/6/vulnerability.db
	// Older versions may have the .db file directly in the grype directory
	hasDB := false
	var dbPath string
	for _, entry := range entries {
		// Check for direct .db file (older grype versions)
		if entry.Name() == "vulnerability.db" || entry.Name() == "vulnerability-db" {
			hasDB = true
			dbPath = filepath.Join(dbDir, entry.Name())
			break
		}
		if filepath.Ext(entry.Name()) == ".db" {
			hasDB = true
			dbPath = filepath.Join(dbDir, entry.Name())
			break
		}
		// Check for schema version subdirectory (grype v6+)
		// Schema directories are numeric (e.g., "5", "6")
		if entry.IsDir() && isNumericDir(entry.Name()) {
			schemaDir := filepath.Join(dbDir, entry.Name())
			vulnDBPath := filepath.Join(schemaDir, "vulnerability.db")
			if _, err := os.Stat(vulnDBPath); err == nil {
				hasDB = true
				dbPath = vulnDBPath
				break
			}
		}
	}

	if !hasDB {
		return &DatabaseStatus{Available: false, Error: "database does not exist", Path: dbDir}, nil
	}

	return &DatabaseStatus{Available: true, Path: dbPath}, nil
}

// isNumericDir checks if a directory name is numeric (schema version like "5", "6")
func isNumericDir(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// DeleteDatabase removes the vulnerability database, forcing a re-download on next use.
// This is useful for testing database initialization.
func DeleteDatabase(cfg Config) error {
	log := log
	dbDir := cfg.DBRootDir
	if dbDir != "" {
		dbDir = filepath.Join(dbDir, "grype")
	} else {
		homeDir, _ := os.UserHomeDir()
		dbDir = filepath.Join(homeDir, ".cache", "grype", "db")
	}

	log.Info("deleting database directory", "dir", dbDir)

	// Log contents before deletion
	logDirectoryContents(dbDir, "delete-pre")

	if err := os.RemoveAll(dbDir); err != nil {
		return fmt.Errorf("failed to delete database directory: %w", err)
	}

	log.Info("database directory deleted successfully")
	return nil
}

// DefaultMatcherConfig returns the default matcher configuration that aligns with Grype CLI defaults
// This configuration is based on Grype v0.104.2 defaults and should be updated when Grype is upgraded
//
// Reference: https://github.com/anchore/grype
// To check current Grype defaults, run: grype <image> -o json | jq .descriptor.configuration.match
func DefaultMatcherConfig() matcher.Config {
	return matcher.Config{
		// Golang configuration - Critical for Go applications
		Golang: golang.MatcherConfig{
			UseCPEs: false, // Use direct matching via PURLs for Go modules
			// CRITICAL: Enable CPE matching for Go stdlib to catch standard library CVEs
			// Without this, stdlib vulnerabilities (often High/Critical severity) are missed
			AlwaysUseCPEForStdlib:                  true,
			AllowMainModulePseudoVersionComparison: false,
		},
		// Stock configuration - Generic package matching
		Stock: stock.MatcherConfig{
			UseCPEs: true, // Use CPE matching for packages without language-specific matchers
		},
		// Language-specific matchers - Use native package matching (not CPEs) by default
		// These rely on package URLs (PURLs) and native version comparisons which are more accurate
		Java: java.MatcherConfig{
			UseCPEs: false,
			ExternalSearchConfig: java.ExternalSearchConfig{
				SearchMavenUpstream: false, // Disabled by default - enable if needed for unknown Java deps
			},
		},
		Dotnet:     dotnet.MatcherConfig{UseCPEs: false},
		Javascript: javascript.MatcherConfig{UseCPEs: false},
		Python:     python.MatcherConfig{UseCPEs: false},
		Ruby:       ruby.MatcherConfig{UseCPEs: false},
		Rust:       rust.MatcherConfig{UseCPEs: false},
	}
}

// ScanVulnerabilities scans an SBOM for vulnerabilities using Grype library
// Takes SBOM JSON bytes as input and returns scan result with vulnerability report and DB info
func ScanVulnerabilities(ctx context.Context, sbomJSON []byte) (*ScanResult, error) {
	return ScanVulnerabilitiesWithConfig(ctx, sbomJSON, Config{})
}

// ScanVulnerabilitiesWithConfig scans an SBOM for vulnerabilities using Grype library with custom configuration
// Returns a ScanResult containing both the vulnerability JSON and information about the database used
func ScanVulnerabilitiesWithConfig(ctx context.Context, sbomJSON []byte, cfg Config) (*ScanResult, error) {
	log := log
	log.Debug("starting vulnerability scan", "sbom_size", len(sbomJSON))

	// Write SBOM to temp file so we can use Grype's Provide function
	// This ensures we get all the proper processing (distro, relationships, etc.)
	tmpFile, err := os.CreateTemp("", "sbom-*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
	}()

	if _, err := tmpFile.Write(sbomJSON); err != nil {
		return nil, fmt.Errorf("failed to write SBOM to temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return nil, fmt.Errorf("failed to close temp file: %w", err)
	}

	log.Debug("using grype SBOM provider for complete processing")

	// Configure the vulnerability database location
	identification := clio.Identification{
		Name:    "bjorn2scan-grype",
		Version: "1.0.0",
	}
	distCfg := distribution.DefaultConfig()
	distCfg.ID = identification

	installCfg := installation.DefaultConfig(identification)

	if cfg.DBRootDir != "" {
		// Ensure the directory exists
		dbDir := filepath.Join(cfg.DBRootDir, "grype")
		if err := os.MkdirAll(dbDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create database directory %s: %w", dbDir, err)
		}
		installCfg.DBRootDir = dbDir
		log.Debug("using grype database directory", "dir", dbDir)
	}

	// Build the vulnerability provider directly from the on-disk DB, bypassing
	// grype.LoadVulnerabilityDB. That high-level helper unconditionally calls
	// c.Status() which runs validateAge against the on-disk metadata and aborts
	// with "the vulnerability database was built N ago" — a known issue that
	// also bit us in database_updater.go (commit 3a64d3d).
	//
	// We don't care about validateAge on the per-scan path:
	//   - DB freshness is the rescan-database job's responsibility, and that
	//     job has its own trust-the-disk fallback. If the DB is too stale to
	//     be useful operationally, that job (not per-scan errors) is the
	//     surface that should escalate.
	//   - Failing scans because grype thinks the on-disk DB is "5 days old"
	//     when we just verified it's fresh creates a vuln_scan_failed cascade.
	//
	// Curator.Reader() only requires the DB to exist on disk (it checks for
	// ErrDBDoesNotExist); it does NOT run validateAge. v6.NewVulnerabilityProvider
	// wraps the Reader. This is exactly what LoadVulnerabilityDB does internally
	// after Status() passes — we just skip Status().
	log.Debug("checking vulnerability database status")
	log.Debug("database config", "db_root", installCfg.DBRootDir, "latest_url", distCfg.LatestURL)

	logDirectoryContents(installCfg.DBRootDir, "db-pre")

	log.Debug("loading vulnerability database (bypassing validateAge)")
	startTime := time.Now()

	distClient, err := distribution.NewClient(distCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create distribution client: %w", err)
	}
	curator, err := installation.NewCurator(installCfg, distClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create curator: %w", err)
	}
	rdr, err := curator.Reader()
	if err != nil {
		log.Error("failed to open vulnerability database reader", "duration", time.Since(startTime).Round(time.Millisecond), slog.Any("error", err))
		logDirectoryContents(installCfg.DBRootDir, "db-post-fail")
		return nil, fmt.Errorf("failed to load vulnerability database: %w", err)
	}
	vulnProvider := v6.NewVulnerabilityProvider(rdr)

	// Synthesise dbStatus from the on-disk metadata so we still report what
	// version was used for the scan (matches the shape LoadVulnerabilityDB
	// would have returned, minus the Status validation).
	dbFile := filepath.Join(installCfg.DBRootDir, "6", "vulnerability.db")
	actualBuilt, _ := readActualDBTimestamp(dbFile)
	dbStatus := &vulnerability.ProviderStatus{
		Built: actualBuilt,
		Path:  dbFile,
	}

	loadDuration := time.Since(startTime).Round(time.Millisecond)

	log.Info("loaded vulnerability database successfully", "duration", loadDuration)
	log.Debug("database status",
		"built", dbStatus.Built,
		"schema", dbStatus.SchemaVersion,
		"from", dbStatus.From)

	// Log directory contents after successful load
	logDirectoryContents(installCfg.DBRootDir, "db-post")

	// dbStatus.Built was populated above from readActualDBTimestamp; no need to re-read.

	// Use Grype's Provide function to get packages and context with proper processing
	// This handles distro extraction, relationship processing, and package filtering
	providerConfig := grypePkg.ProviderConfig{}
	packages, context, _, err := grypePkg.Provide("sbom:"+tmpFile.Name(), providerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to provide packages from SBOM: %w", err)
	}

	log.Debug("scanning packages for vulnerabilities", "packages", len(packages))
	if len(packages) > 0 {
		log.Debug("sample package", "purl", packages[0].PURL)
		if context.Distro != nil {
			log.Debug("context distro", "distro", context.Distro.String())
		}
	}

	// Create vulnerability matcher with all default matchers (dpkg, rpm, apk, etc.)
	// Use DefaultMatcherConfig() to ensure we match Grype CLI defaults
	// Enable EOL distro warnings to maintain parity with upstream grype CLI
	vulnerabilityMatcher := grype.VulnerabilityMatcher{
		VulnerabilityProvider: vulnProvider,
		Matchers:              matcher.NewDefaultMatchers(DefaultMatcherConfig()),
		Alerts: grype.AlertsConfig{
			EnableEOLDistroWarnings: true,
		},
	}

	// Find vulnerability matches
	remainingMatches, ignoredMatches, err := vulnerabilityMatcher.FindMatches(packages, context)
	if err != nil {
		return nil, fmt.Errorf("failed to find vulnerabilities: %w", err)
	}

	if remainingMatches == nil {
		return nil, fmt.Errorf("vulnerability matches are nil")
	}

	log.Debug("vulnerability scan complete",
		"matches", remainingMatches.Count(),
		"ignored", len(ignoredMatches))

	// Collect EOL distro packages for alerting (maintains parity with grype CLI)
	eolPackages := vulnerabilityMatcher.EOLDistroPackages()
	var distroAlertData *models.DistroAlertData
	if len(eolPackages) > 0 {
		log.Info("detected packages from EOL distribution", "eol_packages", len(eolPackages))
		distroAlertData = &models.DistroAlertData{
			EOLDistroPackages: eolPackages,
		}
	}

	// Build database info for the output document
	dbInfo := buildDBInfo(dbStatus, vulnProvider)

	// Build the output document using NewDocument
	doc, err := models.NewDocument(
		identification,         // clio.Identification
		packages,               // packages
		context,                // context
		*remainingMatches,      // matches
		ignoredMatches,         // ignoredMatches
		vulnProvider,           // metadataProvider
		nil,                    // appConfig
		dbInfo,                 // dbInfo
		models.SortBySeverity,  // sortStrategy
		false,                  // outputTimestamp
		distroAlertData,        // distroAlertData (EOL warnings for upstream grype parity)
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create document: %w", err)
	}

	// Encode to JSON
	reportJSON, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to encode vulnerability report to JSON: %w", err)
	}

	log.Debug("vulnerability scan complete", "report_size", len(reportJSON))

	// Build result with vulnerability JSON and DB status
	result := &ScanResult{
		VulnerabilityJSON: reportJSON,
		DBStatus: DatabaseStatus{
			Available:     true,
			Built:         dbStatus.Built,
			SchemaVersion: dbStatus.SchemaVersion,
			Path:          dbStatus.Path,
		},
	}

	return result, nil
}

// buildDBInfo constructs database metadata for inclusion in the vulnerability report.
// This matches the format used by the grype CLI for consistency.
func buildDBInfo(status *vulnerability.ProviderStatus, vp vulnerability.Provider) any {
	var providers map[string]vulnerability.DataProvenance

	if vp != nil {
		providers = make(map[string]vulnerability.DataProvenance)
		if dpr, ok := vp.(vulnerability.StoreMetadataProvider); ok {
			dps, err := dpr.DataProvenance()
			if err == nil {
				providers = dps
			}
		}
	}

	return struct {
		Status    *vulnerability.ProviderStatus           `json:"status"`
		Providers map[string]vulnerability.DataProvenance `json:"providers"`
	}{
		Status:    status,
		Providers: providers,
	}
}

// readActualDBTimestamp reads the database build timestamp directly from the grype
// SQLite database file. This is necessary because grype.LoadVulnerabilityDB may
// return a cached/stale timestamp that doesn't reflect the actual database on disk.
func readActualDBTimestamp(dbPath string) (time.Time, error) {
	// The database path from grype points to the directory, we need the actual db file
	dbFile := dbPath
	if info, err := os.Stat(dbPath); err == nil && info.IsDir() {
		dbFile = filepath.Join(dbPath, "vulnerability.db")
	}

	db, err := sql.Open("sqlite", dbFile+"?mode=ro")
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
	formats := []string{
		time.RFC3339,
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05+00:00",
	}

	var t time.Time
	var parseErr error
	for _, format := range formats {
		t, parseErr = time.Parse(format, builtStr)
		if parseErr == nil {
			break
		}
	}
	if parseErr != nil {
		return time.Time{}, fmt.Errorf("failed to parse timestamp %q: %w", builtStr, parseErr)
	}

	return t.UTC(), nil
}
