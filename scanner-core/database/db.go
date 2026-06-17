package database

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/logging"
)

var log = logging.For(logging.ComponentDatabase)

// DB wraps the database connection.
// writeMu serializes all write transactions at the Go level so that SQLite
// never receives a concurrent write and SQLITE_BUSY is impossible.
// cachesMu protects in-memory caches that eliminate read queries on hot paths.
type DB struct {
	writeMu sync.Mutex
	conn    *sql.DB

	// in-memory caches — updated by notifyWrite() after every successful write
	cachesMu       sync.RWMutex
	lastUpdatedSig string             // change-detection signature for /api/lastupdated
	filterOpts     *FilterOptions     // nil = stale; populated on demand
	nodeFilterOpts *NodeFilterOptions // nil = stale; populated on demand

	// nodeVulnRows caches the full node_vulnerabilities result set for /metrics.
	// Rebuilt asynchronously after StoreNodeVulnerabilities and on a 30-minute TTL.
	// nil = cold (not yet built or invalidated); non-nil = ready to serve.
	nodeVulnRows     []NodeVulnerabilityForMetrics
	nodeVulnBuilding atomic.Bool // true while a rebuild is in progress

	// containerVulnRows caches the full container × image_vulnerabilities join used
	// by the bjorn2scan_image_vulnerability* metric families. Rebuilt asynchronously
	// after StoreImageVulnerabilities, SetContainers, CleanupOrphanedImages and on a
	// 30-minute TTL safety net. add_container/remove_container do NOT trigger rebuilds
	// (too frequent: ~5k/5d on kubeadm); the TTL bounds staleness instead.
	containerVulnRows     []ContainerVulnerability
	containerVulnBuilding atomic.Bool
}

// StartNodeVulnCacheRefresh warms the node vulnerability cache immediately and
// then refreshes it every 30 minutes as a safety net. Should be called once at
// startup, after the database is initialised. The primary invalidation path is
// StoreNodeVulnerabilities, which triggers a rebuild after each node scan.
func (db *DB) StartNodeVulnCacheRefresh(ctx context.Context) {
	go func() {
		db.rebuildNodeVulnCache()
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				db.rebuildNodeVulnCache()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// rebuildNodeVulnCache reads all node vulnerability rows from the DB and
// atomically replaces the in-memory cache. The old cache continues to serve
// callers until the rebuild completes. CompareAndSwap prevents concurrent
// rebuilds from stacking up.
func (db *DB) rebuildNodeVulnCache() {
	if !db.nodeVulnBuilding.CompareAndSwap(false, true) {
		return // rebuild already in progress
	}
	defer db.nodeVulnBuilding.Store(false)

	start := time.Now()
	rows := make([]NodeVulnerabilityForMetrics, 0, 10000)
	if err := db.readNodeVulnsFromDB(func(v NodeVulnerabilityForMetrics) error {
		rows = append(rows, v)
		return nil
	}); err != nil {
		log.Error("node vuln cache rebuild failed", slog.Any("error", err))
		return
	}

	db.cachesMu.Lock()
	db.nodeVulnRows = rows
	db.cachesMu.Unlock()
	log.Debug("node vuln cache rebuilt", "rows", len(rows), "duration", time.Since(start).Round(time.Millisecond))
}

// StartContainerVulnCacheRefresh warms the container vulnerability cache immediately
// and refreshes it every 30 minutes as a safety net. Should be called once at
// startup, after the database is initialised. The primary invalidation paths are
// StoreImageVulnerabilities, SetContainers, and CleanupOrphanedImages.
func (db *DB) StartContainerVulnCacheRefresh(ctx context.Context) {
	go func() {
		db.rebuildContainerVulnCache()
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				db.rebuildContainerVulnCache()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// rebuildContainerVulnCache reads all container × image_vulnerability rows from
// the DB and atomically replaces the in-memory cache. The old cache continues to
// serve callers until the rebuild completes. CompareAndSwap prevents concurrent
// rebuilds from stacking up.
func (db *DB) rebuildContainerVulnCache() {
	if !db.containerVulnBuilding.CompareAndSwap(false, true) {
		return // rebuild already in progress
	}
	defer db.containerVulnBuilding.Store(false)

	start := time.Now()
	rows := make([]ContainerVulnerability, 0, 10000)
	if err := db.readContainerVulnsFromDB(func(v ContainerVulnerability) error {
		rows = append(rows, v)
		return nil
	}); err != nil {
		log.Error("container vuln cache rebuild failed", slog.Any("error", err))
		return
	}

	db.cachesMu.Lock()
	db.containerVulnRows = rows
	db.cachesMu.Unlock()
	log.Debug("container vuln cache rebuilt", "rows", len(rows), "duration", time.Since(start).Round(time.Millisecond))
}

// notifyWrite updates the in-memory last-updated signature and invalidates
// filter-option caches. Must be called after every successful write operation.
func (db *DB) notifyWrite() {
	db.cachesMu.Lock()
	db.lastUpdatedSig = time.Now().UTC().Format(time.RFC3339Nano)
	db.filterOpts = nil
	db.nodeFilterOpts = nil
	db.cachesMu.Unlock()
}

// seedLastUpdated reads the current last-updated signature from the DB once
// so that the in-memory cache is non-empty before any write occurs on this run.
func (db *DB) seedLastUpdated() {
	var sig sql.NullString
	_ = db.conn.QueryRow(`
		SELECT CASE WHEN COUNT(*) = 0 THEN NULL
			ELSE MAX(updated_at) || '|' || (SELECT COUNT(*) FROM containers)
		END FROM images
	`).Scan(&sig)
	if sig.Valid && sig.String != "" {
		db.cachesMu.Lock()
		db.lastUpdatedSig = sig.String
		db.cachesMu.Unlock()
	}
}

// GetConnection returns the underlying database connection (for testing)
func (db *DB) GetConnection() *sql.DB {
	return db.conn
}

// isCorruptionError checks if an error indicates database corruption or an
// unrecoverable I/O error on open (e.g. SQLITE_IOERR_SHMSIZE when a stale
// -shm file is left on the volume after a pod replacement).
func isCorruptionError(err error) bool {
	if err == nil {
		return false
	}
	errMsg := strings.ToLower(err.Error())
	return strings.Contains(errMsg, "malformed") ||
		strings.Contains(errMsg, "corrupt") ||
		strings.Contains(errMsg, "database disk image is malformed") ||
		strings.Contains(errMsg, "disk i/o error")
}

// exitOnCorruption exits the process when a corruption error is detected during a
// write operation. The pod will be restarted by Kubernetes, and the startup integrity
// check in New() will delete the corrupt database and reinitialize from scratch.
func exitOnCorruption(err error) {
	if isCorruptionError(err) {
		log.Error("fatal: database corruption detected during write, exiting for pod restart", slog.Any("error", err))
		os.Exit(1)
	}
}

// deleteDatabase deletes the database file and associated files (WAL, SHM)
func deleteDatabase(dbPath string) error {
	log.Info("deleting database files", "path", dbPath)

	// Delete main database file
	if err := os.Remove(dbPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete database file: %w", err)
	}

	// Delete WAL file if exists
	walPath := dbPath + "-wal"
	if err := os.Remove(walPath); err != nil && !os.IsNotExist(err) {
		log.Warn("failed to delete WAL file", slog.Any("error", err))
	}

	// Delete SHM file if exists
	shmPath := dbPath + "-shm"
	if err := os.Remove(shmPath); err != nil && !os.IsNotExist(err) {
		log.Warn("failed to delete SHM file", slog.Any("error", err))
	}

	log.Info("database files deleted, will create fresh database")
	return nil
}

// New creates a new database connection
// If the database is corrupted, it will be deleted and recreated
func New(dbPath string) (*DB, error) {
	// Try to open the database
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection and check for corruption
	if err := conn.Ping(); err != nil {
		_ = conn.Close()

		// Check if it's a corruption error
		if isCorruptionError(err) {
			log.Error("database corruption detected", slog.Any("error", err))
			log.Info("deleting corrupted database and starting fresh")
			if err := deleteDatabase(dbPath); err != nil {
				return nil, fmt.Errorf("failed to delete corrupted database: %w", err)
			}

			// Try again with fresh database
			conn, err = sql.Open("sqlite", dbPath)
			if err != nil {
				return nil, fmt.Errorf("failed to create new database: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to ping database: %w", err)
		}
	}

	// Configure connection pool for SQLite.
	// 5 connections: writes are serialized by writeMu so extra connections only add
	// read parallelism, which WAL mode handles correctly. This ensures the health
	// check and WAL monitor always have a free slot even during concurrent reads + writes.
	conn.SetMaxOpenConns(5)
	conn.SetMaxIdleConns(5)

	// Configure SQLite for better concurrency
	_, err = conn.Exec(`
		PRAGMA journal_mode = WAL;
		PRAGMA busy_timeout = 30000;
		PRAGMA synchronous = NORMAL;
	`)
	if err != nil {
		_ = conn.Close()

		// If configuration fails due to corruption, delete and recreate
		if isCorruptionError(err) {
			log.Error("database corruption detected during configuration", slog.Any("error", err))
			log.Info("deleting corrupted database and starting fresh")
			if err := deleteDatabase(dbPath); err != nil {
				return nil, fmt.Errorf("failed to delete corrupted database: %w", err)
			}
			return New(dbPath) // Recursive call with fresh database
		}

		return nil, fmt.Errorf("failed to configure database: %w", err)
	}

	db := &DB{conn: conn}

	// Checkpoint WAL on startup to merge any writes from before an unclean shutdown
	// (e.g. OOM kill). Without this the WAL can grow to the same size as the main DB
	// and every query must replay the entire WAL, causing severe slowdowns.
	// TRUNCATE resets the WAL to zero bytes after checkpointing.
	// Safe at startup: the previous pod is dead so no other writer is active.
	var walBusy, walLog, walCheckpointed int
	if err := conn.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&walBusy, &walLog, &walCheckpointed); err != nil {
		log.Warn("startup WAL checkpoint failed", slog.Any("error", err))
	} else if walLog > 0 {
		log.Info("startup WAL checkpoint complete", "wal_frames", walLog, "checkpointed", walCheckpointed, "busy", walBusy == 1)
	}

	// Run quick_check only when the WAL had unmerged frames at startup, which indicates
	// an unclean shutdown (OOM kill, SIGKILL). On a clean shutdown Close() checkpoints
	// and truncates the WAL, so walLog == 0 means the previous run exited gracefully and
	// corruption is extremely unlikely. Skipping quick_check on clean restarts avoids a
	// multi-minute scan of large databases on slow storage (e.g. NFS).
	if walLog > 0 {
		log.Info("unclean shutdown detected (WAL had frames), running integrity check")
		var quickCheckResult string
		if err := conn.QueryRow("PRAGMA quick_check").Scan(&quickCheckResult); err != nil || quickCheckResult != "ok" {
			_ = conn.Close()
			log.Error("database failed integrity check after unclean shutdown, deleting and starting fresh",
				"result", quickCheckResult, slog.Any("error", err))
			if err := deleteDatabase(dbPath); err != nil {
				return nil, fmt.Errorf("failed to delete corrupted database: %w", err)
			}
			return New(dbPath)
		}
		log.Info("integrity check passed")
	}

	// Run migrations to ensure schema is up to date
	if err := db.ensureSchemaVersion(); err != nil {
		_ = conn.Close()

		// If migration fails due to corruption, delete and recreate
		if isCorruptionError(err) {
			log.Error("database corruption detected during migration", slog.Any("error", err))
			log.Info("deleting corrupted database and starting fresh")
			if err := deleteDatabase(dbPath); err != nil {
				return nil, fmt.Errorf("failed to delete corrupted database: %w", err)
			}
			return New(dbPath) // Recursive call with fresh database
		}

		return nil, fmt.Errorf("failed to migrate schema: %w", err)
	}

	// Seed the lastUpdated cache from DB so /api/lastupdated returns a non-empty
	// value immediately, without hitting the DB on every poll.
	db.seedLastUpdated()

	log.Info("database initialized", "path", dbPath)
	return db, nil
}

// ResetInterruptedScans resets any nodes or images left in transient scan states
// back to pending. This happens when the server crashes or is OOM-killed mid-scan.
// Should be called once at startup, before the scan queue and watchers are started.
func (db *DB) ResetInterruptedScans() error {
	done := db.beginWrite("reset_interrupted_scans")
	defer done()

	res, err := db.conn.Exec(`
		UPDATE nodes SET status = 'pending', status_error = ''
		WHERE status IN ('generating_sbom', 'scanning_vulnerabilities')
	`)
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to reset interrupted node scans: %w", err)
	}
	nodeRows, _ := res.RowsAffected()

	res, err = db.conn.Exec(`
		UPDATE images SET status = 'pending'
		WHERE status IN ('generating_sbom', 'scanning_vulnerabilities')
	`)
	if err != nil {
		exitOnCorruption(err)
		return fmt.Errorf("failed to reset interrupted image scans: %w", err)
	}
	imageRows, _ := res.RowsAffected()

	if nodeRows > 0 || imageRows > 0 {
		log.Warn("reset interrupted scans to pending on startup",
			"nodes", nodeRows, "images", imageRows)
	}
	return nil
}

// ReapStuckScans recovers nodes and images that have been wedged in a transient
// scan state ('generating_sbom', 'scanning_vulnerabilities') for longer than
// maxAge, marking them 'vuln_scan_failed' so the periodic rescan path
// re-enqueues them.
//
// Unlike ResetInterruptedScans — which only runs once at startup and so cannot
// help a scan orphaned while the server keeps running — this is meant to be
// called periodically (from the rescan-database job). A scan can be orphaned
// without ever hitting a terminal status (e.g. a worker that stops making
// progress, or an unbounded readiness wait), leaving the row stuck until the
// next restart. The maxAge guard must be safely larger than the real scan
// timeouts (host SBOM 15m + vuln scan 10m) so legitimately in-flight scans are
// never reaped; status writes bump updated_at, so a fresh transition resets the
// clock. 'vuln_scan_failed' is chosen over 'pending' because the rescan filters
// re-enqueue that state for both images and nodes within the same periodic job.
func (db *DB) ReapStuckScans(maxAge time.Duration) (nodeRows, imageRows int64, err error) {
	done := db.beginWrite("reap_stuck_scans")
	defer done()

	cutoff := time.Now().UTC().Add(-maxAge).Format("2006-01-02 15:04:05")
	const reapErr = "scan exceeded maximum duration and was reset by the stuck-scan reaper"

	res, err := db.conn.Exec(`
		UPDATE nodes SET status = 'vuln_scan_failed', status_error = ?
		WHERE status IN ('generating_sbom', 'scanning_vulnerabilities')
		  AND updated_at < ?
	`, reapErr, cutoff)
	if err != nil {
		exitOnCorruption(err)
		return 0, 0, fmt.Errorf("failed to reap stuck node scans: %w", err)
	}
	nodeRows, _ = res.RowsAffected()

	res, err = db.conn.Exec(`
		UPDATE images SET status = 'vuln_scan_failed', status_error = ?
		WHERE status IN ('generating_sbom', 'scanning_vulnerabilities')
		  AND updated_at < ?
	`, reapErr, cutoff)
	if err != nil {
		exitOnCorruption(err)
		return 0, 0, fmt.Errorf("failed to reap stuck image scans: %w", err)
	}
	imageRows, _ = res.RowsAffected()

	if nodeRows > 0 || imageRows > 0 {
		log.Warn("reaped stuck scans to vuln_scan_failed",
			"nodes", nodeRows, "images", imageRows, "max_age", maxAge)
		db.notifyWrite()
	}
	return nodeRows, imageRows, nil
}

// Close closes the database connection gracefully
func Close(db *DB) error {
	if db == nil || db.conn == nil {
		return nil
	}

	// Checkpoint WAL to ensure all data is written to main database
	log.Info("checkpointing WAL before closing database")
	if _, err := db.conn.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		log.Warn("failed to checkpoint WAL", "error", err)
	}

	return db.conn.Close()
}

// walUnmergedFramesLimit is the number of unmerged WAL frames above which the
// WAL monitor will emit a warning. Each frame is 4096 bytes (default page size),
// so 25,000 frames ≈ 100MB of unmerged WAL.
const walUnmergedFramesLimit = 25_000

// HealthCheck checks whether the database connection is responsive.
// It uses SELECT 1 to avoid write I/O (PRAGMA wal_checkpoint) competing with
// active scan jobs on slow NFS, which caused false-positive liveness probe failures.
// WAL accumulation is monitored separately by StartWALMonitor.
func HealthCheck(db *DB) error {
	if db == nil || db.conn == nil {
		return fmt.Errorf("database connection is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var v int
	if err := db.conn.QueryRowContext(ctx, "SELECT 1").Scan(&v); err != nil {
		return fmt.Errorf("database unresponsive: %w", err)
	}
	return nil
}

// StartWALMonitor runs a background goroutine that periodically checkpoints the WAL
// using FULL mode. FULL checkpoints all available frames without blocking for the
// WAL write-position reset (unlike RESTART which holds an exclusive lock and can
// block concurrent SELECT queries, including the health check). PASSIVE was used
// previously but cannot make progress while readers are active (e.g. streaming
// /metrics scrapes or OTEL export reads), causing the WAL to grow unboundedly.
//
// The interval is 30 minutes. SQLite's built-in wal_autocheckpoint already handles
// routine maintenance (PASSIVE every ~1000 pages); this monitor is a safety valve for
// the case where long-running readers prevent auto-checkpoint from making progress.
// A 5-minute interval was too aggressive: it competed for the 2-connection pool during
// active scans, causing the health check's SELECT 1 to time out.
//
// This is separate from HealthCheck so slow NFS I/O does not cause false-positive
// liveness probe failures. The goroutine exits when ctx is cancelled.
func StartWALMonitor(ctx context.Context, db *DB) {
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if db == nil || db.conn == nil {
					return
				}
				checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				var busy, walLog, checkpointed int
				err := db.conn.QueryRowContext(checkCtx, "PRAGMA wal_checkpoint(FULL)").Scan(&busy, &walLog, &checkpointed)
				cancel()
				if err != nil {
					log.Warn("WAL monitor: checkpoint query failed", slog.Any("error", err))
					continue
				}
				unmerged := walLog - checkpointed
				if unmerged > walUnmergedFramesLimit {
					log.Warn("WAL monitor: WAL too large, checkpoint may be blocked by long-running reader",
						"wal_frames", walLog, "unmerged", unmerged,
						"unmerged_mb", unmerged*4096/1024/1024)
				} else if walLog > 0 {
					log.Debug("WAL monitor: checkpoint ok", "wal_frames", walLog, "checkpointed", checkpointed, "unmerged", unmerged)
				}
			}
		}
	}()
}

// RecoverFromCorruption attempts to recover from database corruption
// WARNING: This may result in data loss
func RecoverFromCorruption(dbPath string) error {
	log.Info("attempting to recover corrupted database", "path", dbPath)

	// Try to dump and restore
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open corrupted database: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Attempt to export data to a new database
	backupPath := dbPath + ".backup"
	log.Info("creating backup", "path", backupPath)

	_, err = conn.Exec(fmt.Sprintf("VACUUM INTO '%s'", backupPath))
	if err != nil {
		log.Error("VACUUM INTO failed", "error", err)
		// Try alternative recovery: .dump equivalent
		return fmt.Errorf("failed to recover database: %w", err)
	}

	log.Info("database recovered", "backup_path", backupPath)
	log.Info("to use recovered database, run command", "command", fmt.Sprintf("mv %s %s", backupPath, dbPath))

	return nil
}

// compressGzip gzip-compresses data.
func compressGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("gzip write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("gzip close: %w", err)
	}
	return buf.Bytes(), nil
}

// decompressGzip decompresses gzip data.
func decompressGzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip reader: %w", err)
	}
	defer func() { _ = r.Close() }()
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("gzip read: %w", err)
	}
	return out, nil
}

// batchInsert executes multi-row INSERTs in chunks to stay within SQLite's
// variable limit (999 by default). query is the INSERT prefix up to but not
// including VALUES. rows is a flat slice of all argument values, ncols is the
// number of columns per row, and batchSize is the max rows per statement.
func batchInsert(tx *sql.Tx, query string, rows []any, ncols, batchSize int) error {
	if len(rows) == 0 {
		return nil
	}
	placeholder := "(" + strings.Repeat("?,", ncols-1) + "?)"
	for i := 0; i < len(rows); i += ncols * batchSize {
		end := i + ncols*batchSize
		if end > len(rows) {
			end = len(rows)
		}
		chunk := rows[i:end]
		n := len(chunk) / ncols
		placeholders := strings.Repeat(placeholder+",", n-1) + placeholder
		if _, err := tx.Exec(query+" VALUES "+placeholders, chunk...); err != nil {
			return err
		}
	}
	return nil
}
