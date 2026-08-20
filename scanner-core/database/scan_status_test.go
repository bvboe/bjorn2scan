package database

import (
	"os"
	"testing"
	"time"
)

func TestScanStatusTable(t *testing.T) {
	dbPath := "/tmp/test_scan_status_" + time.Now().Format("20060102150405") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Query the scan_status table
	rows, err := db.conn.Query(`
		SELECT status, description, sort_order 
		FROM scan_status 
		ORDER BY sort_order, status
	`)
	if err != nil {
		t.Fatalf("Failed to query scan_status table: %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Errorf("Failed to close rows: %v", err)
		}
	}()

	expected := []struct {
		status      string
		description string
		sortOrder   int
	}{
		// Ranked by how far the image has progressed: done, actively scanning,
		// queued, then terminal failures. In-progress must outrank 'pending' —
		// status.sort_order is the first ORDER BY term on the image listings, so
		// this is the grouping the user sees. See migrateToV51.
		{"completed", "Scan complete", 1},
		{"scanning_vulnerabilities", "Running vulnerability scan", 2},
		{"generating_sbom", "Retrieving SBOM", 3},
		{"pending", "Pending scan", 4},
		{"sbom_failed", "SBOM generation failed", 5},
		{"sbom_unavailable", "Unable to scan", 6},
		{"vuln_scan_failed", "Scan failed", 7},
	}

	var got []struct {
		status      string
		description string
		sortOrder   int
	}

	for rows.Next() {
		var status, desc string
		var order int
		if err := rows.Scan(&status, &desc, &order); err != nil {
			t.Fatalf("Failed to scan row: %v", err)
		}
		got = append(got, struct {
			status      string
			description string
			sortOrder   int
		}{status, desc, order})
	}

	if len(got) != len(expected) {
		t.Fatalf("Expected %d rows, got %d", len(expected), len(got))
	}

	for i, exp := range expected {
		if got[i].status != exp.status {
			t.Errorf("Row %d: expected status %q, got %q", i, exp.status, got[i].status)
		}
		if got[i].description != exp.description {
			t.Errorf("Row %d: expected description %q, got %q", i, exp.description, got[i].description)
		}
		if got[i].sortOrder != exp.sortOrder {
			t.Errorf("Row %d: expected sort_order %d, got %d", i, exp.sortOrder, got[i].sortOrder)
		}
	}

	t.Log("scan_status table verified successfully")
}

// TestMigrateToV51OnExistingData exercises the upgrade path rather than a fresh
// install. A pre-v51 database already holds rows with the old ordering, so the
// migration has to UPDATE them — an INSERT OR IGNORE seed (how the table is
// populated in v11) would silently leave the old values in place and the bug
// would persist for every existing deployment while looking fixed on a new one.
func TestMigrateToV51OnExistingData(t *testing.T) {
	dbPath := "/tmp/test_scan_status_v51_" + time.Now().Format("20060102150405.000") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	// Rewind to the pre-v51 state to simulate an existing deployment: the old
	// ordering, and no 'sbom_failed' row at all (it was never seeded).
	if _, err := db.conn.Exec(`
		DELETE FROM scan_status WHERE status = 'sbom_failed';
		UPDATE scan_status SET sort_order = 1 WHERE status = 'completed';
		UPDATE scan_status SET sort_order = 2 WHERE status = 'pending';
		UPDATE scan_status SET sort_order = 3 WHERE status = 'scanning_vulnerabilities';
		UPDATE scan_status SET sort_order = 4 WHERE status = 'generating_sbom';
	`); err != nil {
		t.Fatalf("Failed to seed pre-v51 state: %v", err)
	}

	if err := migrateToV51(db.conn); err != nil {
		t.Fatalf("migrateToV51 failed: %v", err)
	}

	order := map[string]int{}
	rows, err := db.conn.Query(`SELECT status, sort_order FROM scan_status`)
	if err != nil {
		t.Fatalf("Failed to query scan_status: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var status string
		var so int
		if err := rows.Scan(&status, &so); err != nil {
			t.Fatalf("Failed to scan row: %v", err)
		}
		order[status] = so
	}

	// The property that matters: both in-progress states outrank 'pending'.
	for _, active := range []string{"generating_sbom", "scanning_vulnerabilities"} {
		if order[active] >= order["pending"] {
			t.Errorf("%s (sort_order %d) must rank above pending (sort_order %d)",
				active, order[active], order["pending"])
		}
	}
	// Completed stays first and failures stay last.
	if order["completed"] != 1 {
		t.Errorf("completed sort_order = %d, want 1", order["completed"])
	}
	for _, failed := range []string{"sbom_failed", "sbom_unavailable", "vuln_scan_failed"} {
		if order[failed] <= order["pending"] {
			t.Errorf("%s (sort_order %d) should rank below pending (sort_order %d)",
				failed, order[failed], order["pending"])
		}
	}
	// The migration must have backfilled the row that was missing entirely.
	if _, ok := order["sbom_failed"]; !ok {
		t.Error("migrateToV51 did not add the missing sbom_failed row")
	}

	// Migration must be idempotent, and must not duplicate the backfilled row.
	if err := migrateToV51(db.conn); err != nil {
		t.Fatalf("migrateToV51 not idempotent: %v", err)
	}
	var count int
	if err := db.conn.QueryRow(`SELECT COUNT(*) FROM scan_status WHERE status = 'sbom_failed'`).Scan(&count); err != nil {
		t.Fatalf("Failed to count sbom_failed rows: %v", err)
	}
	if count != 1 {
		t.Errorf("expected exactly 1 sbom_failed row after re-running migration, got %d", count)
	}
}

// TestEveryStatusHasScanStatusRow guards the whole class of bug that the missing
// 'sbom_failed' row belonged to. The image listing and image detail queries in
// handlers/images.go join scan_status with an INNER join, so a status the scanner
// can write but the table does not know about makes those images vanish from the
// UI rather than show as failed. Any new Status constant must come with a row.
func TestEveryStatusHasScanStatusRow(t *testing.T) {
	dbPath := "/tmp/test_scan_status_coverage_" + time.Now().Format("20060102150405.000") + ".db"
	defer func() { _ = os.Remove(dbPath) }()

	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer func() { _ = Close(db) }()

	all := []Status{
		StatusPending,
		StatusGeneratingSBOM,
		StatusSBOMFailed,
		StatusSBOMUnavailable,
		StatusScanningVulnerabilities,
		StatusVulnScanFailed,
		StatusCompleted,
	}

	for _, status := range all {
		var count int
		err := db.conn.QueryRow(
			`SELECT COUNT(*) FROM scan_status WHERE status = ?`, string(status),
		).Scan(&count)
		if err != nil {
			t.Fatalf("Failed to query scan_status for %q: %v", status, err)
		}
		if count != 1 {
			t.Errorf("status %q has %d rows in scan_status, want 1 — images in this "+
				"status will be dropped by the inner join in handlers/images.go", status, count)
		}
	}
}
