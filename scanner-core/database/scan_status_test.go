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
		{"completed", "Scan complete", 1},
		{"pending", "Pending scan", 2},
		{"scanning_vulnerabilities", "Running vulnerability scan", 3},
		{"generating_sbom", "Retrieving SBOM", 4},
		{"sbom_unavailable", "Unable to scan", 5},
		{"vuln_scan_failed", "Scan failed", 6},
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
