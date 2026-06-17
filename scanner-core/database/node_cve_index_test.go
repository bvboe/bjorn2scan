package database

import (
	"path/filepath"
	"testing"
)

// TestMigrationV50NodeCVEIndexes verifies that migration v50 creates the index
// backing the deployment-wide node CVE listing, and that the deduplicated
// grouping + affected-node counting the listing relies on produce correct
// results against realistic populated data.
func TestMigrationV50NodeCVEIndexes(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("failed to create database: %v", err)
	}
	defer func() {
		if err := Close(db); err != nil {
			t.Logf("warning: failed to close database: %v", err)
		}
	}()

	exec := func(query string) {
		t.Helper()
		if _, err := db.conn.Exec(query); err != nil {
			t.Fatalf("exec failed: %v\nquery: %s", err, query)
		}
	}

	// Two nodes share CVE-2024-0001/openssl (must dedupe to a single listing row
	// affecting 2 nodes); a third node has its own CVE.
	exec(`INSERT INTO nodes (id, name, os_release, status) VALUES
		(1, 'node-a', 'wolfi',  'completed'),
		(2, 'node-b', 'debian', 'completed'),
		(3, 'node-c', 'debian', 'completed')`)

	exec(`INSERT INTO node_vulnerabilities
		(node_id, cve_id, package_name, package_version, package_type, severity, fix_status, fix_version, count, risk, known_exploited) VALUES
		(1, 'CVE-2024-0001', 'openssl', '1.1.1', 'apk', 'Critical', 'fixed',     '1.1.1w', 1, 9.8, 1),
		(2, 'CVE-2024-0001', 'openssl', '1.1.1', 'apk', 'Critical', 'fixed',     '1.1.1w', 1, 9.8, 1),
		(3, 'CVE-2024-0002', 'zlib',    '1.2',   'apk', 'High',     'not-fixed', '',       1, 7.5, 0)`)

	// Index from v50 exists.
	var name string
	if err := db.conn.QueryRow(
		`SELECT name FROM sqlite_master WHERE type='index' AND name = ?`, "idx_node_vulnerabilities_cve_pkg",
	).Scan(&name); err != nil {
		t.Errorf("expected index idx_node_vulnerabilities_cve_pkg to exist: %v", err)
	}

	// CVE-2024-0001 dedupes to one row affecting 2 nodes.
	var affected int
	if err := db.conn.QueryRow(`
		SELECT COUNT(DISTINCT n.id)
		FROM node_vulnerabilities v
		JOIN nodes n ON v.node_id = n.id
		WHERE v.cve_id = 'CVE-2024-0001'
		GROUP BY v.cve_id, v.package_name, v.package_version, v.fix_version, v.fix_status, v.package_type, v.severity
	`).Scan(&affected); err != nil {
		t.Fatalf("grouped query failed: %v", err)
	}
	if affected != 2 {
		t.Errorf("expected CVE-2024-0001 to affect 2 nodes, got %d", affected)
	}

	// Total deduped rows = 2.
	var groups int
	if err := db.conn.QueryRow(`
		SELECT COUNT(*) FROM (
			SELECT 1
			FROM node_vulnerabilities v
			JOIN nodes n ON v.node_id = n.id
			GROUP BY v.cve_id, v.package_name, v.package_version, v.fix_version, v.fix_status, v.package_type, v.severity
		) sub
	`).Scan(&groups); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if groups != 2 {
		t.Errorf("expected 2 deduped CVE rows, got %d", groups)
	}

	// OS filter scopes the affected count: CVE-2024-0001 in 'wolfi' only touches node-a.
	var wolfiAffected int
	if err := db.conn.QueryRow(`
		SELECT COUNT(DISTINCT n.id)
		FROM node_vulnerabilities v
		JOIN nodes n ON v.node_id = n.id
		WHERE v.cve_id = 'CVE-2024-0001' AND n.os_release IN ('wolfi')
		GROUP BY v.cve_id, v.package_name, v.package_version
	`).Scan(&wolfiAffected); err != nil {
		t.Fatalf("os-filtered query failed: %v", err)
	}
	if wolfiAffected != 1 {
		t.Errorf("expected CVE-2024-0001 on 'wolfi' to affect 1 node, got %d", wolfiAffected)
	}
}
