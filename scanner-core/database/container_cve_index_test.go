package database

import (
	"path/filepath"
	"testing"
)

// TestMigrationV49ContainerCVEIndexes verifies that migration v49 creates the
// indexes backing the deployment-wide container CVE listing, and that the
// deduplicated grouping + affected-container counting the listing relies on
// produce correct results against realistic populated data.
func TestMigrationV49ContainerCVEIndexes(t *testing.T) {
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

	// Realistic data: two images share CVE-2024-0001/openssl (so it must dedupe
	// to a single listing row), and one image has its own CVE. img1 runs in two
	// containers, img2 in one.
	exec(`INSERT INTO images (id, digest, os_name) VALUES
		(1, 'sha256:img1', 'wolfi'),
		(2, 'sha256:img2', 'debian')`)

	exec(`INSERT INTO containers (namespace, pod, name, reference, image_id) VALUES
		('default', 'pod-a', 'app', 'nginx:1.25', 1),
		('default', 'pod-b', 'app', 'nginx:1.25', 1),
		('prod',    'pod-c', 'app', 'redis:7',    2)`)

	exec(`INSERT INTO image_vulnerabilities
		(image_id, cve_id, package_name, package_version, package_type, severity, fix_status, fixed_version, count, risk, known_exploited) VALUES
		(1, 'CVE-2024-0001', 'openssl', '1.1.1', 'apk', 'Critical', 'fixed',     '1.1.1w', 1, 9.8, 1),
		(2, 'CVE-2024-0001', 'openssl', '1.1.1', 'apk', 'Critical', 'fixed',     '1.1.1w', 1, 9.8, 1),
		(2, 'CVE-2024-0002', 'zlib',    '1.2',   'apk', 'High',     'not-fixed', '',       1, 7.5, 0)`)

	// Indexes from v49 exist.
	for _, idx := range []string{"idx_image_vulnerabilities_cve_pkg", "idx_containers_ns_image"} {
		var name string
		if err := db.conn.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='index' AND name = ?`, idx,
		).Scan(&name); err != nil {
			t.Errorf("expected index %s to exist: %v", idx, err)
		}
	}

	// CVE-2024-0001 dedupes to one row and affects all 3 containers
	// (2 from img1 + 1 from img2).
	var affected int
	if err := db.conn.QueryRow(`
		SELECT COUNT(DISTINCT c.id)
		FROM image_vulnerabilities v
		JOIN images i ON v.image_id = i.id
		JOIN containers c ON c.image_id = i.id
		WHERE v.cve_id = 'CVE-2024-0001'
		GROUP BY v.cve_id, v.package_name, v.package_version, v.fixed_version, v.fix_status, v.package_type, v.severity
	`).Scan(&affected); err != nil {
		t.Fatalf("grouped query failed: %v", err)
	}
	if affected != 3 {
		t.Errorf("expected CVE-2024-0001 to affect 3 containers, got %d", affected)
	}

	// Total deduped rows across the deployment = 2 (CVE-0001 once, CVE-0002 once).
	var groups int
	if err := db.conn.QueryRow(`
		SELECT COUNT(*) FROM (
			SELECT 1
			FROM image_vulnerabilities v
			JOIN images i ON v.image_id = i.id
			JOIN containers c ON c.image_id = i.id
			GROUP BY v.cve_id, v.package_name, v.package_version, v.fixed_version, v.fix_status, v.package_type, v.severity
		) sub
	`).Scan(&groups); err != nil {
		t.Fatalf("count query failed: %v", err)
	}
	if groups != 2 {
		t.Errorf("expected 2 deduped CVE rows, got %d", groups)
	}

	// Namespace filter scopes the affected count: CVE-2024-0001 in 'default'
	// only touches img1's two containers.
	var defaultAffected int
	if err := db.conn.QueryRow(`
		SELECT COUNT(DISTINCT c.id)
		FROM image_vulnerabilities v
		JOIN images i ON v.image_id = i.id
		JOIN containers c ON c.image_id = i.id
		WHERE v.cve_id = 'CVE-2024-0001' AND c.namespace IN ('default')
		GROUP BY v.cve_id, v.package_name, v.package_version
	`).Scan(&defaultAffected); err != nil {
		t.Fatalf("namespace-filtered query failed: %v", err)
	}
	if defaultAffected != 2 {
		t.Errorf("expected CVE-2024-0001 in 'default' to affect 2 containers, got %d", defaultAffected)
	}
}
