package database

import (
	"testing"
	"time"

	"github.com/bvboe/bjorn2scan/scanner-core/nodes"
)

// seedNodeWithVulns creates a node, stores an SBOM and one vulnerability, and
// leaves it in the completed state.
func seedNodeWithVulns(t *testing.T, db *DB, name string) {
	t.Helper()

	if _, err := db.AddNode(nodes.Node{Name: name}); err != nil {
		t.Fatalf("AddNode(%s): %v", name, err)
	}
	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	if err := db.StoreNodeSBOM(name, []byte(sbom)); err != nil {
		t.Fatalf("StoreNodeSBOM(%s): %v", name, err)
	}
	vulns := `{"matches": [{
		"vulnerability": {"id": "CVE-2021-1234", "severity": "High", "fix": {"state": "fixed", "versions": ["1.1.2"]}},
		"artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}
	}]}`
	if err := db.StoreNodeVulnerabilities(name, []byte(vulns), time.Now()); err != nil {
		t.Fatalf("StoreNodeVulnerabilities(%s): %v", name, err)
	}
	if err := db.UpdateNodeStatus(name, StatusCompleted, ""); err != nil {
		t.Fatalf("UpdateNodeStatus(%s, completed): %v", name, err)
	}
}

func countNodeVulnMetricRows(t *testing.T, db *DB, node string) int {
	t.Helper()
	rows, err := db.GetNodeVulnerabilitiesForMetrics()
	if err != nil {
		t.Fatalf("GetNodeVulnerabilitiesForMetrics: %v", err)
	}
	n := 0
	for _, r := range rows {
		if r.NodeName == node {
			n++
		}
	}
	return n
}

// TestNodeVulnMetricsSurviveRescan pins the fix for the daily rescan storm.
//
// The metrics queries filtered on status = 'completed'. A rescan moves a node
// to generating_sbom and then scanning_vulnerabilities for up to 25 minutes, so
// for that whole window every one of its vulnerability series vanished from the
// export - around 65,400 per node on the kubeadm cluster - even though the rows
// were still in the table and nothing about the node had changed.
//
// The staleness tracker then did its job: it saw the series disappear, marked
// them stale and emitted NaN. So once a day, for up to 25 minutes per node,
// every real vulnerability on a node being re-verified reported as a gap rather
// than a value. In production that showed as data_points swinging
// 851k -> 729k -> 876k with staleness_ms peaking at 122,591 against a median
// of 3.
//
// The rows are readable throughout because StoreNodeVulnerabilities deletes and
// reinserts inside a single transaction, so the old filter was discarding data
// the database still held.
func TestNodeVulnMetricsSurviveRescan(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	const node = "rescan-node"
	seedNodeWithVulns(t, db, node)

	baseline := countNodeVulnMetricRows(t, db, node)
	if baseline == 0 {
		t.Fatal("expected vulnerability rows for a completed node; test cannot prove anything")
	}

	// Each transient state a rescan passes through must keep the node's
	// existing findings visible to the exporter.
	for _, status := range []Status{StatusGeneratingSBOM, StatusScanningVulnerabilities} {
		if err := db.UpdateNodeStatus(node, status, ""); err != nil {
			t.Fatalf("UpdateNodeStatus(%s): %v", status, err)
		}
		if got := countNodeVulnMetricRows(t, db, node); got != baseline {
			t.Errorf("status %s: got %d vulnerability rows, want %d - a node being "+
				"re-verified must keep reporting its known findings, not drop to NaN",
				status, got, baseline)
		}
	}

	// Returning to completed must not change anything either.
	if err := db.UpdateNodeStatus(node, StatusCompleted, ""); err != nil {
		t.Fatalf("UpdateNodeStatus(completed): %v", err)
	}
	if got := countNodeVulnMetricRows(t, db, node); got != baseline {
		t.Errorf("back at completed: got %d rows, want %d", got, baseline)
	}
}

// TestNodeVulnMetricsExcludeFailedScans is the other half of the contract: the
// fix widens the filter to transient rescan states only. A node whose scan
// failed must not keep publishing older findings as though they were current,
// and a node that never completed has nothing to publish.
func TestNodeVulnMetricsExcludeFailedScans(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	const node = "failing-node"
	seedNodeWithVulns(t, db, node)

	if countNodeVulnMetricRows(t, db, node) == 0 {
		t.Fatal("expected vulnerability rows for a completed node")
	}

	for _, status := range []Status{StatusSBOMFailed, StatusVulnScanFailed, StatusSBOMUnavailable, StatusPending} {
		if err := db.UpdateNodeStatus(node, status, "boom"); err != nil {
			t.Fatalf("UpdateNodeStatus(%s): %v", status, err)
		}
		if got := countNodeVulnMetricRows(t, db, node); got != 0 {
			t.Errorf("status %s: got %d vulnerability rows, want 0 - a failed or "+
				"unstarted scan must not keep reporting stale findings", status, got)
		}
	}
}

// TestScannedNodesTracksVulnMetrics keeps the node inventory metric in step with
// the vulnerability metrics. If bjorn2scan_node_scanned dropped a node while its
// vulnerability series kept reporting, any dashboard joining the two would break.
func TestScannedNodesTracksVulnMetrics(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	const node = "inventory-node"
	seedNodeWithVulns(t, db, node)

	present := func() bool {
		list, err := db.GetScannedNodes()
		if err != nil {
			t.Fatalf("GetScannedNodes: %v", err)
		}
		for _, n := range list {
			if n.Name == node {
				return true
			}
		}
		return false
	}

	if !present() {
		t.Fatal("expected a completed node to appear in GetScannedNodes")
	}
	for _, status := range []Status{StatusGeneratingSBOM, StatusScanningVulnerabilities} {
		if err := db.UpdateNodeStatus(node, status, ""); err != nil {
			t.Fatalf("UpdateNodeStatus(%s): %v", status, err)
		}
		if !present() {
			t.Errorf("status %s: node missing from GetScannedNodes while its "+
				"vulnerability series still report", status)
		}
	}
	if err := db.UpdateNodeStatus(node, StatusSBOMFailed, "boom"); err != nil {
		t.Fatalf("UpdateNodeStatus(sbom_failed): %v", err)
	}
	if present() {
		t.Error("a failed node must not appear in GetScannedNodes")
	}
}
