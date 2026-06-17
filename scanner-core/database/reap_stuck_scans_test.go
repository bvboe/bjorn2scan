package database

import (
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// backdateUpdatedAt forces a row's updated_at far enough into the past that the
// reaper's age guard treats it as stuck. Tests need this because every status
// write bumps updated_at to CURRENT_TIMESTAMP.
func backdateUpdatedAt(t *testing.T, db *DB, table, col, val string) {
	t.Helper()
	_, err := db.conn.Exec(
		`UPDATE `+table+` SET updated_at = datetime('now', '-2 hours') WHERE `+col+` = ?`, val)
	if err != nil {
		t.Fatalf("failed to backdate %s.%s: %v", table, col, err)
	}
}

// TestReapStuckScans_ReapsStuckRows verifies that nodes and images wedged in a
// transient state past maxAge are reset to vuln_scan_failed with an error.
func TestReapStuckScans_ReapsStuckRows(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	// Image stuck in scanning_vulnerabilities.
	if _, err := db.AddContainer(containers.Container{
		ID:       containers.ContainerID{Namespace: "default", Pod: "p", Name: "c"},
		Image:    containers.ImageID{Reference: "nginx:1.21", Digest: "sha256:stuckimg"},
		NodeName: "worker-1", ContainerRuntime: "containerd",
	}); err != nil {
		t.Fatalf("AddContainer failed: %v", err)
	}
	if err := db.UpdateStatus("sha256:stuckimg", StatusScanningVulnerabilities, ""); err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	// Node stuck in generating_sbom.
	if _, err := db.AddNode(nodes.Node{Name: "stuck-node", Hostname: "stuck-node", Architecture: "amd64"}); err != nil {
		t.Fatalf("AddNode failed: %v", err)
	}
	if err := db.UpdateNodeStatus("stuck-node", StatusGeneratingSBOM, ""); err != nil {
		t.Fatalf("UpdateNodeStatus failed: %v", err)
	}

	// Make both look stuck.
	backdateUpdatedAt(t, db, "images", "digest", "sha256:stuckimg")
	backdateUpdatedAt(t, db, "nodes", "name", "stuck-node")

	nodeRows, imageRows, err := db.ReapStuckScans(30 * time.Minute)
	if err != nil {
		t.Fatalf("ReapStuckScans failed: %v", err)
	}
	if nodeRows != 1 {
		t.Errorf("expected 1 node reaped, got %d", nodeRows)
	}
	if imageRows != 1 {
		t.Errorf("expected 1 image reaped, got %d", imageRows)
	}

	imgStatus, err := db.GetImageStatus("sha256:stuckimg")
	if err != nil {
		t.Fatalf("GetImageStatus failed: %v", err)
	}
	if imgStatus != StatusVulnScanFailed {
		t.Errorf("expected image status %q, got %q", StatusVulnScanFailed, imgStatus)
	}

	nodeStatus, err := db.GetNodeScanStatus("stuck-node")
	if err != nil {
		t.Fatalf("GetNodeScanStatus failed: %v", err)
	}
	if nodeStatus != StatusVulnScanFailed.String() {
		t.Errorf("expected node status %q, got %q", StatusVulnScanFailed, nodeStatus)
	}
}

// TestReapStuckScans_LeavesFreshScans verifies that scans which entered a
// transient state recently are NOT reaped — the age guard protects in-flight work.
func TestReapStuckScans_LeavesFreshScans(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	if _, err := db.AddContainer(containers.Container{
		ID:       containers.ContainerID{Namespace: "default", Pod: "p", Name: "c"},
		Image:    containers.ImageID{Reference: "nginx:1.21", Digest: "sha256:freshimg"},
		NodeName: "worker-1", ContainerRuntime: "containerd",
	}); err != nil {
		t.Fatalf("AddContainer failed: %v", err)
	}
	if err := db.UpdateStatus("sha256:freshimg", StatusScanningVulnerabilities, ""); err != nil {
		t.Fatalf("UpdateStatus failed: %v", err)
	}

	if _, err := db.AddNode(nodes.Node{Name: "fresh-node", Hostname: "fresh-node", Architecture: "amd64"}); err != nil {
		t.Fatalf("AddNode failed: %v", err)
	}
	if err := db.UpdateNodeStatus("fresh-node", StatusScanningVulnerabilities, ""); err != nil {
		t.Fatalf("UpdateNodeStatus failed: %v", err)
	}

	// updated_at is CURRENT_TIMESTAMP — both are fresh, none should be reaped.
	nodeRows, imageRows, err := db.ReapStuckScans(30 * time.Minute)
	if err != nil {
		t.Fatalf("ReapStuckScans failed: %v", err)
	}
	if nodeRows != 0 || imageRows != 0 {
		t.Errorf("expected 0 rows reaped for fresh scans, got nodes=%d images=%d", nodeRows, imageRows)
	}

	imgStatus, _ := db.GetImageStatus("sha256:freshimg")
	if imgStatus != StatusScanningVulnerabilities {
		t.Errorf("fresh image should still be %q, got %q", StatusScanningVulnerabilities, imgStatus)
	}
}
