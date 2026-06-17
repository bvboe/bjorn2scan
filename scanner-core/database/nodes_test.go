package database

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// createTestDB creates a temporary test database
func createTestDB(t *testing.T) (*DB, func()) {
	t.Helper()
	dbPath := "/tmp/test_nodes_" + time.Now().Format("20060102150405.000") + ".db"
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	cleanup := func() {
		_ = Close(db)
		_ = os.Remove(dbPath)
	}
	return db, cleanup
}

// TestAddNode_CreatesNew tests that a new node is created
func TestAddNode_CreatesNew(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{
		Name:         "test-node-1",
		Hostname:     "test-node-1.local",
		OSRelease:    "Ubuntu 22.04",
		Architecture: "amd64",
	}

	isNew, err := db.AddNode(node)
	if err != nil {
		t.Fatalf("AddNode failed: %v", err)
	}

	if !isNew {
		t.Error("Expected isNew=true for new node")
	}

	// Verify node exists in database
	var name string
	err = db.conn.QueryRow("SELECT name FROM nodes WHERE name = ?", node.Name).Scan(&name)
	if err != nil {
		t.Fatalf("Failed to query node: %v", err)
	}

	if name != node.Name {
		t.Errorf("Name = %v, want %v", name, node.Name)
	}
}

// TestAddNode_UpdatesExisting tests that existing node is updated
func TestAddNode_UpdatesExisting(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{
		Name:         "test-node-1",
		Hostname:     "test-node-1.local",
		OSRelease:    "Ubuntu 22.04",
		Architecture: "amd64",
	}

	// Create first time
	isNew1, err := db.AddNode(node)
	if err != nil {
		t.Fatalf("First AddNode failed: %v", err)
	}
	if !isNew1 {
		t.Error("Expected isNew=true for first call")
	}

	// Update with new OS release
	node.OSRelease = "Ubuntu 24.04"
	isNew2, err := db.AddNode(node)
	if err != nil {
		t.Fatalf("Second AddNode failed: %v", err)
	}

	if isNew2 {
		t.Error("Expected isNew=false for existing node")
	}

	// Verify OS release was updated
	var osRelease string
	err = db.conn.QueryRow("SELECT os_release FROM nodes WHERE name = ?", node.Name).Scan(&osRelease)
	if err != nil {
		t.Fatalf("Failed to query node: %v", err)
	}

	if osRelease != "Ubuntu 24.04" {
		t.Errorf("OSRelease = %v, want Ubuntu 24.04", osRelease)
	}
}

// TestGetNode_ReturnsNode tests retrieving an existing node
func TestGetNode_ReturnsNode(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{
		Name:          "test-node-1",
		Hostname:      "test-node-1.local",
		OSRelease:     "Ubuntu 22.04",
		KernelVersion: "5.15.0",
		Architecture:  "amd64",
	}

	_, err := db.AddNode(node)
	if err != nil {
		t.Fatalf("AddNode failed: %v", err)
	}

	result, err := db.GetNode("test-node-1")
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Name != node.Name {
		t.Errorf("Name = %v, want %v", result.Name, node.Name)
	}
	if result.Hostname != node.Hostname {
		t.Errorf("Hostname = %v, want %v", result.Hostname, node.Hostname)
	}
	if result.OSRelease != node.OSRelease {
		t.Errorf("OSRelease = %v, want %v", result.OSRelease, node.OSRelease)
	}
	if result.Architecture != node.Architecture {
		t.Errorf("Architecture = %v, want %v", result.Architecture, node.Architecture)
	}
}

// TestGetNode_ReturnsNilForMissing tests that missing node returns nil
func TestGetNode_ReturnsNilForMissing(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	result, err := db.GetNode("nonexistent-node")
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}

	if result != nil {
		t.Error("Expected nil result for missing node")
	}
}

// TestGetAllNodes_ReturnsAllNodes tests retrieving all nodes
func TestGetAllNodes_ReturnsAllNodes(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	// Add multiple nodes
	for i := 1; i <= 3; i++ {
		node := nodes.Node{
			Name:         "test-node-" + string(rune('0'+i)),
			Architecture: "amd64",
		}
		_, err := db.AddNode(node)
		if err != nil {
			t.Fatalf("AddNode failed for node %d: %v", i, err)
		}
	}

	result, err := db.GetAllNodes()
	if err != nil {
		t.Fatalf("GetAllNodes failed: %v", err)
	}

	if len(result) != 3 {
		t.Errorf("Expected 3 nodes, got %d", len(result))
	}
}

// TestRemoveNode_RemovesNodeAndData tests removing a node
func TestRemoveNode_RemovesNodeAndData(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{
		Name:         "test-node-1",
		Architecture: "amd64",
	}

	_, err := db.AddNode(node)
	if err != nil {
		t.Fatalf("AddNode failed: %v", err)
	}

	err = db.RemoveNode("test-node-1")
	if err != nil {
		t.Fatalf("RemoveNode failed: %v", err)
	}

	// Verify node is gone
	result, err := db.GetNode("test-node-1")
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}
	if result != nil {
		t.Error("Expected nil result after removal")
	}
}

// TestRemoveNode_NonexistentNode tests removing a nonexistent node
func TestRemoveNode_NonexistentNode(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	err := db.RemoveNode("nonexistent-node")
	if err != nil {
		t.Fatalf("RemoveNode should not fail for nonexistent node: %v", err)
	}
}

// TestUpdateNodeStatus tests updating node status
func TestUpdateNodeStatus(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{
		Name: "test-node-1",
	}
	_, err := db.AddNode(node)
	if err != nil {
		t.Fatalf("AddNode failed: %v", err)
	}

	err = db.UpdateNodeStatus("test-node-1", StatusCompleted, "")
	if err != nil {
		t.Fatalf("UpdateNodeStatus failed: %v", err)
	}

	status, err := db.GetNodeScanStatus("test-node-1")
	if err != nil {
		t.Fatalf("GetNodeScanStatus failed: %v", err)
	}

	if status != "completed" {
		t.Errorf("Status = %v, want completed", status)
	}
}

// TestUpdateNodeStatus_WithError tests updating node status with error message
func TestUpdateNodeStatus_WithError(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{
		Name: "test-node-1",
	}
	_, err := db.AddNode(node)
	if err != nil {
		t.Fatalf("AddNode failed: %v", err)
	}

	err = db.UpdateNodeStatus("test-node-1", StatusVulnScanFailed, "scan timeout")
	if err != nil {
		t.Fatalf("UpdateNodeStatus failed: %v", err)
	}

	result, err := db.GetNode("test-node-1")
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}

	if result.Status != "vuln_scan_failed" {
		t.Errorf("Status = %v, want vuln_scan_failed", result.Status)
	}
	if result.StatusError != "scan timeout" {
		t.Errorf("StatusError = %v, want 'scan timeout'", result.StatusError)
	}
}

// TestStoreNodeSBOM tests storing SBOM packages for a node
func TestStoreNodeSBOM(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{
		Name: "test-node-1",
	}
	_, err := db.AddNode(node)
	if err != nil {
		t.Fatalf("AddNode failed: %v", err)
	}

	// Create a mock SBOM
	sbom := struct {
		Artifacts []struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Type     string `json:"type"`
			Language string `json:"language"`
			PURL     string `json:"purl"`
		} `json:"artifacts"`
	}{
		Artifacts: []struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Type     string `json:"type"`
			Language string `json:"language"`
			PURL     string `json:"purl"`
		}{
			{Name: "openssl", Version: "1.1.1", Type: "deb", PURL: "pkg:deb/ubuntu/openssl@1.1.1"},
			{Name: "curl", Version: "7.68.0", Type: "deb", PURL: "pkg:deb/ubuntu/curl@7.68.0"},
			{Name: "bash", Version: "5.0", Type: "deb", PURL: "pkg:deb/ubuntu/bash@5.0"},
		},
	}

	sbomJSON, err := json.Marshal(sbom)
	if err != nil {
		t.Fatalf("Failed to marshal SBOM: %v", err)
	}

	err = db.StoreNodeSBOM("test-node-1", sbomJSON)
	if err != nil {
		t.Fatalf("StoreNodeSBOM failed: %v", err)
	}

	// Verify packages were stored
	packages, err := db.GetNodePackages("test-node-1")
	if err != nil {
		t.Fatalf("GetNodePackages failed: %v", err)
	}

	if len(packages) != 3 {
		t.Errorf("Expected 3 packages, got %d", len(packages))
	}

	// Verify specific package
	found := false
	for _, pkg := range packages {
		if pkg.Name == "openssl" && pkg.Version == "1.1.1" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to find openssl package")
	}
}

// TestStoreNodeSBOM_ReplacesExisting tests that SBOM storage replaces existing packages
func TestStoreNodeSBOM_ReplacesExisting(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	// Store first SBOM
	sbom1 := `{"artifacts": [{"name": "pkg1", "version": "1.0", "type": "deb"}]}`
	err := db.StoreNodeSBOM("test-node-1", []byte(sbom1))
	if err != nil {
		t.Fatalf("First StoreNodeSBOM failed: %v", err)
	}

	// Store second SBOM (should replace)
	sbom2 := `{"artifacts": [{"name": "pkg2", "version": "2.0", "type": "deb"}, {"name": "pkg3", "version": "3.0", "type": "deb"}]}`
	err = db.StoreNodeSBOM("test-node-1", []byte(sbom2))
	if err != nil {
		t.Fatalf("Second StoreNodeSBOM failed: %v", err)
	}

	packages, err := db.GetNodePackages("test-node-1")
	if err != nil {
		t.Fatalf("GetNodePackages failed: %v", err)
	}

	if len(packages) != 2 {
		t.Errorf("Expected 2 packages after replacement, got %d", len(packages))
	}

	// Verify old package is gone
	for _, pkg := range packages {
		if pkg.Name == "pkg1" {
			t.Error("Old package pkg1 should have been removed")
		}
	}
}

// TestStoreNodeVulnerabilities tests storing vulnerabilities for a node
func TestStoreNodeVulnerabilities(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	// Store SBOM first
	sbom := `{"artifacts": [
		{"name": "openssl", "version": "1.1.1", "type": "deb"},
		{"name": "curl", "version": "7.68.0", "type": "deb"}
	]}`
	err := db.StoreNodeSBOM("test-node-1", []byte(sbom))
	if err != nil {
		t.Fatalf("StoreNodeSBOM failed: %v", err)
	}

	// Create vulnerability report
	vulnReport := `{"matches": [
		{
			"vulnerability": {
				"id": "CVE-2021-1234",
				"severity": "High",
				"cvss": [{"score": 7.5}],
				"fix": {"state": "fixed", "versions": ["1.1.2"]}
			},
			"artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}
		},
		{
			"vulnerability": {
				"id": "CVE-2021-5678",
				"severity": "Critical",
				"cvss": [{"score": 9.8}],
				"fix": {"state": "not-fixed"}
			},
			"artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}
		},
		{
			"vulnerability": {
				"id": "CVE-2021-9999",
				"severity": "Medium",
				"cvss": [{"score": 5.0}]
			},
			"artifact": {"name": "curl", "version": "7.68.0", "type": "deb"}
		}
	]}`

	grypeDBBuilt := time.Now()
	err = db.StoreNodeVulnerabilities("test-node-1", []byte(vulnReport), grypeDBBuilt)
	if err != nil {
		t.Fatalf("StoreNodeVulnerabilities failed: %v", err)
	}

	// Verify vulnerabilities were stored
	vulns, err := db.GetNodeVulnerabilities("test-node-1")
	if err != nil {
		t.Fatalf("GetNodeVulnerabilities failed: %v", err)
	}

	if len(vulns) != 3 {
		t.Errorf("Expected 3 vulnerabilities, got %d", len(vulns))
	}

	// Verify node status updated to completed
	nodeResult, err := db.GetNode("test-node-1")
	if err != nil {
		t.Fatalf("GetNode failed: %v", err)
	}
	if nodeResult.Status != "completed" {
		t.Errorf("Expected status=completed, got %s", nodeResult.Status)
	}
}

// TestStoreNodeVulnerabilities_BatchedInserts tests that large vulnerability counts are handled
func TestStoreNodeVulnerabilities_BatchedInserts(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	// Store SBOM with one package
	sbom := `{"artifacts": [{"name": "testpkg", "version": "1.0", "type": "deb"}]}`
	err := db.StoreNodeSBOM("test-node-1", []byte(sbom))
	if err != nil {
		t.Fatalf("StoreNodeSBOM failed: %v", err)
	}

	// Create many vulnerabilities (more than batch size of 500)
	type vulnMatch struct {
		Vulnerability struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
		} `json:"vulnerability"`
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Type    string `json:"type"`
		} `json:"artifact"`
	}

	matches := make([]vulnMatch, 1500)
	for i := 0; i < 1500; i++ {
		matches[i] = vulnMatch{
			Vulnerability: struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
			}{
				ID:       "CVE-2021-" + string(rune('0'+i/1000)) + string(rune('0'+(i/100)%10)) + string(rune('0'+(i/10)%10)) + string(rune('0'+i%10)),
				Severity: "Medium",
			},
			Artifact: struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Type    string `json:"type"`
			}{
				Name:    "testpkg",
				Version: "1.0",
				Type:    "deb",
			},
		}
	}

	vulnReport := struct {
		Matches []vulnMatch `json:"matches"`
	}{Matches: matches}

	vulnJSON, err := json.Marshal(vulnReport)
	if err != nil {
		t.Fatalf("Failed to marshal vulnerabilities: %v", err)
	}

	grypeDBBuilt := time.Now()
	err = db.StoreNodeVulnerabilities("test-node-1", vulnJSON, grypeDBBuilt)
	if err != nil {
		t.Fatalf("StoreNodeVulnerabilities with batched inserts failed: %v", err)
	}

	// Verify all vulnerabilities were stored
	vulns, err := db.GetNodeVulnerabilities("test-node-1")
	if err != nil {
		t.Fatalf("GetNodeVulnerabilities failed: %v", err)
	}

	if len(vulns) != 1500 {
		t.Errorf("Expected 1500 vulnerabilities, got %d", len(vulns))
	}
}

// TestStoreNodeVulnerabilities_InlinePackageFields tests that vulns are stored with
// inline package_name/version/type regardless of whether the package exists in
// node_packages. No vulnerability should be silently dropped.
func TestStoreNodeVulnerabilities_InlinePackageFields(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node-1", []byte(sbom))

	// Vulnerability report includes a package not in the SBOM — both must be stored.
	vulnReport := `{"matches": [
		{
			"vulnerability": {"id": "CVE-2021-1234", "severity": "High"},
			"artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}
		},
		{
			"vulnerability": {"id": "CVE-2021-5678", "severity": "High"},
			"artifact": {"name": "nonexistent", "version": "1.0", "type": "deb"}
		}
	]}`

	err := db.StoreNodeVulnerabilities("test-node-1", []byte(vulnReport), time.Now())
	if err != nil {
		t.Fatalf("StoreNodeVulnerabilities failed: %v", err)
	}

	vulns, _ := db.GetNodeVulnerabilities("test-node-1")
	if len(vulns) != 2 {
		t.Errorf("Expected 2 vulnerabilities (inline storage, none dropped), got %d", len(vulns))
	}
	// Verify the "nonexistent" package vuln was stored inline
	found := false
	for _, v := range vulns {
		if v.PackageName == "nonexistent" && v.CVEID == "CVE-2021-5678" {
			found = true
		}
	}
	if !found {
		t.Error("Expected CVE-2021-5678 for package 'nonexistent' to be stored inline")
	}
}

// TestGetNodeSummaries tests getting vulnerability summaries
func TestGetNodeSummaries(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node-1", []byte(sbom))

	vulnReport := `{"matches": [
		{"vulnerability": {"id": "CVE-2021-0001", "severity": "Critical"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}},
		{"vulnerability": {"id": "CVE-2021-0002", "severity": "Critical"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}},
		{"vulnerability": {"id": "CVE-2021-0003", "severity": "High"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}},
		{"vulnerability": {"id": "CVE-2021-0004", "severity": "Medium"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}},
		{"vulnerability": {"id": "CVE-2021-0005", "severity": "Low"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}}
	]}`
	_ = db.StoreNodeVulnerabilities("test-node-1", []byte(vulnReport), time.Now())

	summaries, err := db.GetNodeSummaries()
	if err != nil {
		t.Fatalf("GetNodeSummaries failed: %v", err)
	}

	if len(summaries) != 1 {
		t.Fatalf("Expected 1 summary, got %d", len(summaries))
	}

	s := summaries[0]
	if s.NodeName != "test-node-1" {
		t.Errorf("NodeName = %v, want test-node-1", s.NodeName)
	}
	if s.Critical != 2 {
		t.Errorf("Critical = %d, want 2", s.Critical)
	}
	if s.High != 1 {
		t.Errorf("High = %d, want 1", s.High)
	}
	if s.Medium != 1 {
		t.Errorf("Medium = %d, want 1", s.Medium)
	}
	if s.Low != 1 {
		t.Errorf("Low = %d, want 1", s.Low)
	}
	if s.Total != 5 {
		t.Errorf("Total = %d, want 5", s.Total)
	}
}

// TestIsNodeScanComplete tests checking if a node scan is complete
func TestIsNodeScanComplete(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	// Initially not complete
	complete, err := db.IsNodeScanComplete("test-node-1")
	if err != nil {
		t.Fatalf("IsNodeScanComplete failed: %v", err)
	}
	if complete {
		t.Error("Expected incomplete before SBOM storage")
	}

	// Add SBOM and vulnerabilities
	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node-1", []byte(sbom))

	vulnReport := `{"matches": []}`
	_ = db.StoreNodeVulnerabilities("test-node-1", []byte(vulnReport), time.Now())

	// Should now be complete
	complete, err = db.IsNodeScanComplete("test-node-1")
	if err != nil {
		t.Fatalf("IsNodeScanComplete failed: %v", err)
	}
	if !complete {
		t.Error("Expected complete after SBOM and vuln storage")
	}
}

// TestGetNodesNeedingRescan tests finding nodes that need rescanning
func TestGetNodesNeedingRescan(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	// Create a completed node with old grype DB
	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node-1", []byte(sbom))

	oldGrypeDB := time.Now().Add(-48 * time.Hour)
	_ = db.StoreNodeVulnerabilities("test-node-1", []byte(`{"matches": []}`), oldGrypeDB)

	// Query with newer grype DB time
	currentGrypeDB := time.Now()
	nodesToRescan, err := db.GetNodesNeedingRescan(currentGrypeDB)
	if err != nil {
		t.Fatalf("GetNodesNeedingRescan failed: %v", err)
	}

	if len(nodesToRescan) != 1 {
		t.Errorf("Expected 1 node needing rescan, got %d", len(nodesToRescan))
	}
}

// TestGetNodesNeedingRescan_IncludesVulnScanFailed verifies that nodes stuck
// in vuln_scan_failed with a stale grype_db are picked up for rescan. Without
// this, a node whose last scan failed (e.g. because grype's validateAge bug
// returned "5 days ago") stays stranded forever — mirrors the image-side fix.
func TestGetNodesNeedingRescan_IncludesVulnScanFailed(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	// Seed a node with SBOM + vuln data scanned against an old grype DB, then
	// mark it vuln_scan_failed (simulates the production cascade we're fixing).
	node := nodes.Node{Name: "test-node-failed"}
	_, _ = db.AddNode(node)
	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node-failed", []byte(sbom))
	oldGrypeDB := time.Now().Add(-72 * time.Hour)
	_ = db.StoreNodeVulnerabilities("test-node-failed", []byte(`{"matches": []}`), oldGrypeDB)
	_ = db.UpdateNodeStatus("test-node-failed", StatusVulnScanFailed, "1 week ago")

	currentGrypeDB := time.Now()
	nodesToRescan, err := db.GetNodesNeedingRescan(currentGrypeDB)
	if err != nil {
		t.Fatalf("GetNodesNeedingRescan failed: %v", err)
	}

	found := false
	for _, n := range nodesToRescan {
		if n.Name == "test-node-failed" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected vuln_scan_failed node with stale grype_db to be returned for rescan; got %d nodes: %+v",
			len(nodesToRescan), nodesToRescan)
	}
}

// TestGetNodesNeedingRescan_ExcludesUpToDate tests that up-to-date nodes are excluded
func TestGetNodesNeedingRescan_ExcludesUpToDate(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node-1", []byte(sbom))

	currentGrypeDB := time.Now()
	_ = db.StoreNodeVulnerabilities("test-node-1", []byte(`{"matches": []}`), currentGrypeDB)

	// Query with same grype DB time
	nodesToRescan, err := db.GetNodesNeedingRescan(currentGrypeDB)
	if err != nil {
		t.Fatalf("GetNodesNeedingRescan failed: %v", err)
	}

	if len(nodesToRescan) != 0 {
		t.Errorf("Expected 0 nodes needing rescan, got %d", len(nodesToRescan))
	}
}

// TestRemoveNode_CascadesDeleteToPackagesAndVulns tests that removal cascades
func TestRemoveNode_CascadesDeleteToPackagesAndVulns(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node-1", []byte(sbom))

	vulnReport := `{"matches": [
		{"vulnerability": {"id": "CVE-2021-1234", "severity": "High"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}}
	]}`
	_ = db.StoreNodeVulnerabilities("test-node-1", []byte(vulnReport), time.Now())

	// Verify data exists
	packages, _ := db.GetNodePackages("test-node-1")
	if len(packages) == 0 {
		t.Fatal("Expected packages before removal")
	}

	vulns, _ := db.GetNodeVulnerabilities("test-node-1")
	if len(vulns) == 0 {
		t.Fatal("Expected vulnerabilities before removal")
	}

	// Remove node
	err := db.RemoveNode("test-node-1")
	if err != nil {
		t.Fatalf("RemoveNode failed: %v", err)
	}

	// Verify all data is gone
	var pkgCount, vulnCount int
	_ = db.conn.QueryRow("SELECT COUNT(*) FROM node_packages").Scan(&pkgCount)
	_ = db.conn.QueryRow("SELECT COUNT(*) FROM node_vulnerabilities").Scan(&vulnCount)

	if pkgCount != 0 {
		t.Errorf("Expected 0 packages after removal, got %d", pkgCount)
	}
	if vulnCount != 0 {
		t.Errorf("Expected 0 vulnerabilities after removal, got %d", vulnCount)
	}
}

// TestStoreNodeSBOM_StoresDetailsInSeparateTable tests that package details are stored separately
func TestStoreNodeSBOM_StoresDetailsInSeparateTable(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	sbom := `{"artifacts": [
		{"name": "openssl", "version": "1.1.1", "type": "deb", "purl": "pkg:deb/ubuntu/openssl@1.1.1"}
	]}`
	err := db.StoreNodeSBOM("test-node-1", []byte(sbom))
	if err != nil {
		t.Fatalf("StoreNodeSBOM failed: %v", err)
	}

	// Get the package ID
	packages, err := db.GetNodePackages("test-node-1")
	if err != nil {
		t.Fatalf("GetNodePackages failed: %v", err)
	}
	if len(packages) != 1 {
		t.Fatalf("Expected 1 package, got %d", len(packages))
	}

	// Retrieve details from separate table
	details, err := db.GetNodePackageDetails(packages[0].ID)
	if err != nil {
		t.Fatalf("GetNodePackageDetails failed: %v", err)
	}

	// Details should be a JSON array
	var detailsArr []json.RawMessage
	if err := json.Unmarshal([]byte(details), &detailsArr); err != nil {
		t.Fatalf("Details should be valid JSON array: %v", err)
	}

	if len(detailsArr) != 1 {
		t.Errorf("Expected 1 detail entry, got %d", len(detailsArr))
	}
}

// TestStoreNodeSBOM_AggregatesInstanceDetails tests that multiple instances are aggregated
func TestStoreNodeSBOM_AggregatesInstanceDetails(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	// Same package appearing in multiple locations
	sbom := `{"artifacts": [
		{"name": "lodash", "version": "4.17.21", "type": "npm", "locations": [{"path": "/app/node_modules/lodash"}]},
		{"name": "lodash", "version": "4.17.21", "type": "npm", "locations": [{"path": "/lib/node_modules/lodash"}]},
		{"name": "lodash", "version": "4.17.21", "type": "npm", "locations": [{"path": "/other/node_modules/lodash"}]}
	]}`
	err := db.StoreNodeSBOM("test-node-1", []byte(sbom))
	if err != nil {
		t.Fatalf("StoreNodeSBOM failed: %v", err)
	}

	// Should have 1 unique package with count=3
	packages, err := db.GetNodePackages("test-node-1")
	if err != nil {
		t.Fatalf("GetNodePackages failed: %v", err)
	}
	if len(packages) != 1 {
		t.Fatalf("Expected 1 unique package, got %d", len(packages))
	}
	if packages[0].Count != 3 {
		t.Errorf("Expected count=3, got %d", packages[0].Count)
	}

	// Details should contain all 3 instances
	details, err := db.GetNodePackageDetails(packages[0].ID)
	if err != nil {
		t.Fatalf("GetNodePackageDetails failed: %v", err)
	}

	var detailsArr []json.RawMessage
	if err := json.Unmarshal([]byte(details), &detailsArr); err != nil {
		t.Fatalf("Details should be valid JSON array: %v", err)
	}

	if len(detailsArr) != 3 {
		t.Errorf("Expected 3 detail entries (all instances), got %d", len(detailsArr))
	}
}

// TestStoreNodeVulnerabilities_StoresDetailsInSeparateTable tests that vuln details are stored separately
func TestStoreNodeVulnerabilities_StoresDetailsInSeparateTable(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node-1", []byte(sbom))

	vulnReport := `{"matches": [
		{
			"vulnerability": {"id": "CVE-2021-1234", "severity": "High", "risk": 7.5},
			"artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"},
			"relatedVulnerabilities": [{"id": "CVE-2021-1234"}]
		}
	]}`
	err := db.StoreNodeVulnerabilities("test-node-1", []byte(vulnReport), time.Now())
	if err != nil {
		t.Fatalf("StoreNodeVulnerabilities failed: %v", err)
	}

	vulns, err := db.GetNodeVulnerabilities("test-node-1")
	if err != nil {
		t.Fatalf("GetNodeVulnerabilities failed: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("Expected 1 vulnerability, got %d", len(vulns))
	}

	// Retrieve details from separate table
	details, err := db.GetNodeVulnerabilityDetails(vulns[0].ID)
	if err != nil {
		t.Fatalf("GetNodeVulnerabilityDetails failed: %v", err)
	}

	// Details should be a JSON array
	var detailsArr []json.RawMessage
	if err := json.Unmarshal([]byte(details), &detailsArr); err != nil {
		t.Fatalf("Details should be valid JSON array: %v", err)
	}

	if len(detailsArr) != 1 {
		t.Errorf("Expected 1 detail entry, got %d", len(detailsArr))
	}
}

// TestStoreNodeVulnerabilities_DeduplicatesWithCount tests that duplicate vulns are aggregated
func TestStoreNodeVulnerabilities_DeduplicatesWithCount(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node-1"}
	_, _ = db.AddNode(node)

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node-1", []byte(sbom))

	// Same CVE appearing multiple times for same package (e.g., from different matchers)
	vulnReport := `{"matches": [
		{
			"vulnerability": {"id": "CVE-2021-1234", "severity": "High", "risk": 7.5},
			"artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"},
			"matchDetails": [{"type": "exact-direct-match"}]
		},
		{
			"vulnerability": {"id": "CVE-2021-1234", "severity": "High", "risk": 7.5},
			"artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"},
			"matchDetails": [{"type": "cpe-match"}]
		},
		{
			"vulnerability": {"id": "CVE-2021-1234", "severity": "High", "risk": 7.5},
			"artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"},
			"matchDetails": [{"type": "another-match"}]
		}
	]}`
	err := db.StoreNodeVulnerabilities("test-node-1", []byte(vulnReport), time.Now())
	if err != nil {
		t.Fatalf("StoreNodeVulnerabilities failed: %v", err)
	}

	// Should have 1 unique vulnerability with count=3
	vulns, err := db.GetNodeVulnerabilities("test-node-1")
	if err != nil {
		t.Fatalf("GetNodeVulnerabilities failed: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("Expected 1 unique vulnerability (deduplicated), got %d", len(vulns))
	}
	if vulns[0].Count != 3 {
		t.Errorf("Expected count=3, got %d", vulns[0].Count)
	}

	// Details should contain all 3 instances
	details, err := db.GetNodeVulnerabilityDetails(vulns[0].ID)
	if err != nil {
		t.Fatalf("GetNodeVulnerabilityDetails failed: %v", err)
	}

	var detailsArr []json.RawMessage
	if err := json.Unmarshal([]byte(details), &detailsArr); err != nil {
		t.Fatalf("Details should be valid JSON array: %v", err)
	}

	if len(detailsArr) != 3 {
		t.Errorf("Expected 3 detail entries (all instances), got %d", len(detailsArr))
	}
}

// TestGetNodeVulnerabilityDetails_ReturnsEmptyArrayForMissing tests missing details return empty array
func TestGetNodeVulnerabilityDetails_ReturnsEmptyArrayForMissing(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	// Query for non-existent vulnerability
	details, err := db.GetNodeVulnerabilityDetails(99999)
	if err != nil {
		t.Fatalf("GetNodeVulnerabilityDetails should not error for missing: %v", err)
	}
	if details != "[]" {
		t.Errorf("Expected empty array '[]', got %s", details)
	}
}

// TestGetNodePackageDetails_ReturnsEmptyArrayForMissing tests missing details return empty array
func TestGetNodePackageDetails_ReturnsEmptyArrayForMissing(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	// Query for non-existent package
	details, err := db.GetNodePackageDetails(99999)
	if err != nil {
		t.Fatalf("GetNodePackageDetails should not error for missing: %v", err)
	}
	if details != "[]" {
		t.Errorf("Expected empty array '[]', got %s", details)
	}
}

// TestGetScannedNodes tests retrieving completed nodes for metrics
func TestGetScannedNodes(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	// Create nodes with different statuses
	node1 := nodes.Node{Name: "completed-node", Hostname: "host1.local", OSRelease: "Ubuntu 22.04", KernelVersion: "5.15.0", Architecture: "amd64"}
	node2 := nodes.Node{Name: "pending-node", Hostname: "host2.local", OSRelease: "Ubuntu 22.04", Architecture: "arm64"}
	node3 := nodes.Node{Name: "another-completed", Hostname: "host3.local", OSRelease: "Amazon Linux 2023", Architecture: "amd64"}

	_, _ = db.AddNode(node1)
	_, _ = db.AddNode(node2)
	_, _ = db.AddNode(node3)

	// Mark node1 and node3 as completed, leave node2 as pending
	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("completed-node", []byte(sbom))
	_ = db.StoreNodeVulnerabilities("completed-node", []byte(`{"matches": []}`), time.Now())

	_ = db.StoreNodeSBOM("another-completed", []byte(sbom))
	_ = db.StoreNodeVulnerabilities("another-completed", []byte(`{"matches": []}`), time.Now())

	// Get scanned nodes
	scannedNodes, err := db.GetScannedNodes()
	if err != nil {
		t.Fatalf("GetScannedNodes failed: %v", err)
	}

	// Should only return completed nodes
	if len(scannedNodes) != 2 {
		t.Errorf("Expected 2 completed nodes, got %d", len(scannedNodes))
	}

	// Verify node data is populated correctly
	for _, n := range scannedNodes {
		if n.Name == "completed-node" {
			if n.Hostname != "host1.local" {
				t.Errorf("Expected hostname host1.local, got %s", n.Hostname)
			}
			if n.OSRelease != "Ubuntu 22.04" {
				t.Errorf("Expected os_release Ubuntu 22.04, got %s", n.OSRelease)
			}
			if n.KernelVersion != "5.15.0" {
				t.Errorf("Expected kernel_version 5.15.0, got %s", n.KernelVersion)
			}
			if n.Architecture != "amd64" {
				t.Errorf("Expected architecture amd64, got %s", n.Architecture)
			}
		}
		if n.Name == "pending-node" {
			t.Error("pending-node should not be in scanned nodes list")
		}
	}
}

// TestGetScannedNodes_Empty tests that empty result returns empty slice
func TestGetScannedNodes_Empty(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	scannedNodes, err := db.GetScannedNodes()
	if err != nil {
		t.Fatalf("GetScannedNodes failed: %v", err)
	}

	if scannedNodes == nil {
		t.Error("Expected empty slice, not nil")
	}
	if len(scannedNodes) != 0 {
		t.Errorf("Expected 0 nodes, got %d", len(scannedNodes))
	}
}

// TestGetNodeVulnerabilitiesForMetrics tests retrieving vulnerabilities for metrics export
func TestGetNodeVulnerabilitiesForMetrics(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{
		Name:          "test-node",
		Hostname:      "test-node.local",
		OSRelease:     "Ubuntu 22.04",
		KernelVersion: "5.15.0-91-generic",
		Architecture:  "amd64",
	}
	_, _ = db.AddNode(node)

	sbom := `{"artifacts": [
		{"name": "openssl", "version": "3.0.2", "type": "deb"},
		{"name": "curl", "version": "7.81.0", "type": "deb"}
	]}`
	_ = db.StoreNodeSBOM("test-node", []byte(sbom))

	vulnReport := `{"matches": [
		{
			"vulnerability": {
				"id": "CVE-2024-1234",
				"severity": "Critical",
				"risk": 9.8,
				"fix": {"state": "fixed", "versions": ["3.0.13"]},
				"knownExploited": [{"cve": "CVE-2024-1234"}]
			},
			"artifact": {"name": "openssl", "version": "3.0.2", "type": "deb"}
		},
		{
			"vulnerability": {
				"id": "CVE-2024-5678",
				"severity": "High",
				"risk": 7.5,
				"fix": {"state": "not-fixed"}
			},
			"artifact": {"name": "curl", "version": "7.81.0", "type": "deb"}
		}
	]}`
	_ = db.StoreNodeVulnerabilities("test-node", []byte(vulnReport), time.Now())

	// Get vulnerabilities for metrics
	vulns, err := db.GetNodeVulnerabilitiesForMetrics()
	if err != nil {
		t.Fatalf("GetNodeVulnerabilitiesForMetrics failed: %v", err)
	}

	if len(vulns) != 2 {
		t.Fatalf("Expected 2 vulnerabilities, got %d", len(vulns))
	}

	// Verify first vulnerability has all expected fields
	var criticalVuln *NodeVulnerabilityForMetrics
	for i := range vulns {
		if vulns[i].CVEID == "CVE-2024-1234" {
			criticalVuln = &vulns[i]
			break
		}
	}

	if criticalVuln == nil {
		t.Fatal("Expected to find CVE-2024-1234")
	}

	// Verify node info
	if criticalVuln.NodeName != "test-node" {
		t.Errorf("NodeName = %s, want test-node", criticalVuln.NodeName)
	}
	if criticalVuln.Hostname != "test-node.local" {
		t.Errorf("Hostname = %s, want test-node.local", criticalVuln.Hostname)
	}
	if criticalVuln.OSRelease != "Ubuntu 22.04" {
		t.Errorf("OSRelease = %s, want Ubuntu 22.04", criticalVuln.OSRelease)
	}
	if criticalVuln.KernelVersion != "5.15.0-91-generic" {
		t.Errorf("KernelVersion = %s, want 5.15.0-91-generic", criticalVuln.KernelVersion)
	}
	if criticalVuln.Architecture != "amd64" {
		t.Errorf("Architecture = %s, want amd64", criticalVuln.Architecture)
	}

	// Verify vulnerability info
	if criticalVuln.Severity != "Critical" {
		t.Errorf("Severity = %s, want Critical", criticalVuln.Severity)
	}
	if criticalVuln.Risk != 9.8 {
		t.Errorf("Risk = %f, want 9.8", criticalVuln.Risk)
	}
	if criticalVuln.FixStatus != "fixed" {
		t.Errorf("FixStatus = %s, want fixed", criticalVuln.FixStatus)
	}
	if criticalVuln.FixVersion != "3.0.13" {
		t.Errorf("FixVersion = %s, want 3.0.13", criticalVuln.FixVersion)
	}
	if criticalVuln.KnownExploited != 1 {
		t.Errorf("KnownExploited = %d, want 1", criticalVuln.KnownExploited)
	}

	// Verify package info
	if criticalVuln.PackageName != "openssl" {
		t.Errorf("PackageName = %s, want openssl", criticalVuln.PackageName)
	}
	if criticalVuln.PackageVersion != "3.0.2" {
		t.Errorf("PackageVersion = %s, want 3.0.2", criticalVuln.PackageVersion)
	}
	if criticalVuln.PackageType != "deb" {
		t.Errorf("PackageType = %s, want deb", criticalVuln.PackageType)
	}
}

// TestGetNodeVulnerabilitiesForMetrics_OnlyCompletedNodes tests that only completed nodes are included
func TestGetNodeVulnerabilitiesForMetrics_OnlyCompletedNodes(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	// Create two nodes
	node1 := nodes.Node{Name: "completed-node"}
	node2 := nodes.Node{Name: "pending-node"}
	_, _ = db.AddNode(node1)
	_, _ = db.AddNode(node2)

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.0", "type": "deb"}]}`
	vulnReport := `{"matches": [{"vulnerability": {"id": "CVE-2024-0001", "severity": "High"}, "artifact": {"name": "openssl", "version": "1.0", "type": "deb"}}]}`

	// Complete first node
	_ = db.StoreNodeSBOM("completed-node", []byte(sbom))
	_ = db.StoreNodeVulnerabilities("completed-node", []byte(vulnReport), time.Now())

	// Only store SBOM for second node (leaves it in scanning_vulnerabilities status)
	_ = db.StoreNodeSBOM("pending-node", []byte(sbom))

	vulns, err := db.GetNodeVulnerabilitiesForMetrics()
	if err != nil {
		t.Fatalf("GetNodeVulnerabilitiesForMetrics failed: %v", err)
	}

	// Should only include vulnerabilities from completed node
	if len(vulns) != 1 {
		t.Errorf("Expected 1 vulnerability (from completed node only), got %d", len(vulns))
	}

	if len(vulns) > 0 && vulns[0].NodeName != "completed-node" {
		t.Errorf("Expected vulnerability from completed-node, got %s", vulns[0].NodeName)
	}
}

// TestGetNodeVulnerabilitiesForMetrics_Empty tests empty result returns empty slice
func TestGetNodeVulnerabilitiesForMetrics_Empty(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	vulns, err := db.GetNodeVulnerabilitiesForMetrics()
	if err != nil {
		t.Fatalf("GetNodeVulnerabilitiesForMetrics failed: %v", err)
	}

	if vulns == nil {
		t.Error("Expected empty slice, not nil")
	}
	if len(vulns) != 0 {
		t.Errorf("Expected 0 vulnerabilities, got %d", len(vulns))
	}
}

// TestGetNodeVulnerabilitiesForMetrics_DeduplicatedCount tests that count is preserved
func TestGetNodeVulnerabilitiesForMetrics_DeduplicatedCount(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	node := nodes.Node{Name: "test-node"}
	_, _ = db.AddNode(node)

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.0", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node", []byte(sbom))

	// Same CVE appearing 3 times (e.g., from different matchers)
	vulnReport := `{"matches": [
		{"vulnerability": {"id": "CVE-2024-0001", "severity": "High"}, "artifact": {"name": "openssl", "version": "1.0", "type": "deb"}},
		{"vulnerability": {"id": "CVE-2024-0001", "severity": "High"}, "artifact": {"name": "openssl", "version": "1.0", "type": "deb"}},
		{"vulnerability": {"id": "CVE-2024-0001", "severity": "High"}, "artifact": {"name": "openssl", "version": "1.0", "type": "deb"}}
	]}`
	_ = db.StoreNodeVulnerabilities("test-node", []byte(vulnReport), time.Now())

	vulns, err := db.GetNodeVulnerabilitiesForMetrics()
	if err != nil {
		t.Fatalf("GetNodeVulnerabilitiesForMetrics failed: %v", err)
	}

	if len(vulns) != 1 {
		t.Fatalf("Expected 1 deduplicated vulnerability, got %d", len(vulns))
	}

	if vulns[0].Count != 3 {
		t.Errorf("Expected Count=3, got %d", vulns[0].Count)
	}
}

// TestGetNodeScanStatusCounts verifies node counts are grouped by status and
// zero-filled across all statuses in the scan_status table.
func TestGetNodeScanStatusCounts(t *testing.T) {
	db, cleanup := createTestDB(t)
	defer cleanup()

	// 2 completed, 1 vuln_scan_failed (default status on AddNode is "pending").
	for _, n := range []string{"n1", "n2", "n3", "n4"} {
		if _, err := db.AddNode(nodes.Node{Name: n, Hostname: n, Architecture: "amd64"}); err != nil {
			t.Fatalf("AddNode %s: %v", n, err)
		}
	}
	for _, n := range []string{"n1", "n2"} {
		if err := db.UpdateNodeStatus(n, StatusCompleted, ""); err != nil {
			t.Fatalf("UpdateNodeStatus %s: %v", n, err)
		}
	}
	if err := db.UpdateNodeStatus("n3", StatusVulnScanFailed, "boom"); err != nil {
		t.Fatalf("UpdateNodeStatus n3: %v", err)
	}
	// n4 stays pending

	counts, err := db.GetNodeScanStatusCounts()
	if err != nil {
		t.Fatalf("GetNodeScanStatusCounts: %v", err)
	}

	got := map[string]int{}
	for _, c := range counts {
		got[c.Status] = c.Count
	}
	if got["completed"] != 2 {
		t.Errorf("completed: want 2, got %d", got["completed"])
	}
	if got["vuln_scan_failed"] != 1 {
		t.Errorf("vuln_scan_failed: want 1, got %d", got["vuln_scan_failed"])
	}
	if got["pending"] != 1 {
		t.Errorf("pending: want 1, got %d", got["pending"])
	}
	// zero-fill: a known status with no nodes should still be present with 0.
	if _, ok := got["completed"]; !ok {
		t.Error("expected statuses to be zero-filled from scan_status table")
	}
}
