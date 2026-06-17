package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// createTestDBForHandlers creates a temporary test database
func createTestDBForHandlers(t *testing.T) (*database.DB, func()) {
	t.Helper()
	dbPath := "/tmp/test_handlers_nodes_" + time.Now().Format("20060102150405.000") + ".db"
	db, err := database.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	cleanup := func() {
		_ = database.Close(db)
		_ = os.Remove(dbPath)
	}
	return db, cleanup
}

// TestListNodesHandler_ReturnsEmptyList tests empty node list
func TestListNodesHandler_ReturnsEmptyList(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	handler := ListNodesHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	var result []nodes.NodeWithStatus
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// Empty list should have length 0 (may be null or [] in JSON)
	if len(result) != 0 {
		t.Errorf("Expected empty list, got %d nodes", len(result))
	}
}

// TestListNodesHandler_ReturnsNodes tests listing nodes
func TestListNodesHandler_ReturnsNodes(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	// Add test nodes
	_, _ = db.AddNode(nodes.Node{Name: "node-1", Hostname: "node-1.local"})
	_, _ = db.AddNode(nodes.Node{Name: "node-2", Hostname: "node-2.local"})

	handler := ListNodesHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var result []nodes.NodeWithStatus
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected 2 nodes, got %d", len(result))
	}
}

// TestListNodesHandler_RejectsNonGet tests that non-GET methods are rejected
func TestListNodesHandler_RejectsNonGet(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	handler := ListNodesHandler(db)

	methods := []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch}
	for _, method := range methods {
		req := httptest.NewRequest(method, "/api/nodes", nil)
		w := httptest.NewRecorder()

		handler(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("Method %s: Expected status 405, got %d", method, w.Code)
		}
	}
}

// TestNodeDetailHandler_ReturnsNode tests getting a single node
func TestNodeDetailHandler_ReturnsNode(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{
		Name:         "test-node",
		Hostname:     "test-node.local",
		OSRelease:    "Ubuntu 22.04",
		Architecture: "amd64",
	})

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/test-node", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var result nodes.NodeWithStatus
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if result.Name != "test-node" {
		t.Errorf("Expected name=test-node, got %s", result.Name)
	}
	if result.Hostname != "test-node.local" {
		t.Errorf("Expected hostname=test-node.local, got %s", result.Hostname)
	}
}

// TestNodeDetailHandler_ReturnsNotFound tests 404 for missing node
func TestNodeDetailHandler_ReturnsNotFound(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/nonexistent", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d; body: %s", w.Code, w.Body.String())
	}
}

// TestNodeDetailHandler_RequiresNodeName tests that node name is required
func TestNodeDetailHandler_RequiresNodeName(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

// TestNodeDetailHandler_Packages tests getting node packages
func TestNodeDetailHandler_Packages(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{Name: "test-node"})

	sbom := `{"artifacts": [
		{"name": "openssl", "version": "1.1.1", "type": "deb"},
		{"name": "curl", "version": "7.68.0", "type": "deb"}
	]}`
	_ = db.StoreNodeSBOM("test-node", []byte(sbom))

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/test-node/packages", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var result []nodes.NodePackage
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected 2 packages, got %d", len(result))
	}
}

// TestNodeDetailHandler_PackagesFormatJSON tests getting raw SBOM with format=json
func TestNodeDetailHandler_PackagesFormatJSON(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{Name: "test-node"})

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}], "source": {"type": "image"}}`
	_ = db.StoreNodeSBOM("test-node", []byte(sbom))

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/test-node/packages?format=json", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	contentDisp := w.Header().Get("Content-Disposition")
	if contentDisp == "" {
		t.Error("Expected Content-Disposition header to be set")
	}

	// Should return raw SBOM, not parsed packages
	var rawSBOM map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &rawSBOM); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if _, ok := rawSBOM["artifacts"]; !ok {
		t.Error("Expected raw SBOM with 'artifacts' key")
	}
	if _, ok := rawSBOM["source"]; !ok {
		t.Error("Expected raw SBOM with 'source' key")
	}
}

// TestNodeDetailHandler_PackagesFormatJSON_NotFound tests 404 when SBOM doesn't exist
func TestNodeDetailHandler_PackagesFormatJSON_NotFound(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{Name: "test-node"})
	// Don't store SBOM

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/test-node/packages?format=json", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

// TestNodeDetailHandler_Vulnerabilities tests getting node vulnerabilities
func TestNodeDetailHandler_Vulnerabilities(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{Name: "test-node"})

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node", []byte(sbom))

	vulnReport := `{"matches": [
		{"vulnerability": {"id": "CVE-2021-1234", "severity": "High"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}},
		{"vulnerability": {"id": "CVE-2021-5678", "severity": "Critical"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}}
	]}`
	_ = db.StoreNodeVulnerabilities("test-node", []byte(vulnReport), time.Now())

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/test-node/vulnerabilities", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var result []nodes.NodeVulnerability
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected 2 vulnerabilities, got %d", len(result))
	}
}

// TestNodeDetailHandler_VulnerabilitiesFormatJSON tests getting raw vulnerabilities with format=json
func TestNodeDetailHandler_VulnerabilitiesFormatJSON(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{Name: "test-node"})

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node", []byte(sbom))

	vulnReport := `{"matches": [{"vulnerability": {"id": "CVE-2021-1234", "severity": "High"}, "artifact": {"name": "openssl"}}], "source": {"type": "sbom"}}`
	_ = db.StoreNodeVulnerabilities("test-node", []byte(vulnReport), time.Now())

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/test-node/vulnerabilities?format=json", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	contentDisp := w.Header().Get("Content-Disposition")
	if contentDisp == "" {
		t.Error("Expected Content-Disposition header to be set")
	}

	// Should return raw Grype output, not parsed vulnerabilities
	var rawVulns map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &rawVulns); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if _, ok := rawVulns["matches"]; !ok {
		t.Error("Expected raw vulnerabilities with 'matches' key")
	}
	if _, ok := rawVulns["source"]; !ok {
		t.Error("Expected raw vulnerabilities with 'source' key")
	}
}

// TestNodeDetailHandler_VulnerabilitiesFormatJSON_NotFound tests 404 when vulnerabilities don't exist
func TestNodeDetailHandler_VulnerabilitiesFormatJSON_NotFound(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{Name: "test-node"})
	// Don't store vulnerabilities

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/test-node/vulnerabilities?format=json", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

// TestNodeDetailHandler_PackagesFormatCSV tests getting packages as CSV
func TestNodeDetailHandler_PackagesFormatCSV(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{Name: "test-node"})

	sbom := `{"artifacts": [
		{"name": "openssl", "version": "1.1.1", "type": "deb", "purl": "pkg:deb/openssl@1.1.1"},
		{"name": "curl", "version": "7.68.0", "type": "deb", "purl": "pkg:deb/curl@7.68.0"}
	]}`
	_ = db.StoreNodeSBOM("test-node", []byte(sbom))

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/test-node/packages?format=csv", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "text/csv" {
		t.Errorf("Expected Content-Type text/csv, got %s", contentType)
	}

	contentDisp := w.Header().Get("Content-Disposition")
	if contentDisp == "" {
		t.Error("Expected Content-Disposition header to be set")
	}
	if contentDisp != `attachment; filename="packages-test-node.csv"` {
		t.Errorf("Unexpected Content-Disposition: %s", contentDisp)
	}

	// Check CSV content
	body := w.Body.String()
	if body == "" {
		t.Error("Expected CSV body, got empty")
	}
	// Should contain header row
	if !contains(body, "name,version,type,purl,count") {
		t.Error("Expected CSV header row with name,version,type,purl,count")
	}
	// Should contain data rows
	if !contains(body, "openssl") {
		t.Error("Expected CSV to contain 'openssl'")
	}
	if !contains(body, "curl") {
		t.Error("Expected CSV to contain 'curl'")
	}
}

// TestNodeDetailHandler_VulnerabilitiesFormatCSV tests getting vulnerabilities as CSV
func TestNodeDetailHandler_VulnerabilitiesFormatCSV(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{Name: "test-node"})

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("test-node", []byte(sbom))

	vulnReport := `{"matches": [
		{"vulnerability": {"id": "CVE-2021-1234", "severity": "High", "cvss": [{"metrics": {"baseScore": 7.5}}]}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}, "matchDetails": [{"found": {"versionConstraint": "<1.1.2"}}]},
		{"vulnerability": {"id": "CVE-2021-5678", "severity": "Critical", "cvss": [{"metrics": {"baseScore": 9.8}}]}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}, "matchDetails": [{"found": {"versionConstraint": "<1.2.0"}}]}
	]}`
	_ = db.StoreNodeVulnerabilities("test-node", []byte(vulnReport), time.Now())

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/test-node/vulnerabilities?format=csv", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "text/csv" {
		t.Errorf("Expected Content-Type text/csv, got %s", contentType)
	}

	contentDisp := w.Header().Get("Content-Disposition")
	if contentDisp == "" {
		t.Error("Expected Content-Disposition header to be set")
	}
	if contentDisp != `attachment; filename="vulnerabilities-test-node.csv"` {
		t.Errorf("Unexpected Content-Disposition: %s", contentDisp)
	}

	// Check CSV content
	body := w.Body.String()
	if body == "" {
		t.Error("Expected CSV body, got empty")
	}
	// Should contain header row
	if !contains(body, "cve_id,severity,score,package_name,package_version,package_type,fix_status,fix_version,known_exploited,count") {
		t.Error("Expected CSV header row")
	}
	// Should contain data rows
	if !contains(body, "CVE-2021-1234") {
		t.Error("Expected CSV to contain 'CVE-2021-1234'")
	}
	if !contains(body, "CVE-2021-5678") {
		t.Error("Expected CSV to contain 'CVE-2021-5678'")
	}
	if !contains(body, "Critical") {
		t.Error("Expected CSV to contain 'Critical'")
	}
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestNodeDetailHandler_UnknownSubresource tests 404 for unknown subresource
func TestNodeDetailHandler_UnknownSubresource(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{Name: "test-node"})

	handler := NodeDetailHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/nodes/test-node/unknown", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

// TestNodeSummaryHandler_ReturnsSummaries tests getting node summaries
func TestNodeSummaryHandler_ReturnsSummaries(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{Name: "node-1"})
	_, _ = db.AddNode(nodes.Node{Name: "node-2"})

	// Add packages and vulns to node-1
	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("node-1", []byte(sbom))

	vulnReport := `{"matches": [
		{"vulnerability": {"id": "CVE-2021-0001", "severity": "Critical"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}},
		{"vulnerability": {"id": "CVE-2021-0002", "severity": "High"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}}
	]}`
	_ = db.StoreNodeVulnerabilities("node-1", []byte(vulnReport), time.Now())

	handler := NodeSummaryHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/summary/by-node", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var result []nodes.NodeSummary
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if len(result) != 2 {
		t.Errorf("Expected 2 summaries, got %d", len(result))
	}

	// Find node-1 summary and verify counts
	for _, s := range result {
		if s.NodeName == "node-1" {
			if s.Critical != 1 {
				t.Errorf("node-1: Expected Critical=1, got %d", s.Critical)
			}
			if s.High != 1 {
				t.Errorf("node-1: Expected High=1, got %d", s.High)
			}
			if s.Total != 2 {
				t.Errorf("node-1: Expected Total=2, got %d", s.Total)
			}
		}
	}
}

// TestNodeSummaryHandler_RejectsNonGet tests that non-GET methods are rejected
func TestNodeSummaryHandler_RejectsNonGet(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	handler := NodeSummaryHandler(db)

	req := httptest.NewRequest(http.MethodPost, "/api/summary/by-node", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

// TestRegisterNodeHandlers_RegistersAllRoutes tests that all routes are registered
func TestRegisterNodeHandlers_RegistersAllRoutes(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	mux := http.NewServeMux()
	RegisterNodeHandlers(mux, db)

	// Test each route responds (not 404 from ServeMux)
	routes := []string{
		"/api/nodes",
		"/api/nodes/test-node",
		"/api/summary/by-node",
	}

	for _, route := range routes {
		req := httptest.NewRequest(http.MethodGet, route, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		// Should not be 404 from mux (handler not found)
		// The actual response might be 404 (node not found) or 200, but not mux 404
		if w.Code == http.StatusNotFound && w.Body.String() == "404 page not found\n" {
			t.Errorf("Route %s not registered (got mux 404)", route)
		}
	}
}

// TestNodeSummaryHandler_ReturnsTotalRiskAndExploitCount tests that summaries include risk and exploit fields
func TestNodeSummaryHandler_ReturnsTotalRiskAndExploitCount(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{Name: "node-1"})

	// Add packages and vulns with score and known_exploited
	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("node-1", []byte(sbom))

	// Vulnerability with risk score and known_exploited (risk field is used, not cvss)
	vulnReport := `{"matches": [
		{"vulnerability": {"id": "CVE-2021-0001", "severity": "Critical", "risk": 9.8, "knownExploited": [{"cve": "CVE-2021-0001"}]}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}, "matchDetails": [{"found": {"versionConstraint": "<1.2"}}]}
	]}`
	_ = db.StoreNodeVulnerabilities("node-1", []byte(vulnReport), time.Now())

	handler := NodeSummaryHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/summary/by-node", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var result []nodes.NodeSummary
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected 1 summary, got %d", len(result))
	}

	// Check that TotalRisk and ExploitCount are present
	if result[0].TotalRisk == 0 {
		t.Error("Expected TotalRisk > 0")
	}
	if result[0].ExploitCount != 1 {
		t.Errorf("Expected ExploitCount=1, got %d", result[0].ExploitCount)
	}
}

// TestNodeSummaryHandler_FormatCSV tests CSV export
func TestNodeSummaryHandler_FormatCSV(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{Name: "node-1", OSRelease: "Ubuntu 22.04"})

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("node-1", []byte(sbom))

	vulnReport := `{"matches": [
		{"vulnerability": {"id": "CVE-2021-0001", "severity": "Critical"}, "artifact": {"name": "openssl", "version": "1.1.1", "type": "deb"}, "matchDetails": [{"found": {"versionConstraint": "<1.2"}}]}
	]}`
	_ = db.StoreNodeVulnerabilities("node-1", []byte(vulnReport), time.Now())

	handler := NodeSummaryHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/summary/by-node?format=csv", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "text/csv" {
		t.Errorf("Expected Content-Type text/csv, got %s", contentType)
	}

	contentDisp := w.Header().Get("Content-Disposition")
	if contentDisp != "attachment; filename=node_summary.csv" {
		t.Errorf("Unexpected Content-Disposition: %s", contentDisp)
	}

	body := w.Body.String()
	// Check header row
	if !contains(body, "Node Name") || !contains(body, "Risk Score") || !contains(body, "Known Exploits") {
		t.Error("CSV header missing expected columns")
	}
	// Check data row
	if !contains(body, "node-1") || !contains(body, "Ubuntu 22.04") {
		t.Error("CSV data missing expected values")
	}
}

// TestNodeDistributionSummaryHandler_ReturnsData tests basic functionality
func TestNodeDistributionSummaryHandler_ReturnsData(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	// Add nodes with different OS releases
	_, _ = db.AddNode(nodes.Node{Name: "node-1", OSRelease: "Ubuntu 22.04"})
	_, _ = db.AddNode(nodes.Node{Name: "node-2", OSRelease: "Ubuntu 22.04"})

	// Complete the scan for these nodes
	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("node-1", []byte(sbom))
	_ = db.StoreNodeSBOM("node-2", []byte(sbom))

	vulnReport := `{"matches": []}`
	_ = db.StoreNodeVulnerabilities("node-1", []byte(vulnReport), time.Now())
	_ = db.StoreNodeVulnerabilities("node-2", []byte(vulnReport), time.Now())

	handler := NodeDistributionSummaryHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/summary/by-node-distro", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var result []nodes.NodeDistributionSummary
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if len(result) != 1 {
		t.Fatalf("Expected 1 distribution, got %d", len(result))
	}

	if result[0].OSName != "Ubuntu 22.04" {
		t.Errorf("Expected OSName='Ubuntu 22.04', got '%s'", result[0].OSName)
	}
	if result[0].NodeCount != 2 {
		t.Errorf("Expected NodeCount=2, got %d", result[0].NodeCount)
	}
}

// TestNodeDistributionSummaryHandler_FormatCSV tests CSV export
func TestNodeDistributionSummaryHandler_FormatCSV(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	_, _ = db.AddNode(nodes.Node{Name: "node-1", OSRelease: "Ubuntu 22.04"})

	sbom := `{"artifacts": [{"name": "openssl", "version": "1.1.1", "type": "deb"}]}`
	_ = db.StoreNodeSBOM("node-1", []byte(sbom))

	vulnReport := `{"matches": []}`
	_ = db.StoreNodeVulnerabilities("node-1", []byte(vulnReport), time.Now())

	handler := NodeDistributionSummaryHandler(db)

	req := httptest.NewRequest(http.MethodGet, "/api/summary/by-node-distro?format=csv", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "text/csv" {
		t.Errorf("Expected Content-Type text/csv, got %s", contentType)
	}

	contentDisp := w.Header().Get("Content-Disposition")
	if contentDisp != "attachment; filename=node_distribution_summary.csv" {
		t.Errorf("Unexpected Content-Disposition: %s", contentDisp)
	}

	body := w.Body.String()
	// Check header row
	if !contains(body, "OS Distribution") || !contains(body, "Node Count") || !contains(body, "Avg Critical") {
		t.Error("CSV header missing expected columns")
	}
	// Check data row
	if !contains(body, "Ubuntu 22.04") {
		t.Error("CSV data missing expected values")
	}
}

// TestNodeDistributionSummaryHandler_RejectsNonGet tests that non-GET methods are rejected
func TestNodeDistributionSummaryHandler_RejectsNonGet(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	handler := NodeDistributionSummaryHandler(db)

	req := httptest.NewRequest(http.MethodPost, "/api/summary/by-node-distro", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}
