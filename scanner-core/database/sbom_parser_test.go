package database

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

// TestSyftPackage_UnmarshalJSON tests that SyftPackage correctly extracts index fields and preserves raw JSON
func TestSyftPackage_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantName    string
		wantVersion string
		wantType    string
		wantErr     bool
	}{
		{
			name: "Complete package with all fields",
			input: `{
				"name": "openssl",
				"version": "1.1.1w",
				"type": "deb",
				"cpes": ["cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*"],
				"purl": "pkg:deb/debian/openssl@1.1.1w",
				"licenses": ["Apache-2.0"]
			}`,
			wantName:    "openssl",
			wantVersion: "1.1.1w",
			wantType:    "deb",
			wantErr:     false,
		},
		{
			name:        "Minimal package",
			input:       `{"name":"nginx","version":"1.21","type":"rpm"}`,
			wantName:    "nginx",
			wantVersion: "1.21",
			wantType:    "rpm",
			wantErr:     false,
		},
		{
			name:    "Invalid JSON",
			input:   `{"name":"broken"`,
			wantErr: true,
		},
		{
			name:        "Missing fields defaults to empty strings",
			input:       `{"extra":"field"}`,
			wantName:    "",
			wantVersion: "",
			wantType:    "",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pkg SyftPackage
			err := json.Unmarshal([]byte(tt.input), &pkg)

			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Check extracted fields
			if pkg.Name != tt.wantName {
				t.Errorf("Name = %v, want %v", pkg.Name, tt.wantName)
			}
			if pkg.Version != tt.wantVersion {
				t.Errorf("Version = %v, want %v", pkg.Version, tt.wantVersion)
			}
			if pkg.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", pkg.Type, tt.wantType)
			}

			// Verify raw JSON is preserved
			if len(pkg.Raw) == 0 {
				t.Error("Raw JSON should be preserved but is empty")
			}
		})
	}
}

// TestSyftPackage_MarshalJSON tests that marshaling returns the raw JSON
func TestSyftPackage_MarshalJSON(t *testing.T) {
	input := `{"name":"test","version":"1.0","type":"deb","extra":"preserved"}`

	var pkg SyftPackage
	if err := json.Unmarshal([]byte(input), &pkg); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify Raw field is populated
	if len(pkg.Raw) == 0 {
		t.Fatal("Raw JSON is empty after unmarshal")
	}

	// Marshal back
	output, err := json.Marshal(pkg)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Verify output is not empty
	if len(output) == 0 {
		t.Fatal("Marshal returned empty output")
	}

	// Verify we get back the raw JSON (compare as maps to handle potential reordering)
	var inputMap, outputMap map[string]interface{}
	if err := json.Unmarshal([]byte(input), &inputMap); err != nil {
		t.Fatalf("Failed to unmarshal input to map: %v", err)
	}
	if err := json.Unmarshal(output, &outputMap); err != nil {
		t.Fatalf("Failed to unmarshal output to map: %v", err)
	}

	// Check that all original fields are preserved
	for key, val := range inputMap {
		outputVal, exists := outputMap[key]
		if !exists {
			t.Errorf("Field %s: missing in output", key)
			continue
		}
		// Convert both to strings for comparison to handle type differences
		if fmt.Sprint(outputVal) != fmt.Sprint(val) {
			t.Errorf("Field %s: got %v (type %T), want %v (type %T)", key, outputVal, outputVal, val, val)
		}
	}
}

// TestSyftPackage_PreservesAllFields verifies that future Syft fields are preserved
func TestSyftPackage_PreservesAllFields(t *testing.T) {
	// Simulate a future Syft version adding new fields
	input := `{
		"name": "curl",
		"version": "7.68.0",
		"type": "deb",
		"futureField1": "preserved",
		"futureField2": {"nested": "also preserved"},
		"futureArray": ["item1", "item2"]
	}`

	var pkg SyftPackage
	if err := json.Unmarshal([]byte(input), &pkg); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Verify indexed fields were extracted
	if pkg.Name != "curl" {
		t.Errorf("Name not extracted: got %v", pkg.Name)
	}

	// Marshal back and verify future fields are still there
	output, err := json.Marshal(pkg)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	// Check future fields are preserved
	if val, ok := result["futureField1"]; !ok || val != "preserved" {
		t.Errorf("futureField1 was not preserved: got %v", result["futureField1"])
	}
	if _, ok := result["futureField2"]; !ok {
		t.Error("futureField2 was not preserved")
	}
	if _, ok := result["futureArray"]; !ok {
		t.Error("futureArray was not preserved")
	}
}

// TestGrypeMatch_UnmarshalJSON tests vulnerability match unmarshaling
func TestGrypeMatch_UnmarshalJSON(t *testing.T) {
	input := `{
		"vulnerability": {
			"id": "CVE-2024-1234",
			"severity": "High",
			"fix": {
				"versions": ["1.2.3"],
				"state": "fixed"
			},
			"risk": 8.5,
			"epss": [{"cve":"CVE-2024-1234","epss":0.05,"percentile":0.92,"date":"2024-01-01"}],
			"knownExploited": []
		},
		"artifact": {
			"name": "libssl1.1",
			"version": "1.1.1",
			"type": "deb"
		},
		"matchDetails": [{"type": "exact-direct-match"}]
	}`

	var match GrypeMatch
	err := json.Unmarshal([]byte(input), &match)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Check extracted fields
	if match.Vulnerability.ID != "CVE-2024-1234" {
		t.Errorf("Vulnerability ID = %v, want CVE-2024-1234", match.Vulnerability.ID)
	}
	if match.Vulnerability.Severity != "High" {
		t.Errorf("Severity = %v, want High", match.Vulnerability.Severity)
	}
	if match.Artifact.Name != "libssl1.1" {
		t.Errorf("Artifact name = %v, want libssl1.1", match.Artifact.Name)
	}

	// Verify raw JSON is preserved
	if len(match.Raw) == 0 {
		t.Error("Raw JSON should be preserved but is empty")
	}

	// Verify matchDetails is preserved in raw JSON
	output, err := json.Marshal(match)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if result["matchDetails"] == nil {
		t.Error("matchDetails field was not preserved in raw JSON")
	}
}

// TestParseSBOMData_MultiplePackageInstances tests that count matches actual instances
func TestParseSBOMData_MultiplePackageInstances(t *testing.T) {
	dbPath := "/tmp/test_sbom_parser_" + time.Now().Format("20060102150405") + ".db"
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer func() {
		_ = Close(db)
		_ = os.Remove(dbPath)
	}()

	// Create test image
	imageID := int64(1)
	_, err = db.conn.Exec(`INSERT INTO images (id, digest) VALUES (?, ?)`,
		imageID, "sha256:test123")
	if err != nil {
		t.Fatalf("Failed to insert test image: %v", err)
	}

	// SBOM with 4 instances of the same package
	sbomJSON := `{
		"artifacts": [
			{"name":"openssl","version":"1.1.1","type":"deb","location":"/usr/lib/x86_64-linux-gnu/libssl.so.1.1"},
			{"name":"openssl","version":"1.1.1","type":"deb","location":"/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1"},
			{"name":"openssl","version":"1.1.1","type":"deb","location":"/usr/bin/openssl"},
			{"name":"openssl","version":"1.1.1","type":"deb","location":"/etc/ssl/openssl.cnf"}
		]
	}`

	err = parseSBOMData(db, imageID, []byte(sbomJSON))
	if err != nil {
		t.Fatalf("parseSBOMData failed: %v", err)
	}

	// Verify count = 4
	var count int
	err = db.conn.QueryRow(`
		SELECT number_of_instances
		FROM image_packages
		WHERE image_id = ? AND name = ? AND version = ? AND type = ?`,
		imageID, "openssl", "1.1.1", "deb").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query package: %v", err)
	}

	if count != 4 {
		t.Errorf("Package count = %d, want 4", count)
	}

	// Verify all 4 instances are in details
	var detailsJSON string
	err = db.conn.QueryRow(`
		SELECT pd.details
		FROM image_package_details pd
		JOIN image_packages p ON p.id = pd.package_id
		WHERE p.image_id = ? AND p.name = ?`,
		imageID, "openssl").Scan(&detailsJSON)
	if err != nil {
		t.Fatalf("Failed to query package details: %v", err)
	}

	var details []SyftPackage
	if err := json.Unmarshal([]byte(detailsJSON), &details); err != nil {
		t.Fatalf("Failed to unmarshal details: %v", err)
	}

	if len(details) != 4 {
		t.Errorf("Details array length = %d, want 4", len(details))
	}

	// Verify each instance preserves its unique location
	locations := make(map[string]bool)
	for _, pkg := range details {
		var pkgMap map[string]interface{}
		if err := json.Unmarshal(pkg.Raw, &pkgMap); err != nil {
			t.Fatalf("Failed to unmarshal package raw JSON: %v", err)
		}
		if loc, ok := pkgMap["location"].(string); ok {
			locations[loc] = true
		}
	}

	if len(locations) != 4 {
		t.Errorf("Found %d unique locations, want 4", len(locations))
	}
}

// TestParseVulnerabilityData_MultipleMatches tests that vulnerability count matches actual matches
func TestParseVulnerabilityData_MultipleMatches(t *testing.T) {
	dbPath := "/tmp/test_vuln_parser_" + time.Now().Format("20060102150405") + ".db"
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer func() {
		_ = Close(db)
		_ = os.Remove(dbPath)
	}()

	// Create test image
	imageID := int64(1)
	_, err = db.conn.Exec(`INSERT INTO images (id, digest) VALUES (?, ?)`,
		imageID, "sha256:test123")
	if err != nil {
		t.Fatalf("Failed to insert test image: %v", err)
	}

	// Vulnerability report with 3 matches of the same CVE for the same package
	vulnJSON := `{
		"matches": [
			{
				"vulnerability": {
					"id": "CVE-2024-1234",
					"severity": "High",
					"fix": {"versions": ["1.2.0"], "state": "fixed"},
					"risk": 8.5,
					"epss": [],
					"knownExploited": []
				},
				"artifact": {
					"name": "curl",
					"version": "7.68.0",
					"type": "deb"
				},
				"matchDetails": [{"type": "exact-direct-match", "matcher": "dpkg-matcher"}]
			},
			{
				"vulnerability": {
					"id": "CVE-2024-1234",
					"severity": "High",
					"fix": {"versions": ["1.2.0"], "state": "fixed"},
					"risk": 8.5,
					"epss": [],
					"knownExploited": []
				},
				"artifact": {
					"name": "curl",
					"version": "7.68.0",
					"type": "deb"
				},
				"matchDetails": [{"type": "exact-indirect-match", "matcher": "cpe-matcher"}]
			},
			{
				"vulnerability": {
					"id": "CVE-2024-1234",
					"severity": "High",
					"fix": {"versions": ["1.2.0"], "state": "fixed"},
					"risk": 8.5,
					"epss": [],
					"knownExploited": []
				},
				"artifact": {
					"name": "curl",
					"version": "7.68.0",
					"type": "deb"
				},
				"matchDetails": [{"type": "fuzzy-match", "confidence": 0.95}]
			}
		],
		"distro": {
			"name": "debian",
			"version": "11"
		}
	}`

	err = parseVulnerabilityData(db, imageID, []byte(vulnJSON))
	if err != nil {
		t.Fatalf("parseVulnerabilityData failed: %v", err)
	}

	// Verify count = 3
	var count int
	err = db.conn.QueryRow(`
		SELECT count
		FROM image_vulnerabilities
		WHERE image_id = ? AND cve_id = ? AND package_name = ?`,
		imageID, "CVE-2024-1234", "curl").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query vulnerability: %v", err)
	}

	if count != 3 {
		t.Errorf("Vulnerability count = %d, want 3", count)
	}

	// Verify all 3 matches are in details
	var detailsJSON string
	err = db.conn.QueryRow(`
		SELECT vd.details
		FROM image_vulnerability_details vd
		JOIN image_vulnerabilities v ON v.id = vd.vulnerability_id
		WHERE v.image_id = ? AND v.cve_id = ?`,
		imageID, "CVE-2024-1234").Scan(&detailsJSON)
	if err != nil {
		t.Fatalf("Failed to query vulnerability details: %v", err)
	}

	var details []GrypeMatch
	if err := json.Unmarshal([]byte(detailsJSON), &details); err != nil {
		t.Fatalf("Failed to unmarshal details: %v", err)
	}

	if len(details) != 3 {
		t.Errorf("Details array length = %d, want 3", len(details))
	}

	// Verify each match preserves its unique matchDetails
	matchTypes := make(map[string]bool)
	for _, match := range details {
		var matchMap map[string]interface{}
		if err := json.Unmarshal(match.Raw, &matchMap); err != nil {
			t.Fatalf("Failed to unmarshal match raw JSON: %v", err)
		}
		if matchDetails, ok := matchMap["matchDetails"].([]interface{}); ok && len(matchDetails) > 0 {
			if detail, ok := matchDetails[0].(map[string]interface{}); ok {
				if matchType, ok := detail["type"].(string); ok {
					matchTypes[matchType] = true
				}
			}
		}
	}

	if len(matchTypes) != 3 {
		t.Errorf("Found %d unique match types, want 3", len(matchTypes))
	}
}

// TestParseVulnerabilityData_ExtractsDistro tests distro extraction
func TestParseVulnerabilityData_ExtractsDistro(t *testing.T) {
	dbPath := "/tmp/test_distro_" + time.Now().Format("20060102150405") + ".db"
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer func() {
		_ = Close(db)
		_ = os.Remove(dbPath)
	}()

	// Create test image
	imageID := int64(1)
	_, err = db.conn.Exec(`INSERT INTO images (id, digest) VALUES (?, ?)`,
		imageID, "sha256:test123")
	if err != nil {
		t.Fatalf("Failed to insert test image: %v", err)
	}

	vulnJSON := `{
		"matches": [],
		"distro": {
			"name": "ubuntu",
			"version": "22.04"
		}
	}`

	err = parseVulnerabilityData(db, imageID, []byte(vulnJSON))
	if err != nil {
		t.Fatalf("parseVulnerabilityData failed: %v", err)
	}

	// Verify distro info was stored
	var osName, osVersion string
	err = db.conn.QueryRow(`
		SELECT os_name, os_version
		FROM images
		WHERE id = ?`, imageID).Scan(&osName, &osVersion)
	if err != nil {
		t.Fatalf("Failed to query image: %v", err)
	}

	if osName != "ubuntu" {
		t.Errorf("os_name = %v, want ubuntu", osName)
	}
	if osVersion != "22.04" {
		t.Errorf("os_version = %v, want 22.04", osVersion)
	}
}

// TestParseVulnerabilityData_KnownExploits tests CISA KEV extraction
func TestParseVulnerabilityData_KnownExploits(t *testing.T) {
	dbPath := "/tmp/test_exploits_" + time.Now().Format("20060102150405") + ".db"
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer func() {
		_ = Close(db)
		_ = os.Remove(dbPath)
	}()

	// Create test image
	imageID := int64(1)
	_, err = db.conn.Exec(`INSERT INTO images (id, digest) VALUES (?, ?)`,
		imageID, "sha256:test123")
	if err != nil {
		t.Fatalf("Failed to insert test image: %v", err)
	}

	vulnJSON := `{
		"matches": [
			{
				"vulnerability": {
					"id": "CVE-2024-9999",
					"severity": "Critical",
					"fix": {"versions": [], "state": "not-fixed"},
					"risk": 9.8,
					"epss": [{"cve":"CVE-2024-9999","epss":0.95,"percentile":0.99,"date":"2024-01-01"}],
					"knownExploited": [
						{
							"cve": "CVE-2024-9999",
							"vendorProject": "Apache",
							"product": "HTTP Server",
							"dateAdded": "2024-01-15",
							"requiredAction": "Apply updates",
							"dueDate": "2024-02-15",
							"knownRansomwareCampaignUse": "Known",
							"urls": ["https://example.com/advisory"],
							"cwes": ["CWE-79"]
						}
					]
				},
				"artifact": {
					"name": "apache2",
					"version": "2.4.41",
					"type": "deb"
				}
			}
		]
	}`

	err = parseVulnerabilityData(db, imageID, []byte(vulnJSON))
	if err != nil {
		t.Fatalf("parseVulnerabilityData failed: %v", err)
	}

	// Verify known_exploited count
	var knownExploited, epssScore, epssPercentile float64
	err = db.conn.QueryRow(`
		SELECT known_exploited, epss_score, epss_percentile
		FROM image_vulnerabilities
		WHERE image_id = ? AND cve_id = ?`,
		imageID, "CVE-2024-9999").Scan(&knownExploited, &epssScore, &epssPercentile)
	if err != nil {
		t.Fatalf("Failed to query vulnerability: %v", err)
	}

	if knownExploited != 1 {
		t.Errorf("known_exploited = %v, want 1", knownExploited)
	}
	if epssScore != 0.95 {
		t.Errorf("epss_score = %v, want 0.95", epssScore)
	}
	if epssPercentile != 0.99 {
		t.Errorf("epss_percentile = %v, want 0.99", epssPercentile)
	}
}
