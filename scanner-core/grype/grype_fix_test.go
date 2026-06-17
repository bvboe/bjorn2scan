package grype

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestScanWithDistro(t *testing.T) {
	// Read the nginx SBOM
	sbomPath := "../../dev-local/problem-scan/sbom_sha256__23b4dcdf0d34.json"
	sbomJSON, err := os.ReadFile(sbomPath)
	if err != nil {
		t.Skipf("Skipping test: could not read SBOM file: %v", err)
		return
	}

	// Scan for vulnerabilities
	ctx := context.Background()
	scanResult, err := ScanVulnerabilities(ctx, sbomJSON)
	if err != nil {
		t.Fatalf("Failed to scan vulnerabilities: %v", err)
	}

	// Parse the result
	var result map[string]interface{}
	if err := json.Unmarshal(scanResult.VulnerabilityJSON, &result); err != nil {
		t.Fatalf("Failed to parse vulnerability JSON: %v", err)
	}

	// Check that we have matches
	matches, ok := result["matches"].([]interface{})
	if !ok {
		t.Fatal("No matches field in result")
	}

	matchCount := len(matches)
	t.Logf("Found %d vulnerability matches", matchCount)

	// Check distro in result
	if distro, ok := result["distro"].(map[string]interface{}); ok {
		t.Logf("Distro: name=%v, version=%v", distro["name"], distro["version"])

		// Verify distro is populated
		if name, ok := distro["name"].(string); !ok || name == "" {
			t.Error("Distro name is empty")
		}
	} else {
		t.Error("No distro field in result")
	}

	// We expect significantly more than 7 vulnerabilities for nginx:1.15
	if matchCount < 100 {
		t.Errorf("Expected at least 100 vulnerabilities, got %d", matchCount)
	}

	// Verify descriptor.db is present (database metadata)
	if descriptor, ok := result["descriptor"].(map[string]interface{}); ok {
		t.Logf("Descriptor: name=%v, version=%v", descriptor["name"], descriptor["version"])
		if db, ok := descriptor["db"].(map[string]interface{}); ok {
			if status, ok := db["status"].(map[string]interface{}); ok {
				t.Logf("DB Status: schemaVersion=%v, built=%v", status["schemaVersion"], status["built"])
			}
			if providers, ok := db["providers"].(map[string]interface{}); ok {
				t.Logf("DB Providers count: %d", len(providers))
			} else {
				t.Error("descriptor.db.providers is missing")
			}
		} else {
			t.Error("descriptor.db is missing")
		}
	} else {
		t.Error("descriptor is missing")
	}
}

func TestIsNumericDir(t *testing.T) {
	tests := []struct {
		name     string
		expected bool
	}{
		{"6", true},
		{"5", true},
		{"10", true},
		{"123", true},
		{"0", true},
		{"v6", false},
		{"", false},
		{"abc", false},
		{"6a", false},
		{"a6", false},
		{"grype", false},
		{"vulnerability.db", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNumericDir(tt.name)
			if got != tt.expected {
				t.Errorf("isNumericDir(%q) = %v, want %v", tt.name, got, tt.expected)
			}
		})
	}
}

func TestCheckDatabaseV6Structure(t *testing.T) {
	// Create a temporary directory structure mimicking grype v6
	tmpDir := t.TempDir()
	grypeDir := filepath.Join(tmpDir, "grype")
	schemaDir := filepath.Join(grypeDir, "6")
	dbFile := filepath.Join(schemaDir, "vulnerability.db")

	// Create directory structure
	if err := os.MkdirAll(schemaDir, 0755); err != nil {
		t.Fatalf("Failed to create schema directory: %v", err)
	}

	// Create empty database file
	if err := os.WriteFile(dbFile, []byte("dummy db"), 0644); err != nil {
		t.Fatalf("Failed to create db file: %v", err)
	}

	// Test CheckDatabase with v6 structure
	cfg := Config{DBRootDir: tmpDir}
	status, err := CheckDatabase(cfg)
	if err != nil {
		t.Fatalf("CheckDatabase returned error: %v", err)
	}

	if !status.Available {
		t.Errorf("CheckDatabase returned Available=false, error=%q", status.Error)
	}

	if status.Path != dbFile {
		t.Errorf("CheckDatabase returned Path=%q, want %q", status.Path, dbFile)
	}
}

func TestCheckDatabaseNoDatabase(t *testing.T) {
	// Create a temporary directory with no database
	tmpDir := t.TempDir()
	grypeDir := filepath.Join(tmpDir, "grype")

	// Create empty grype directory
	if err := os.MkdirAll(grypeDir, 0755); err != nil {
		t.Fatalf("Failed to create grype directory: %v", err)
	}

	// Test CheckDatabase with empty directory
	cfg := Config{DBRootDir: tmpDir}
	status, err := CheckDatabase(cfg)
	if err != nil {
		t.Fatalf("CheckDatabase returned error: %v", err)
	}

	if status.Available {
		t.Error("CheckDatabase returned Available=true for empty directory")
	}

	if status.Error == "" {
		t.Error("CheckDatabase returned empty error for unavailable database")
	}
}
