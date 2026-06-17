package deployment

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewUUID_CreatesNewUUID(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()

	// Create UUID
	u, err := NewUUID(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create UUID: %v", err)
	}

	// Verify UUID is not empty
	if u.String() == "" {
		t.Error("UUID should not be empty")
	}

	// Verify UUID is valid format
	if !IsValidUUID(u.String()) {
		t.Errorf("UUID is not valid: %s", u.String())
	}

	// Verify file was created
	expectedPath := filepath.Join(tmpDir, uuidFileName)
	if u.FilePath() != expectedPath {
		t.Errorf("FilePath = %s, want %s", u.FilePath(), expectedPath)
	}

	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Error("UUID file was not created")
	}
}

func TestNewUUID_LoadsExistingUUID(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()

	// Create first UUID
	u1, err := NewUUID(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create first UUID: %v", err)
	}

	// Load UUID again (should read from file)
	u2, err := NewUUID(tmpDir)
	if err != nil {
		t.Fatalf("Failed to load UUID: %v", err)
	}

	// Verify UUIDs match
	if u1.String() != u2.String() {
		t.Errorf("UUIDs don't match: %s != %s", u1.String(), u2.String())
	}
}

func TestNewUUID_PersistsAcrossRestarts(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()

	// Create UUID
	u1, err := NewUUID(tmpDir)
	if err != nil {
		t.Fatalf("Failed to create UUID: %v", err)
	}

	originalUUID := u1.String()

	// Simulate restart by creating new UUID instance
	for i := 0; i < 5; i++ {
		u, err := NewUUID(tmpDir)
		if err != nil {
			t.Fatalf("Failed to load UUID on iteration %d: %v", i, err)
		}

		if u.String() != originalUUID {
			t.Errorf("UUID changed on iteration %d: %s != %s", i, u.String(), originalUUID)
		}
	}
}

func TestNewUUID_CreatesDirectoryIfNeeded(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data", "nested")

	// Directory doesn't exist yet
	if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
		t.Fatal("Test setup error: directory should not exist")
	}

	// Create UUID (should create directory)
	u, err := NewUUID(dataDir)
	if err != nil {
		t.Fatalf("Failed to create UUID: %v", err)
	}

	// Verify directory was created
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		t.Error("Directory was not created")
	}

	// Verify UUID file exists
	if _, err := os.Stat(u.FilePath()); os.IsNotExist(err) {
		t.Error("UUID file was not created")
	}
}

func TestNewUUID_RejectsInvalidUUID(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	uuidFile := filepath.Join(tmpDir, uuidFileName)

	// Write invalid UUID
	if err := os.WriteFile(uuidFile, []byte("not-a-valid-uuid"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Try to load UUID (should fail)
	_, err := NewUUID(tmpDir)
	if err == nil {
		t.Error("Expected error for invalid UUID, got nil")
	}
}

func TestNewUUID_HandlesWhitespace(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	uuidFile := filepath.Join(tmpDir, uuidFileName)

	// Write UUID with whitespace
	validUUID := "550e8400-e29b-41d4-a716-446655440000"
	if err := os.WriteFile(uuidFile, []byte("  "+validUUID+"  \n"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Load UUID (should trim whitespace)
	u, err := NewUUID(tmpDir)
	if err != nil {
		t.Fatalf("Failed to load UUID: %v", err)
	}

	if u.String() != validUUID {
		t.Errorf("UUID = %s, want %s", u.String(), validUUID)
	}
}

func TestIsValidUUID(t *testing.T) {
	tests := []struct {
		uuid  string
		valid bool
	}{
		{"550e8400-e29b-41d4-a716-446655440000", true},
		{"550E8400-E29B-41D4-A716-446655440000", true}, // uppercase
		{"not-a-uuid", false},
		{"", false},
		{"550e8400-e29b-41d4-a716", false},              // too short
		{"550e8400-e29b-41d4-a716-446655440000-extra", false}, // too long
	}

	for _, tt := range tests {
		result := IsValidUUID(tt.uuid)
		if result != tt.valid {
			t.Errorf("IsValidUUID(%q) = %v, want %v", tt.uuid, result, tt.valid)
		}
	}
}

func TestGenerateUUID_IsUnique(t *testing.T) {
	// Generate multiple UUIDs and verify they're unique
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		uuid, err := generateUUID()
		if err != nil {
			t.Fatalf("Failed to generate UUID: %v", err)
		}

		if seen[uuid] {
			t.Errorf("Generated duplicate UUID: %s", uuid)
		}
		seen[uuid] = true
	}
}

func TestGenerateUUID_IsValid(t *testing.T) {
	uuid, err := generateUUID()
	if err != nil {
		t.Fatalf("Failed to generate UUID: %v", err)
	}

	if !IsValidUUID(uuid) {
		t.Errorf("Generated invalid UUID: %s", uuid)
	}
}
