package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := defaultConfig()

	if cfg.Port != "9999" {
		t.Errorf("Expected default port 9999, got %s", cfg.Port)
	}

	if cfg.DBPath != "/var/lib/bjorn2scan/containers.db" {
		t.Errorf("Expected default db path, got %s", cfg.DBPath)
	}

	if cfg.DebugEnabled {
		t.Error("Expected debug disabled by default")
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.conf")

	configContent := `port=8080
db_path=/tmp/test.db
debug_enabled=true
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Load config
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify values from file
	if cfg.Port != "8080" {
		t.Errorf("Expected port 8080, got %s", cfg.Port)
	}

	if cfg.DBPath != "/tmp/test.db" {
		t.Errorf("Expected db path /tmp/test.db, got %s", cfg.DBPath)
	}

	if !cfg.DebugEnabled {
		t.Error("Expected debug enabled")
	}
}

func TestLoadConfigWithEnvironmentOverrides(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test.conf")

	configContent := `port=8080
db_path=/tmp/test.db
debug_enabled=false
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	// Set environment variables to override
	if err := os.Setenv("PORT", "7777"); err != nil {
		t.Fatalf("Failed to set PORT env var: %v", err)
	}
	if err := os.Setenv("DEBUG_ENABLED", "true"); err != nil {
		t.Fatalf("Failed to set DEBUG_ENABLED env var: %v", err)
	}
	defer func() {
		_ = os.Unsetenv("PORT")
		_ = os.Unsetenv("DEBUG_ENABLED")
	}()

	// Load config
	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify env vars override file values
	if cfg.Port != "7777" {
		t.Errorf("Expected port 7777 from env, got %s", cfg.Port)
	}

	if cfg.DBPath != "/tmp/test.db" {
		t.Errorf("Expected db path from file, got %s", cfg.DBPath)
	}

	if !cfg.DebugEnabled {
		t.Error("Expected debug enabled from env")
	}
}

func TestLoadConfigNoFile(t *testing.T) {
	// Load config with non-existent file (should use defaults)
	cfg, err := LoadConfig("/nonexistent/path.conf")
	if err != nil {
		t.Fatalf("Should not error when file doesn't exist: %v", err)
	}

	// Verify defaults are used
	if cfg.Port != "9999" {
		t.Errorf("Expected default port, got %s", cfg.Port)
	}

	if cfg.DebugEnabled {
		t.Error("Expected debug disabled by default")
	}
}

func TestLoadConfigEmptyPath(t *testing.T) {
	// Load with empty path (should use defaults)
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("Failed to load config with empty path: %v", err)
	}

	// Verify defaults
	if cfg.Port != "9999" {
		t.Errorf("Expected default port, got %s", cfg.Port)
	}
}

func TestDebugEnabledVariations(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{"true lowercase", "true", true},
		{"TRUE uppercase", "TRUE", true},
		{"1", "1", true},
		{"yes", "yes", true},
		{"false", "false", false},
		{"0", "0", false},
		{"no", "no", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			configPath := filepath.Join(tmpDir, "test.conf")

			configContent := "debug_enabled=" + tt.value + "\n"
			err := os.WriteFile(configPath, []byte(configContent), 0644)
			if err != nil {
				t.Fatalf("Failed to create test config file: %v", err)
			}

			cfg, err := LoadConfig(configPath)
			if err != nil {
				t.Fatalf("Failed to load config: %v", err)
			}

			if cfg.DebugEnabled != tt.expected {
				t.Errorf("Expected debug_enabled=%v for value %q, got %v",
					tt.expected, tt.value, cfg.DebugEnabled)
			}
		})
	}
}

func TestLoadConfigWithDefaults(t *testing.T) {
	// Save original env vars
	origPort := os.Getenv("PORT")
	origDB := os.Getenv("DB_PATH")
	origDebug := os.Getenv("DEBUG_ENABLED")

	// Set env vars for testing
	if err := os.Setenv("PORT", "5555"); err != nil {
		t.Fatalf("Failed to set PORT: %v", err)
	}
	if err := os.Setenv("DB_PATH", "/custom/path.db"); err != nil {
		t.Fatalf("Failed to set DB_PATH: %v", err)
	}
	if err := os.Setenv("DEBUG_ENABLED", "true"); err != nil {
		t.Fatalf("Failed to set DEBUG_ENABLED: %v", err)
	}

	defer func() {
		// Restore original env vars
		_ = os.Setenv("PORT", origPort)
		_ = os.Setenv("DB_PATH", origDB)
		_ = os.Setenv("DEBUG_ENABLED", origDebug)
	}()

	// Load config (will not find default files, uses env vars)
	cfg, err := LoadConfigWithDefaults()
	if err != nil {
		t.Fatalf("Failed to load config with defaults: %v", err)
	}

	// Verify env vars are applied
	if cfg.Port != "5555" {
		t.Errorf("Expected port from env, got %s", cfg.Port)
	}

	if cfg.DBPath != "/custom/path.db" {
		t.Errorf("Expected db path from env, got %s", cfg.DBPath)
	}

	if !cfg.DebugEnabled {
		t.Error("Expected debug enabled from env")
	}
}
