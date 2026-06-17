package updater

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewInstaller(t *testing.T) {
	tests := []struct {
		name          string
		binaryPath    string
		healthURL     string
		healthTimeout time.Duration
		wantBinary    string
		wantHealth    string
		wantTimeout   time.Duration
	}{
		{
			name:          "All defaults",
			binaryPath:    "",
			healthURL:     "",
			healthTimeout: 0,
			wantBinary:    defaultBinaryPath,
			wantHealth:    "http://localhost:9999/health",
			wantTimeout:   60 * time.Second,
		},
		{
			name:          "Custom values",
			binaryPath:    "/custom/path/binary",
			healthURL:     "http://custom:8080/health",
			healthTimeout: 30 * time.Second,
			wantBinary:    "/custom/path/binary",
			wantHealth:    "http://custom:8080/health",
			wantTimeout:   30 * time.Second,
		},
		{
			name:          "Partial defaults",
			binaryPath:    "/custom/binary",
			healthURL:     "",
			healthTimeout: 0,
			wantBinary:    "/custom/binary",
			wantHealth:    "http://localhost:9999/health",
			wantTimeout:   60 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			installer := NewInstaller(tt.binaryPath, tt.healthURL, tt.healthTimeout)

			if installer.binaryPath != tt.wantBinary {
				t.Errorf("binaryPath = %q, want %q", installer.binaryPath, tt.wantBinary)
			}
			if installer.healthURL != tt.wantHealth {
				t.Errorf("healthURL = %q, want %q", installer.healthURL, tt.wantHealth)
			}
			if installer.healthTimeout != tt.wantTimeout {
				t.Errorf("healthTimeout = %v, want %v", installer.healthTimeout, tt.wantTimeout)
			}
		})
	}
}

func TestInstaller_GetBackupPath(t *testing.T) {
	tests := []struct {
		name       string
		binaryPath string
		want       string
	}{
		{
			name:       "Standard path",
			binaryPath: "/var/lib/bjorn2scan/bin/bjorn2scan-agent",
			want:       "/var/lib/bjorn2scan/bin/bjorn2scan-agent.backup",
		},
		{
			name:       "Custom path",
			binaryPath: "/opt/bjorn2scan/agent",
			want:       "/opt/bjorn2scan/agent.backup",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			installer := NewInstaller(tt.binaryPath, "", 0)
			got := installer.GetBackupPath()

			if got != tt.want {
				t.Errorf("GetBackupPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInstaller_ShouldCheckRollback(t *testing.T) {
	installer := NewInstaller("", "", 0)

	// Initially should not need rollback check
	if installer.ShouldCheckRollback() {
		t.Error("ShouldCheckRollback() = true, want false (no marker)")
	}

	// Create marker
	if err := os.WriteFile(rollbackMarker, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create rollback marker: %v", err)
	}
	defer func() { _ = os.Remove(rollbackMarker) }()

	// Should now need rollback check
	if !installer.ShouldCheckRollback() {
		t.Error("ShouldCheckRollback() = false, want true (marker exists)")
	}
}

func TestInstaller_CleanupRollbackMarker(t *testing.T) {
	installer := NewInstaller("", "", 0)

	// Create marker
	if err := os.WriteFile(rollbackMarker, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create rollback marker: %v", err)
	}

	// Cleanup
	if err := installer.CleanupRollbackMarker(); err != nil {
		t.Errorf("CleanupRollbackMarker() error = %v", err)
	}

	// Verify removed
	if _, err := os.Stat(rollbackMarker); !os.IsNotExist(err) {
		t.Error("Rollback marker still exists after cleanup")
	}
}

func TestInstaller_CleanupRollbackMarker_NonExistent(t *testing.T) {
	installer := NewInstaller("", "", 0)

	// Cleanup nonexistent marker should error
	err := installer.CleanupRollbackMarker()
	if err == nil {
		t.Error("CleanupRollbackMarker() expected error for nonexistent marker, got nil")
	}
}

func TestInstaller_CopyFile(t *testing.T) {
	installer := NewInstaller("", "", 0)

	// Create source file
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "source")
	srcContent := []byte("test content")
	if err := os.WriteFile(srcPath, srcContent, 0644); err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	// Copy file
	dstPath := filepath.Join(tmpDir, "destination")
	if err := installer.copyFile(srcPath, dstPath); err != nil {
		t.Fatalf("copyFile() error = %v", err)
	}

	// Verify destination file
	dstContent, err := os.ReadFile(dstPath)
	if err != nil {
		t.Fatalf("Failed to read destination file: %v", err)
	}

	if string(dstContent) != string(srcContent) {
		t.Errorf("Destination content = %q, want %q", string(dstContent), string(srcContent))
	}

	// Verify permissions
	info, err := os.Stat(dstPath)
	if err != nil {
		t.Fatalf("Failed to stat destination: %v", err)
	}

	mode := info.Mode()
	if mode&0111 == 0 {
		t.Error("Destination file is not executable")
	}
}

func TestInstaller_CopyFile_NonExistentSource(t *testing.T) {
	installer := NewInstaller("", "", 0)

	tmpDir := t.TempDir()
	err := installer.copyFile("/nonexistent/source", filepath.Join(tmpDir, "dest"))
	if err == nil {
		t.Fatal("copyFile() expected error for nonexistent source, got nil")
	}

	if !strings.Contains(err.Error(), "failed to read source") {
		t.Errorf("copyFile() error = %v, want error containing 'failed to read source'", err)
	}
}

func TestInstaller_CheckHealth_Success(t *testing.T) {
	// Create test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer server.Close()

	installer := NewInstaller("", server.URL, 5*time.Second)

	if err := installer.checkHealth(); err != nil {
		t.Errorf("checkHealth() error = %v", err)
	}
}

func TestInstaller_CheckHealth_Failure(t *testing.T) {
	// Create test HTTP server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	installer := NewInstaller("", server.URL, 2*time.Second)

	err := installer.checkHealth()
	if err == nil {
		t.Fatal("checkHealth() expected error for unhealthy service, got nil")
	}

	if !strings.Contains(err.Error(), "health check timeout") {
		t.Errorf("checkHealth() error = %v, want error containing 'health check timeout'", err)
	}
}

func TestInstaller_CheckHealth_Timeout(t *testing.T) {
	// Create test HTTP server that never responds
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second) // Longer than test timeout
	}))
	defer server.Close()

	installer := NewInstaller("", server.URL, 1*time.Second)

	start := time.Now()
	err := installer.checkHealth()
	duration := time.Since(start)

	if err == nil {
		t.Fatal("checkHealth() expected error for timeout, got nil")
	}

	// Should timeout roughly within the specified duration (with margin for retries)
	// The implementation does retries with delays, so allow more time
	if duration > 10*time.Second {
		t.Errorf("checkHealth() took %v, expected less than 10 seconds", duration)
	}
}

func TestInstaller_CheckHealth_EventuallySucceeds(t *testing.T) {
	// Create test HTTP server that succeeds after a few attempts
	attemptCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		if attemptCount < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	installer := NewInstaller("", server.URL, 10*time.Second)

	if err := installer.checkHealth(); err != nil {
		t.Errorf("checkHealth() error = %v, expected success after retries", err)
	}

	if attemptCount < 2 {
		t.Errorf("Expected at least 2 attempts, got %d", attemptCount)
	}
}

func TestInstaller_CheckHealth_Unreachable(t *testing.T) {
	// Use unreachable URL
	installer := NewInstaller("", "http://127.0.0.1:1", 2*time.Second)

	err := installer.checkHealth()
	if err == nil {
		t.Fatal("checkHealth() expected error for unreachable service, got nil")
	}
}

/*
Integration Tests Needed (require systemctl and actual service):

1. TestInstaller_Install_Success
   - Create test binary
   - Install it
   - Verify service restarts
   - Verify health check passes
   - Verify backup is created
   - Verify rollback marker is cleaned up

2. TestInstaller_Install_HealthCheckFails
   - Create test binary that fails health check
   - Attempt install
   - Verify rollback occurs
   - Verify original binary is restored

3. TestInstaller_Install_RestartFails
   - Create test binary
   - Mock systemctl to fail
   - Attempt install
   - Verify rollback occurs

4. TestInstaller_Rollback_Success
   - Create backup binary
   - Perform rollback
   - Verify backup is restored
   - Verify service restarts

5. TestInstaller_Rollback_NoBackup
   - Attempt rollback without backup
   - Verify appropriate error

6. TestInstaller_Install_AtomicReplace
   - Create test binary
   - Install while another process is reading the binary
   - Verify atomic replacement (no corruption)

7. TestInstaller_Install_PermissionDenied
   - Attempt install without permissions
   - Verify appropriate error

8. TestInstaller_Install_DiskFull
   - Mock disk full condition
   - Attempt install
   - Verify cleanup and rollback

These integration tests should be in a separate file with build tags like:
  //go:build integration

They would need:
- Root/sudo access for systemctl
- Running bjorn2scan-agent service
- Ability to replace system binaries
- Mock/test environment separate from production
*/
