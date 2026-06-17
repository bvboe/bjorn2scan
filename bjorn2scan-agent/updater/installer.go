package updater

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

)


const (
	defaultBinaryPath = "/var/lib/bjorn2scan/bin/bjorn2scan-agent"
	backupSuffix      = ".backup"
	rollbackMarker    = "/tmp/bjorn2scan-update-rollback"
)


// Installer handles atomic binary replacement and service restart
type Installer struct {
	binaryPath    string
	healthURL     string
	healthTimeout time.Duration
}

// NewInstaller creates a new installer
func NewInstaller(binaryPath, healthURL string, healthTimeout time.Duration) *Installer {
	if binaryPath == "" {
		binaryPath = defaultBinaryPath
	}
	if healthURL == "" {
		healthURL = "http://localhost:9999/health"
	}
	if healthTimeout == 0 {
		healthTimeout = 60 * time.Second
	}

	return &Installer{
		binaryPath:    binaryPath,
		healthURL:     healthURL,
		healthTimeout: healthTimeout,
	}
}

// Install performs atomic binary replacement and exits for restart
// The health check and rollback decision happen on the next startup
// The cleanup function is called after the binary is copied but before exit
func (i *Installer) Install(newBinaryPath string, cleanup func() error) error {
	log := log

	log.Info("starting installation")

	// 1. Backup current binary
	backupPath := i.binaryPath + backupSuffix
	log.Info("backing up current binary", "backup_path", backupPath)
	if err := i.copyFile(i.binaryPath, backupPath); err != nil {
		return fmt.Errorf("failed to backup binary: %w", err)
	}

	// 2. Create rollback marker (will be checked on next startup)
	if err := os.WriteFile(rollbackMarker, []byte("pending"), 0644); err != nil {
		return fmt.Errorf("failed to create rollback marker: %w", err)
	}

	// 3. Atomic replace (rename is atomic on most filesystems)
	log.Info("installing new binary", "path", i.binaryPath)
	// First copy to a temp location in the same directory (ensures same filesystem)
	tempPath := i.binaryPath + ".new"
	if err := i.copyFile(newBinaryPath, tempPath); err != nil {
		return fmt.Errorf("failed to stage new binary: %w", err)
	}

	// Set executable permissions
	if err := os.Chmod(tempPath, 0755); err != nil {
		_ = os.Remove(tempPath) // Best effort cleanup
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tempPath, i.binaryPath); err != nil {
		_ = os.Remove(tempPath) // Best effort cleanup
		return fmt.Errorf("failed to install new binary: %w", err)
	}

	log.Info("binary installed successfully")

	// 4. Cleanup temp directory (binary has been copied, no longer needed)
	if cleanup != nil {
		if err := cleanup(); err != nil {
			log.Warn("failed to cleanup temp directory", "error", err)
			// Continue anyway - cleanup failure shouldn't block the update
		}
	}

	log.Info("update installed, exiting for restart")
	log.Info("new version will be verified on startup")

	// Exit gracefully - systemd will restart the service with Restart=always
	// The new binary will run, perform health check, and either commit or rollback
	os.Exit(0)

	return nil // Never reached, but required for compilation
}

// Rollback restores the previous binary and exits for restart
func (i *Installer) Rollback() error {
	log := log

	log.Info("performing rollback")

	backupPath := i.binaryPath + backupSuffix
	if _, err := os.Stat(backupPath); os.IsNotExist(err) {
		return fmt.Errorf("backup file not found: %s", backupPath)
	}

	// Restore backup
	if err := os.Rename(backupPath, i.binaryPath); err != nil {
		return fmt.Errorf("failed to restore backup: %w", err)
	}

	// Remove rollback marker
	_ = os.Remove(rollbackMarker) // Best effort cleanup

	log.Info("rollback completed, exiting for restart")

	// Exit - systemd will restart with the old version
	os.Exit(1)

	return nil // Never reached
}

// PerformPostUpdateHealthCheck checks if update was successful and commits or rolls back
// This should be called on startup if ShouldCheckRollback() returns true
func (i *Installer) PerformPostUpdateHealthCheck() error {
	log := log

	log.Info("pending update detected, performing health check")

	// Give the service a moment to fully start
	time.Sleep(2 * time.Second)

	// Perform health check
	if err := i.checkHealth(); err != nil {
		log.Error("health check failed", "error", err)
		log.Info("rolling back to previous version")
		return i.Rollback()
	}

	// Health check passed - commit the update
	log.Info("health check passed")
	return i.CommitUpdate()
}

// CommitUpdate removes the rollback marker and backup after successful update
func (i *Installer) CommitUpdate() error {
	log := log

	backupPath := i.binaryPath + backupSuffix

	// Remove rollback marker
	if err := os.Remove(rollbackMarker); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove rollback marker: %w", err)
	}

	// Remove backup
	if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove backup: %w", err)
	}

	log.Info("update committed successfully")
	return nil
}

// checkHealth performs a health check on the service
func (i *Installer) checkHealth() error {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	deadline := time.Now().Add(i.healthTimeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(i.healthURL)
		if err == nil && resp.StatusCode == http.StatusOK {
			_ = resp.Body.Close()
			return nil
		}
		if resp != nil {
			_ = resp.Body.Close()
		}

		// Wait before retry
		time.Sleep(2 * time.Second)
	}

	return fmt.Errorf("health check timeout after %v", i.healthTimeout)
}

// copyFile copies a file from src to dst
func (i *Installer) copyFile(src, dst string) error {
	sourceData, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("failed to read source: %w", err)
	}

	if err := os.WriteFile(dst, sourceData, 0755); err != nil {
		return fmt.Errorf("failed to write destination: %w", err)
	}

	return nil
}

// ShouldCheckRollback checks if there's a pending rollback check
func (i *Installer) ShouldCheckRollback() bool {
	_, err := os.Stat(rollbackMarker)
	return err == nil
}

// CleanupRollbackMarker removes the rollback marker
func (i *Installer) CleanupRollbackMarker() error {
	return os.Remove(rollbackMarker)
}

// GetBackupPath returns the path to the backup binary
func (i *Installer) GetBackupPath() string {
	return filepath.Join(filepath.Dir(i.binaryPath), filepath.Base(i.binaryPath)+backupSuffix)
}
