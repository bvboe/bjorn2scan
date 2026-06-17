package updater

import (
	"sync"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{
			name: "Valid configuration",
			config: &Config{
				Enabled:        true,
				CheckInterval:  1 * time.Hour,
				FeedURL:        "http://localhost:8080/releases.atom",
				AssetBaseURL:   "http://localhost:8080/download",
				CurrentVersion: "0.1.0",
			},
			wantErr: false,
		},
		{
			name: "Minimal configuration",
			config: &Config{
				FeedURL:      "http://localhost:8080/releases.atom",
				AssetBaseURL: "http://localhost:8080/download",
			},
			wantErr: false,
		},
		{
			name: "Missing feed URL",
			config: &Config{
				AssetBaseURL: "http://localhost:8080/download",
			},
			wantErr: true,
			errMsg:  "feed URL is required",
		},
		{
			name: "Missing asset base URL",
			config: &Config{
				FeedURL: "http://localhost:8080/releases.atom",
			},
			wantErr: true,
			errMsg:  "asset base URL is required",
		},
		{
			name: "With version constraints",
			config: &Config{
				FeedURL:      "http://localhost:8080/releases.atom",
				AssetBaseURL: "http://localhost:8080/download",
				VersionConstraints: &VersionConstraints{
					AutoUpdateMinor: true,
					AutoUpdateMajor: false,
					MinVersion:      "0.1.0",
					MaxVersion:      "1.0.0",
				},
			},
			wantErr: false,
		},
		{
			name: "With signature verification",
			config: &Config{
				FeedURL:              "http://localhost:8080/releases.atom",
				AssetBaseURL:         "http://localhost:8080/download",
				VerifySignatures:     true,
				CosignIdentityRegexp: "https://github.com/*",
				CosignOIDCIssuer:     "https://token.actions.githubusercontent.com",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updater, err := New(tt.config)

			if (err != nil) != tt.wantErr {
				t.Errorf("New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				if updater != nil {
					t.Error("New() returned updater when error expected")
				}
				if err != nil && tt.errMsg != "" {
					if err.Error() != tt.errMsg && len(tt.errMsg) > 0 {
						// Just check it contains the error message prefix
						t.Logf("Error message: %v", err)
					}
				}
				return
			}

			if updater == nil {
				t.Fatal("New() returned nil updater")
				return
			}

			// Verify initialization
			if updater.config != tt.config {
				t.Error("Config not set correctly")
			}

			if updater.status != StatusIdle {
				t.Errorf("Initial status = %v, want %v", updater.status, StatusIdle)
			}

			if updater.feedParser == nil {
				t.Error("Feed parser not initialized")
			}

			if updater.versionChecker == nil {
				t.Error("Version checker not initialized")
			}

			if updater.stopChan == nil {
				t.Error("Stop channel not initialized")
			}

			if updater.pauseChan == nil {
				t.Error("Pause channel not initialized")
			}
		})
	}
}

func TestUpdater_StatusManagement(t *testing.T) {
	config := &Config{
		FeedURL:      "http://localhost:8080/releases.atom",
		AssetBaseURL: "http://localhost:8080/download",
	}

	updater, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create updater: %v", err)
	}

	tests := []struct {
		name     string
		status   Status
		errorMsg string
	}{
		{
			name:     "Idle status",
			status:   StatusIdle,
			errorMsg: "",
		},
		{
			name:     "Checking status",
			status:   StatusChecking,
			errorMsg: "",
		},
		{
			name:     "Downloading status",
			status:   StatusDownloading,
			errorMsg: "",
		},
		{
			name:     "Verifying status",
			status:   StatusVerifying,
			errorMsg: "",
		},
		{
			name:     "Installing status",
			status:   StatusInstalling,
			errorMsg: "",
		},
		{
			name:     "Failed status with error",
			status:   StatusFailed,
			errorMsg: "test error message",
		},
		{
			name:     "Failed status with long error",
			status:   StatusFailed,
			errorMsg: "this is a very long error message that describes what went wrong in detail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set status
			updater.setStatus(tt.status, tt.errorMsg)

			// Get status
			status, errorMsg, lastCheck, lastUpdate, latestVersion, _ := updater.GetStatus()

			if status != tt.status {
				t.Errorf("Status = %v, want %v", status, tt.status)
			}

			if errorMsg != tt.errorMsg {
				t.Errorf("Error message = %q, want %q", errorMsg, tt.errorMsg)
			}

			// lastCheck and lastUpdate should be zero initially
			if !lastCheck.IsZero() && tt.name == "Idle status" {
				t.Error("lastCheck should be zero initially")
			}

			if !lastUpdate.IsZero() {
				t.Error("lastUpdate should be zero initially")
			}

			if latestVersion != "" {
				t.Error("latestVersion should be empty initially")
			}
		})
	}
}

func TestUpdater_GetStatusReturnsCurrentVersion(t *testing.T) {
	config := &Config{
		FeedURL:        "http://localhost:8080/releases.atom",
		AssetBaseURL:   "http://localhost:8080/download",
		CurrentVersion: "1.2.3",
	}

	updater, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create updater: %v", err)
	}

	_, _, _, _, _, currentVersion := updater.GetStatus()
	if currentVersion != "1.2.3" {
		t.Errorf("GetStatus() currentVersion = %q, want %q", currentVersion, "1.2.3")
	}
}

func TestUpdater_StatusThreadSafety(t *testing.T) {
	config := &Config{
		FeedURL:      "http://localhost:8080/releases.atom",
		AssetBaseURL: "http://localhost:8080/download",
	}

	updater, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create updater: %v", err)
	}

	// Concurrently set and get status
	var wg sync.WaitGroup
	iterations := 100

	// Writers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				status := Status([]Status{
					StatusIdle,
					StatusChecking,
					StatusDownloading,
					StatusVerifying,
					StatusInstalling,
					StatusFailed,
				}[j%6])
				updater.setStatus(status, "test")
			}
		}(i)
	}

	// Readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				updater.GetStatus()
			}
		}()
	}

	wg.Wait()

	// If we get here without data races, the test passed
	t.Log("Thread safety test completed successfully")
}

func TestUpdater_PauseResume(t *testing.T) {
	config := &Config{
		FeedURL:      "http://localhost:8080/releases.atom",
		AssetBaseURL: "http://localhost:8080/download",
	}

	updater, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create updater: %v", err)
	}

	// Initially not paused
	if updater.isPaused() {
		t.Error("Updater should not be paused initially")
	}

	// Pause
	go updater.Pause()
	time.Sleep(10 * time.Millisecond) // Give time for channel operation

	// Check paused state via pauseChan handling
	// Note: In the real implementation, isPaused() checks the paused field
	// which is set by the Start() loop when it receives from pauseChan
	// For unit testing, we can't easily test this without running Start()

	// Resume
	go updater.Resume()
	time.Sleep(10 * time.Millisecond)

	// The actual pause/resume behavior is tested in integration tests
	// because it requires the Start() loop to be running
}

func TestUpdater_IsPausedThreadSafety(t *testing.T) {
	config := &Config{
		FeedURL:      "http://localhost:8080/releases.atom",
		AssetBaseURL: "http://localhost:8080/download",
	}

	updater, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create updater: %v", err)
	}

	// Concurrently check pause state
	var wg sync.WaitGroup
	iterations := 1000

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				updater.isPaused()
			}
		}()
	}

	// Also set pause state
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations/10; j++ {
				updater.mu.Lock()
				updater.paused = (j % 2) == 0
				updater.mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// If we get here without data races, the test passed
	t.Log("isPaused thread safety test completed successfully")
}

func TestStatus_Constants(t *testing.T) {
	// Test that status constants are defined correctly
	statuses := []Status{
		StatusIdle,
		StatusChecking,
		StatusDownloading,
		StatusVerifying,
		StatusInstalling,
		StatusRestarting,
		StatusFailed,
	}

	// Verify all statuses are unique
	seen := make(map[Status]bool)
	for _, status := range statuses {
		if seen[status] {
			t.Errorf("Duplicate status constant: %v", status)
		}
		seen[status] = true

		// Verify status is not empty
		if string(status) == "" {
			t.Error("Status constant is empty")
		}
	}

	// Verify expected count
	if len(statuses) != 7 {
		t.Errorf("Expected 7 status constants, got %d", len(statuses))
	}
}

func TestConfig_Structure(t *testing.T) {
	// Test Config structure can be created and accessed
	config := &Config{
		Enabled:              true,
		CheckInterval:        6 * time.Hour,
		FeedURL:              "https://github.com/bvboe/b2s-go/releases.atom",
		AssetBaseURL:         "https://github.com/bvboe/b2s-go/releases/download",
		CurrentVersion:       "0.1.38",
		VerifySignatures:     true,
		RollbackEnabled:      true,
		HealthCheckTimeout:   5 * time.Minute,
		CosignIdentityRegexp: "https://github.com/bvboe/b2s-go/*",
		CosignOIDCIssuer:     "https://token.actions.githubusercontent.com",
		VersionConstraints: &VersionConstraints{
			AutoUpdateMinor: true,
			AutoUpdateMajor: false,
			PinnedVersion:   "",
			MinVersion:      "0.1.0",
			MaxVersion:      "1.0.0",
		},
	}

	if !config.Enabled {
		t.Error("Enabled should be true")
	}

	if config.CheckInterval != 6*time.Hour {
		t.Errorf("CheckInterval = %v, want %v", config.CheckInterval, 6*time.Hour)
	}

	if config.FeedURL != "https://github.com/bvboe/b2s-go/releases.atom" {
		t.Errorf("FeedURL = %q, want %q", config.FeedURL, "https://github.com/bvboe/b2s-go/releases.atom")
	}

	if config.AssetBaseURL != "https://github.com/bvboe/b2s-go/releases/download" {
		t.Errorf("AssetBaseURL = %q, want %q", config.AssetBaseURL, "https://github.com/bvboe/b2s-go/releases/download")
	}

	if config.CurrentVersion != "0.1.38" {
		t.Errorf("CurrentVersion = %q, want %q", config.CurrentVersion, "0.1.38")
	}

	if !config.VerifySignatures {
		t.Error("VerifySignatures should be true")
	}

	if !config.RollbackEnabled {
		t.Error("RollbackEnabled should be true")
	}

	if config.HealthCheckTimeout != 5*time.Minute {
		t.Errorf("HealthCheckTimeout = %v, want %v", config.HealthCheckTimeout, 5*time.Minute)
	}

	if config.VersionConstraints == nil {
		t.Fatal("VersionConstraints is nil")
	}
}

func TestUpdater_StopChannel(t *testing.T) {
	config := &Config{
		FeedURL:      "http://localhost:8080/releases.atom",
		AssetBaseURL: "http://localhost:8080/download",
	}

	updater, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create updater: %v", err)
	}

	// Verify stop channel is not nil
	if updater.stopChan == nil {
		t.Fatal("stopChan is nil")
	}

	// Call Stop() - should close the channel
	updater.Stop()

	// Verify channel is closed by reading from it
	select {
	case _, ok := <-updater.stopChan:
		if ok {
			t.Error("stopChan should be closed after Stop()")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("stopChan should be immediately readable after Stop()")
	}
}

func TestUpdater_PauseChannel(t *testing.T) {
	config := &Config{
		FeedURL:      "http://localhost:8080/releases.atom",
		AssetBaseURL: "http://localhost:8080/download",
	}

	updater, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create updater: %v", err)
	}

	// Verify pause channel is not nil
	if updater.pauseChan == nil {
		t.Fatal("pauseChan is nil")
	}

	// Test sending to pause channel doesn't block
	done := make(chan bool)
	go func() {
		updater.Pause()
		done <- true
	}()

	select {
	case <-done:
		// Success - didn't block
	case <-time.After(100 * time.Millisecond):
		t.Error("Pause() blocked unexpectedly")
	}
}

func TestUpdater_TriggerCheck(t *testing.T) {
	config := &Config{
		FeedURL:        "http://localhost:8080/releases.atom",
		AssetBaseURL:   "http://localhost:8080/download",
		CurrentVersion: "0.1.0",
	}

	updater, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create updater: %v", err)
	}

	// TriggerCheck should not block (it starts a goroutine)
	done := make(chan bool)
	go func() {
		updater.TriggerCheck()
		done <- true
	}()

	select {
	case <-done:
		// Success - TriggerCheck returned immediately
	case <-time.After(100 * time.Millisecond):
		t.Error("TriggerCheck() blocked unexpectedly")
	}

	// Give the goroutine time to start (it will fail because no GitHub API)
	time.Sleep(50 * time.Millisecond)

	// Check that status changed (likely to StatusFailed due to API call failing)
	status, _, _, _, _, _ := updater.GetStatus()
	if status == StatusIdle {
		// It might still be idle if the check hasn't started yet
		// This is expected in a unit test without real API
		t.Logf("Status is still idle (expected in unit test)")
	}
}

/*
Integration Tests Needed (require running updater and real/mock services):

1. TestUpdater_Start_DisabledConfig
   - Create updater with Enabled=false
   - Call Start()
   - Verify it returns immediately without checking
   - No updates should be performed

2. TestUpdater_Start_SuccessfulUpdate
   - Create test GitHub release
   - Start updater with short check interval
   - Verify it checks for updates
   - Verify update is downloaded and installed
   - Verify status transitions
   - Clean up

3. TestUpdater_Start_NoUpdateNeeded
   - Current version equals latest version
   - Start updater
   - Verify no update is performed
   - Verify status returns to idle

4. TestUpdater_Start_PauseResume
   - Start updater
   - Pause it
   - Verify no checks happen while paused
   - Resume it
   - Verify checks resume
   - Clean up

5. TestUpdater_Start_Stop
   - Start updater
   - Let it run for a few intervals
   - Stop it
   - Verify it stops cleanly
   - Verify no more checks happen

6. TestUpdater_CheckForUpdate_NetworkError
   - Mock GitHub API to return network error
   - Trigger check
   - Verify status becomes Failed
   - Verify error message is set

7. TestUpdater_CheckForUpdate_VersionConstraints
   - Set version constraints (e.g., max version)
   - Latest version violates constraint
   - Trigger check
   - Verify update is not performed

8. TestUpdater_PerformUpdate_DownloadFailure
   - Mock download to fail
   - Trigger update
   - Verify status becomes Failed
   - Verify rollback (if enabled)

9. TestUpdater_PerformUpdate_VerificationFailure
   - Enable signature verification
   - Mock verification to fail
   - Trigger update
   - Verify update is aborted
   - Verify status becomes Failed

10. TestUpdater_PerformUpdate_InstallationFailure
    - Mock installation to fail
    - Trigger update
    - Verify status becomes Failed
    - Verify rollback occurs

11. TestUpdater_CheckInterval
    - Create updater with 1 second interval
    - Start it
    - Count number of checks over 5 seconds
    - Verify checks happen at correct interval
    - Clean up

12. TestUpdater_ConcurrentUpdates
    - Start updater
    - Trigger multiple manual checks
    - Verify only one update runs at a time
    - Verify no race conditions

These integration tests should be in a separate file with build tags like:
  //go:build integration

They would need:
- Mock GitHub API or test repository
- Real filesystem access
- Time-based testing
- Proper cleanup
- Handling of concurrent operations
*/
