package updater

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/logging"
)

var log = logging.For(logging.ComponentHTTP)

// Status represents the current state of the updater
type Status string

const (
	StatusIdle        Status = "idle"
	StatusChecking    Status = "checking"
	StatusDownloading Status = "downloading"
	StatusVerifying   Status = "verifying"
	StatusInstalling  Status = "installing"
	StatusRestarting  Status = "restarting"
	StatusFailed      Status = "failed"
)

// Config contains updater configuration
type Config struct {
	Enabled                bool
	CheckInterval          time.Duration
	FeedURL                string
	AssetBaseURL           string
	CurrentVersion         string
	VerifySignatures       bool
	RollbackEnabled        bool
	HealthCheckTimeout     time.Duration
	VersionConstraints     *VersionConstraints
	CosignIdentityRegexp   string
	CosignOIDCIssuer       string
	DownloadMaxRetries     int
	DownloadValidateAssets bool
}

// Updater manages the auto-update process
type Updater struct {
	config         *Config
	status         Status
	lastCheck      time.Time
	lastUpdate     time.Time
	latestVersion  string
	errorMsg       string
	mu             sync.RWMutex
	stopChan       chan struct{}
	pauseChan      chan bool
	paused         bool
	feedParser     *FeedParser
	versionChecker *VersionChecker
}

// New creates a new updater
func New(config *Config) (*Updater, error) {
	if config.FeedURL == "" {
		return nil, fmt.Errorf("feed URL is required")
	}
	if config.AssetBaseURL == "" {
		return nil, fmt.Errorf("asset base URL is required")
	}

	feedParser := NewFeedParser(config.FeedURL)
	versionChecker := NewVersionChecker(config.VersionConstraints)

	return &Updater{
		config:         config,
		status:         StatusIdle,
		stopChan:       make(chan struct{}),
		pauseChan:      make(chan bool, 1),
		feedParser:     feedParser,
		versionChecker: versionChecker,
	}, nil
}

// Start begins the update checker loop
func (u *Updater) Start() {
	log := log

	if !u.config.Enabled {
		log.Info("auto-update is disabled")
		return
	}

	log.Info("auto-updater started", "check_interval", u.config.CheckInterval)

	// Check immediately on start, then on schedule
	u.checkForUpdate()

	ticker := time.NewTicker(u.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !u.isPaused() {
				u.checkForUpdate()
			}
		case paused := <-u.pauseChan:
			u.mu.Lock()
			u.paused = paused
			u.mu.Unlock()
			if paused {
				log.Info("auto-updater paused")
			} else {
				log.Info("auto-updater resumed")
			}
		case <-u.stopChan:
			log.Info("auto-updater stopped")
			return
		}
	}
}

// checkForUpdate checks for and applies updates
func (u *Updater) checkForUpdate() {
	log := log

	u.setStatus(StatusChecking, "")
	u.mu.Lock()
	u.lastCheck = time.Now()
	u.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	log.Info("checking for updates")

	// Get latest release from feed
	release, err := u.feedParser.GetLatestRelease(ctx)
	if err != nil {
		u.setStatus(StatusFailed, fmt.Sprintf("failed to check for updates: %v", err))
		return
	}

	version := release.Version

	u.mu.Lock()
	u.latestVersion = version
	u.mu.Unlock()

	log.Info("version check", "current_version", u.config.CurrentVersion, "latest_version", version)

	// Check if update should be performed
	shouldUpdate, reason := u.versionChecker.ShouldUpdate(u.config.CurrentVersion, version)
	if !shouldUpdate {
		log.Info("no update needed", "reason", reason)
		u.setStatus(StatusIdle, "")
		return
	}

	log.Info("update available", "from_version", u.config.CurrentVersion, "to_version", version)

	// Perform update
	if err := u.performUpdate(ctx, release); err != nil {
		u.setStatus(StatusFailed, fmt.Sprintf("update failed: %v", err))
		log.Error("update failed", "error", err)
		return
	}

	u.mu.Lock()
	u.lastUpdate = time.Now()
	u.mu.Unlock()

	u.setStatus(StatusIdle, "")
	log.Info("update completed successfully")
}

// performUpdate downloads and installs an update
func (u *Updater) performUpdate(ctx context.Context, release *Release) error {
	log := log

	// Download
	u.setStatus(StatusDownloading, "")
	log.Info("downloading update")

	// Configure downloader with retry and validation settings
	downloaderConfig := &DownloaderConfig{
		AssetBaseURL:     u.config.AssetBaseURL,
		MaxRetries:       u.config.DownloadMaxRetries,
		EnableValidation: u.config.DownloadValidateAssets,
	}

	downloader, err := NewDownloaderWithConfig(downloaderConfig)
	if err != nil {
		return fmt.Errorf("failed to create downloader: %w", err)
	}
	defer func() { _ = downloader.Cleanup() }()

	// Use tag for download (includes 'v' prefix if present)
	binaryPath, err := downloader.DownloadRelease(ctx, release.Tag)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}

	// Verify tarball signature before extraction.
	// The bundle signs the tarball itself, so we verify before trusting its contents.
	if u.config.VerifySignatures {
		u.setStatus(StatusVerifying, "")
		log.Info("verifying signature")

		verifier := NewVerifier(u.config.CosignIdentityRegexp, u.config.CosignOIDCIssuer)
		bundlePath := binaryPath + ".sigstore"

		if err := verifier.VerifySignature(binaryPath, bundlePath); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
		log.Info("signature verified")
	} else {
		log.Warn("signature verification disabled; install sigstore bundle verification for supply-chain security")
	}

	// Extract binary from verified tarball
	log.Info("extracting binary")
	extractedPath, err := downloader.ExtractBinary(binaryPath)
	if err != nil {
		return fmt.Errorf("extraction failed: %w", err)
	}

	// Install
	u.setStatus(StatusInstalling, "")
	installer := NewInstaller("", "", u.config.HealthCheckTimeout)

	// Pass cleanup function to Install() - it will cleanup after copying the binary but before exit
	// The defer cleanup (line 175) will still run on error paths
	if err := installer.Install(extractedPath, downloader.Cleanup); err != nil {
		return fmt.Errorf("installation failed: %w", err)
	}

	return nil
}

// Stop stops the updater
func (u *Updater) Stop() {
	close(u.stopChan)
}

// Pause pauses automatic updates
func (u *Updater) Pause() {
	u.pauseChan <- true
}

// Resume resumes automatic updates
func (u *Updater) Resume() {
	u.pauseChan <- false
}

// TriggerCheck manually triggers an update check
func (u *Updater) TriggerCheck() {
	go u.checkForUpdate()
}

// GetStatus returns the current status
func (u *Updater) GetStatus() (Status, string, time.Time, time.Time, string, string) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.status, u.errorMsg, u.lastCheck, u.lastUpdate, u.latestVersion, u.config.CurrentVersion
}

// setStatus updates the current status
func (u *Updater) setStatus(status Status, errorMsg string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.status = status
	u.errorMsg = errorMsg
}

// isPaused checks if the updater is paused
func (u *Updater) isPaused() bool {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.paused
}
