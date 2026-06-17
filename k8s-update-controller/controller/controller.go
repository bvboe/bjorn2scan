package controller

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/bvboe/b2s-go/k8s-update-controller/config"
)

var log = slog.Default().With("component", "k8s-update-controller")

// Controller manages the update process
type Controller struct {
	config         *config.Config
	helmClient     *HelmClient
	registryClient *RegistryClient
	versionChecker *VersionChecker
}

// UpdateResult contains the result of an update check
type UpdateResult struct {
	CurrentVersion   string
	LatestVersion    string
	UpdateAvailable  bool
	UpdatePerformed  bool
	UpdatedToVersion string
	Reason           string
}

// New creates a new controller
func New(cfg *config.Config) (*Controller, error) {
	// Create Helm client
	helmClient, err := NewHelmClient(cfg.Helm.Namespace, cfg.Helm.ReleaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to create Helm client: %w", err)
	}

	// Create registry client
	registryClient := NewRegistryClient(cfg.Helm.ChartRegistry)

	// Create version checker
	versionChecker := NewVersionChecker(&cfg.VersionConstraints)

	return &Controller{
		config:         cfg,
		helmClient:     helmClient,
		registryClient: registryClient,
		versionChecker: versionChecker,
	}, nil
}

// CheckAndUpdate performs a single update check and applies updates if needed
func (c *Controller) CheckAndUpdate(ctx context.Context) (*UpdateResult, error) {
	log := log
	result := &UpdateResult{}

	// 1. Get current release version
	log.Info("step 1: getting current release")
	currentRelease, err := c.helmClient.GetCurrentRelease()
	if err != nil {
		return nil, fmt.Errorf("failed to get current release: %w", err)
	}
	result.CurrentVersion = currentRelease.Chart.Metadata.Version
	log.Info("current version", "version", result.CurrentVersion)

	// 2. List available versions from registry
	log.Info("step 2: querying registry for available versions")
	versions, err := c.registryClient.ListVersions(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list versions: %w", err)
	}
	log.Info("found versions in registry", "count", len(versions))

	// 3. Find latest version matching constraints
	log.Info("step 3: evaluating version constraints")
	latestVersion, err := c.versionChecker.FindLatestVersion(result.CurrentVersion, versions)
	if err != nil {
		return nil, fmt.Errorf("failed to find latest version: %w", err)
	}
	result.LatestVersion = latestVersion

	// 4. Check if update should be performed
	shouldUpdate, reason := c.versionChecker.ShouldUpdate(result.CurrentVersion, latestVersion)
	log.Info("update evaluation", "should_update", shouldUpdate, "reason", reason)

	if !shouldUpdate {
		result.UpdateAvailable = false
		result.Reason = reason
		return result, nil
	}

	result.UpdateAvailable = true

	// 5. Download chart
	log.Info("step 4: downloading chart", "version", latestVersion)
	chartPath, err := c.registryClient.DownloadChart(ctx, latestVersion)
	if err != nil {
		return nil, fmt.Errorf("failed to download chart: %w", err)
	}
	defer func() {
		// Clean up downloaded chart (parent directory)
		// chartPath is like /tmp/helm-chart-12345/chart.tgz
		// We want to remove /tmp/helm-chart-12345
		if chartPath != "" {
			dir := chartPath[:len(chartPath)-len("/chart.tgz")]
			_ = c.cleanupTempDir(dir)
		}
	}()
	log.Info("chart downloaded", "path", chartPath)

	// 6. Verify signature (if enabled)
	if c.config.Verification.Enabled {
		log.Info("step 5: verifying chart signature")
		if err := c.registryClient.VerifySignature(ctx, chartPath, latestVersion,
			c.config.Verification.ReleaseBaseURL,
			c.config.Verification.CosignIdentityRegexp,
			c.config.Verification.CosignOIDCIssuer); err != nil {
			return nil, fmt.Errorf("signature verification failed: %w", err)
		}
		log.Info("signature verified")
	} else {
		log.Warn("signature verification disabled; enable verification.enabled for supply-chain security")
	}

	// 7. Perform Helm upgrade
	log.Info("step 6: upgrading release", "version", latestVersion)
	if err := c.helmClient.UpgradeRelease(ctx, chartPath, latestVersion); err != nil {
		return nil, fmt.Errorf("helm upgrade failed: %w", err)
	}
	log.Info("upgrade completed")

	result.UpdatePerformed = true
	result.UpdatedToVersion = latestVersion

	// 8. Wait for health check
	if c.config.Rollback.Enabled {
		delay := c.config.Rollback.HealthCheckDelay()
		log.Info("step 7: waiting for health check", "delay", delay)
		time.Sleep(delay)

		healthy, err := c.helmClient.IsReleaseHealthy()
		if err != nil || !healthy {
			log.Error("health check failed", "error", err)

			if c.config.Rollback.AutoRollback {
				log.Info("performing automatic rollback")
				if rbErr := c.helmClient.RollbackRelease(); rbErr != nil {
					return nil, fmt.Errorf("rollback failed after upgrade failure: %w", rbErr)
				}
				return nil, fmt.Errorf("upgrade rolled back due to health check failure")
			}

			return nil, fmt.Errorf("health check failed but auto-rollback is disabled")
		}

		log.Info("health check passed")
	}

	return result, nil
}

// cleanupTempDir removes a temporary directory
func (c *Controller) cleanupTempDir(dir string) error {
	// Implementation for cleanup
	return nil
}
