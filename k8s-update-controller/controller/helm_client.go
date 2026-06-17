package controller

import (
	"context"
	"fmt"
	"os"
	"time"

	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/release"
	"k8s.io/client-go/rest"
)


// HelmClient wraps Helm operations
type HelmClient struct {
	namespace   string
	releaseName string
	settings    *cli.EnvSettings
}

// NewHelmClient creates a new Helm client
func NewHelmClient(namespace, releaseName string) (*HelmClient, error) {
	settings := cli.New()
	settings.SetNamespace(namespace)

	// Verify we can create a Kubernetes config
	_, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster config: %w", err)
	}

	return &HelmClient{
		namespace:   namespace,
		releaseName: releaseName,
		settings:    settings,
	}, nil
}

// GetCurrentRelease returns the currently installed release
func (hc *HelmClient) GetCurrentRelease() (*release.Release, error) {
	actionConfig, err := hc.getActionConfig()
	if err != nil {
		return nil, err
	}

	getAction := action.NewGet(actionConfig)
	rel, err := getAction.Run(hc.releaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to get release %s: %w", hc.releaseName, err)
	}

	return rel, nil
}

// UpgradeRelease performs a Helm upgrade
func (hc *HelmClient) UpgradeRelease(ctx context.Context, chartPath string, version string) error {
	log := log

	actionConfig, err := hc.getActionConfig()
	if err != nil {
		return err
	}

	// Load chart
	chart, err := loader.Load(chartPath)
	if err != nil {
		return fmt.Errorf("failed to load chart: %w", err)
	}

	// Create upgrade action
	upgradeAction := action.NewUpgrade(actionConfig)
	upgradeAction.Namespace = hc.namespace
	upgradeAction.Wait = true
	upgradeAction.Timeout = 10 * time.Minute

	// Perform upgrade
	rel, err := upgradeAction.Run(hc.releaseName, chart, nil)
	if err != nil {
		return fmt.Errorf("failed to upgrade release: %w", err)
	}

	log.Info("upgraded release", "name", rel.Name, "version", rel.Chart.Metadata.Version)
	return nil
}

// RollbackRelease rolls back to the previous release
func (hc *HelmClient) RollbackRelease() error {
	log := log

	actionConfig, err := hc.getActionConfig()
	if err != nil {
		return err
	}

	rollbackAction := action.NewRollback(actionConfig)
	rollbackAction.Wait = true
	rollbackAction.Timeout = 5 * time.Minute

	if err := rollbackAction.Run(hc.releaseName); err != nil {
		return fmt.Errorf("failed to rollback release: %w", err)
	}

	log.Info("rolled back release", "name", hc.releaseName)
	return nil
}

// GetReleaseHistory returns the release history
func (hc *HelmClient) GetReleaseHistory() ([]*release.Release, error) {
	actionConfig, err := hc.getActionConfig()
	if err != nil {
		return nil, err
	}

	historyAction := action.NewHistory(actionConfig)
	historyAction.Max = 10

	releases, err := historyAction.Run(hc.releaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to get release history: %w", err)
	}

	return releases, nil
}

// IsReleaseHealthy checks if the release is healthy by verifying deployment status
func (hc *HelmClient) IsReleaseHealthy() (bool, error) {
	rel, err := hc.GetCurrentRelease()
	if err != nil {
		return false, err
	}

	// Check release status
	if rel.Info.Status != release.StatusDeployed {
		return false, fmt.Errorf("release status is %s, expected deployed", rel.Info.Status)
	}

	return true, nil
}

// getActionConfig creates a Helm action configuration
func (hc *HelmClient) getActionConfig() (*action.Configuration, error) {
	log := log
	actionConfig := new(action.Configuration)

	// Initialize with Kubernetes client
	if err := actionConfig.Init(hc.settings.RESTClientGetter(), hc.namespace, os.Getenv("HELM_DRIVER"), func(format string, v ...interface{}) {
		log.Debug("helm debug", "message", fmt.Sprintf(format, v...))
	}); err != nil {
		return nil, fmt.Errorf("failed to initialize Helm action config: %w", err)
	}

	return actionConfig, nil
}
