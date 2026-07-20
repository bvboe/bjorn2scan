package controller

import (
	"context"
	"fmt"
	"os"
	"time"

	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/chart/loader"
	"helm.sh/helm/v4/pkg/cli"
	"helm.sh/helm/v4/pkg/kube"
	relcommon "helm.sh/helm/v4/pkg/release/common"
	release "helm.sh/helm/v4/pkg/release/v1"
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

	// Helm v4 actions return release.Releaser (an `any`); the driver stores
	// v1 releases, so assert back to the concrete type.
	r, ok := rel.(*release.Release)
	if !ok {
		return nil, fmt.Errorf("unexpected release type %T for %s", rel, hc.releaseName)
	}
	return r, nil
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
	upgradeAction.WaitStrategy = kube.StatusWatcherStrategy
	upgradeAction.Timeout = 10 * time.Minute

	// Perform upgrade
	rel, err := upgradeAction.RunWithContext(ctx, hc.releaseName, chart, nil)
	if err != nil {
		return fmt.Errorf("failed to upgrade release: %w", err)
	}

	if r, ok := rel.(*release.Release); ok {
		log.Info("upgraded release", "name", r.Name, "version", r.Chart.Metadata.Version)
	} else {
		log.Info("upgraded release", "name", hc.releaseName, "version", version)
	}
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
	rollbackAction.WaitStrategy = kube.StatusWatcherStrategy
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

	rels, err := historyAction.Run(hc.releaseName)
	if err != nil {
		return nil, fmt.Errorf("failed to get release history: %w", err)
	}

	releases := make([]*release.Release, 0, len(rels))
	for _, r := range rels {
		rr, ok := r.(*release.Release)
		if !ok {
			return nil, fmt.Errorf("unexpected release type %T in history", r)
		}
		releases = append(releases, rr)
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
	if rel.Info.Status != relcommon.StatusDeployed {
		return false, fmt.Errorf("release status is %s, expected deployed", rel.Info.Status)
	}

	return true, nil
}

// getActionConfig creates a Helm action configuration
func (hc *HelmClient) getActionConfig() (*action.Configuration, error) {
	actionConfig := new(action.Configuration)

	// Initialize with Kubernetes client. Helm v4 dropped the debug-log
	// parameter from Init (logging now goes through log/slog).
	if err := actionConfig.Init(hc.settings.RESTClientGetter(), hc.namespace, os.Getenv("HELM_DRIVER")); err != nil {
		return nil, fmt.Errorf("failed to initialize Helm action config: %w", err)
	}

	return actionConfig, nil
}
