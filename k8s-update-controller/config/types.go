package config

import "time"

// Config represents the update controller configuration
type Config struct {
	Enabled            bool               `yaml:"enabled"`
	VersionConstraints VersionConstraints `yaml:"versionConstraints"`
	Helm               HelmConfig         `yaml:"helm"`
	Rollback           RollbackConfig     `yaml:"rollback"`
	Verification       VerificationConfig `yaml:"verification"`
}

// VersionConstraints defines version update policies
type VersionConstraints struct {
	AutoUpdateMinor bool   `yaml:"autoUpdateMinor"`
	AutoUpdateMajor bool   `yaml:"autoUpdateMajor"`
	PinnedVersion   string `yaml:"pinnedVersion"`
	MinVersion      string `yaml:"minVersion"`
	MaxVersion      string `yaml:"maxVersion"`
}

// HelmConfig contains Helm-specific configuration
type HelmConfig struct {
	ReleaseName   string `yaml:"releaseName"`
	Namespace     string `yaml:"namespace"`
	ChartRegistry string `yaml:"chartRegistry"`
}

// RollbackConfig defines rollback behavior
type RollbackConfig struct {
	Enabled             bool   `yaml:"enabled"`
	HealthCheckDelayStr string `yaml:"healthCheckDelay"`
	healthCheckDelay    time.Duration
	AutoRollback        bool `yaml:"autoRollback"`
}

// HealthCheckDelay returns the parsed duration
func (r *RollbackConfig) HealthCheckDelay() time.Duration {
	return r.healthCheckDelay
}

// ParseDurations parses string durations into time.Duration
func (r *RollbackConfig) ParseDurations() error {
	if r.HealthCheckDelayStr == "" {
		r.healthCheckDelay = 5 * time.Minute // default
		return nil
	}
	d, err := time.ParseDuration(r.HealthCheckDelayStr)
	if err != nil {
		return err
	}
	r.healthCheckDelay = d
	return nil
}

// VerificationConfig defines signature verification settings
type VerificationConfig struct {
	Enabled              bool   `yaml:"enabled"`
	CosignIdentityRegexp string `yaml:"cosignIdentityRegexp"`
	CosignOIDCIssuer     string `yaml:"cosignOIDCIssuer"`
	// ReleaseBaseURL is the base URL for GitHub release assets, used to fetch
	// the .sigstore bundle alongside each released Helm chart.
	// e.g. "https://github.com/bvboe/b2s-go/releases/download"
	ReleaseBaseURL string `yaml:"releaseBaseURL"`
}
