// Package config provides configuration loading for bjorn2scan components.
// It supports loading from properties/INI files with environment variable overrides.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/ini.v1"
)

// Config holds all configuration options for bjorn2scan components.
type Config struct {
	Port         string
	DBPath       string
	DebugEnabled bool
	WebUIEnabled bool

	// Auto-update configuration
	AutoUpdateEnabled            bool
	AutoUpdateCheckInterval      time.Duration
	AutoUpdateMinorVersions      bool
	AutoUpdateMajorVersions      bool
	AutoUpdatePinnedVersion      string
	AutoUpdateMinVersion         string
	AutoUpdateMaxVersion         string
	UpdateFeedURL                string
	UpdateAssetBaseURL           string
	UpdateVerifySignatures       bool
	UpdateRollbackEnabled        bool
	UpdateHealthCheckTimeout     time.Duration
	UpdateCosignIdentityRegexp   string
	UpdateCosignOIDCIssuer       string
	UpdateDownloadMaxRetries     int
	UpdateDownloadValidateAssets bool

	// Scheduled jobs configuration
	JobsEnabled bool

	// Rescan database job - monitors vulnerability database for updates
	JobsRescanDatabaseEnabled  bool
	JobsRescanDatabaseInterval time.Duration
	JobsRescanDatabaseTimeout  time.Duration

	// Refresh images job - triggers periodic reconciliation
	JobsRefreshImagesEnabled  bool
	JobsRefreshImagesInterval time.Duration
	JobsRefreshImagesTimeout  time.Duration

	// Cleanup job - removes orphaned images
	JobsCleanupEnabled  bool
	JobsCleanupInterval time.Duration
	JobsCleanupTimeout  time.Duration

	// OpenTelemetry metrics configuration
	OTELMetricsEnabled      bool
	OTELMetricsEndpoint     string
	OTELMetricsProtocol     string // "grpc" or "http"
	OTELMetricsPushInterval time.Duration
	OTELMetricsInsecure     bool
	OTELUseDirectExport     bool // Use direct OTLP export for high-cardinality metrics (bypasses SDK buffering)
	OTELDirectBatchSize     int  // Batch size for direct export (default 5000)

	// Individual metric toggles
	MetricsDeploymentEnabled             bool // Enable bjorn2scan_deployment metric
	MetricsScannedContainersEnabled      bool // Enable bjorn2scan_scanned_container metric
	MetricsVulnerabilitiesEnabled        bool // Enable bjorn2scan_vulnerability metric
	MetricsVulnerabilityExploitedEnabled bool // Enable bjorn2scan_vulnerability_exploited metric
	MetricsVulnerabilityRiskEnabled      bool // Enable bjorn2scan_vulnerability_risk metric
	MetricsImageScanStatusEnabled        bool // Enable bjorn2scan_image_scan_status metric

	// Metrics staleness tracking
	MetricsStalenessWindow time.Duration // Duration after which metrics are considered stale (default: 60m)

	// Host scanning configuration
	HostScanningEnabled             bool          // Enable scanning of host/node packages
	HostScanningInterval            time.Duration // Interval for periodic host SBOM regeneration (default: 24h)
	HostScanningExtraExclusions     []string      // Additional exclusion patterns for host scanning
	HostScanningAutoDetectNFS       bool          // Auto-detect network mounts (default: true)
	HostScanningExtraNetworkFSTypes []string      // Additional network FS types to detect (added to defaults)

	// Node metrics toggles (only applicable when host scanning is enabled)
	MetricsNodeScannedEnabled              bool // Enable bjorn2scan_node_scanned metric
	MetricsNodeScanStatusEnabled           bool // Enable bjorn2scan_node_scan_status metric
	MetricsNodeVulnerabilitiesEnabled      bool // Enable bjorn2scan_node_vulnerability metric
	MetricsNodeVulnerabilityRiskEnabled    bool // Enable bjorn2scan_node_vulnerability_risk metric
	MetricsNodeVulnerabilityExploitedEnabled bool // Enable bjorn2scan_node_vulnerability_exploited metric
}

// defaultConfig returns a Config with hardcoded defaults.
func defaultConfig() *Config {
	return &Config{
		Port:         "9999",
		DBPath:       "/var/lib/bjorn2scan/data/containers.db",
		DebugEnabled: false,
		WebUIEnabled: true,

		// Auto-update defaults
		AutoUpdateEnabled: true,
		//Todo - revert back to something more reasonable
		AutoUpdateCheckInterval:      1 * time.Hour,
		AutoUpdateMinorVersions:      true,
		AutoUpdateMajorVersions:      false,
		AutoUpdatePinnedVersion:      "",
		AutoUpdateMinVersion:         "",
		AutoUpdateMaxVersion:         "",
		UpdateFeedURL:                "https://github.com/bvboe/b2s-go/releases.atom",
		UpdateAssetBaseURL:           "https://github.com/bvboe/b2s-go/releases/download",
		UpdateVerifySignatures:       true,
		UpdateRollbackEnabled:        true,
		UpdateHealthCheckTimeout:     60 * time.Second,
		UpdateCosignIdentityRegexp:   "https://github.com/bvboe/b2s-go/*",
		UpdateCosignOIDCIssuer:       "https://token.actions.githubusercontent.com",
		UpdateDownloadMaxRetries:     3,
		UpdateDownloadValidateAssets: true,

		// Jobs enabled by default
		JobsEnabled: true,

		// Rescan database job - check every 30 minutes
		JobsRescanDatabaseEnabled:  true,
		JobsRescanDatabaseInterval: 30 * time.Minute,
		JobsRescanDatabaseTimeout:  30 * time.Minute,

		// Refresh images job - periodic container reconciliation
		JobsRefreshImagesEnabled:  true,
		JobsRefreshImagesInterval: 6 * time.Hour,
		JobsRefreshImagesTimeout:  10 * time.Minute,

		// Cleanup job - run daily
		JobsCleanupEnabled:  true,
		JobsCleanupInterval: 24 * time.Hour,
		JobsCleanupTimeout:  1 * time.Hour,

		// OpenTelemetry metrics - disabled by default
		OTELMetricsEnabled:      false,
		OTELMetricsEndpoint:     "localhost:4317",
		OTELMetricsProtocol:     "grpc", // Use "http" for Prometheus native OTLP
		OTELMetricsPushInterval: 15 * time.Minute,
		OTELMetricsInsecure:     true,
		OTELUseDirectExport:     true,  // Bypass SDK buffering for high-cardinality node metrics
		OTELDirectBatchSize:     5000,  // Batch size for direct export

		// Individual metrics - enabled by default
		MetricsDeploymentEnabled:             true,
		MetricsScannedContainersEnabled:      true,
		MetricsVulnerabilitiesEnabled:        true,
		MetricsVulnerabilityExploitedEnabled: true,
		MetricsVulnerabilityRiskEnabled:      true,
		MetricsImageScanStatusEnabled:        true,

		// Metrics staleness - 60 minutes by default
		MetricsStalenessWindow: 60 * time.Minute,

		// Host scanning - enabled by default
		HostScanningEnabled:             true,
		HostScanningInterval:            24 * time.Hour,
		HostScanningExtraExclusions:     nil,
		HostScanningAutoDetectNFS:       true,
		HostScanningExtraNetworkFSTypes: nil,

		// Node metrics - enabled by default when host scanning is enabled
		MetricsNodeScannedEnabled:              true,
		MetricsNodeScanStatusEnabled:           true,
		MetricsNodeVulnerabilitiesEnabled:      true,
		MetricsNodeVulnerabilityRiskEnabled:    true,
		MetricsNodeVulnerabilityExploitedEnabled: true,
	}
}

// LoadConfig loads configuration from the specified file path.
// Environment variables override file values.
// Precedence: environment variables > config file > defaults
func LoadConfig(path string) (*Config, error) {
	cfg := defaultConfig()

	// Try to load config file
	if path != "" {
		if _, err := os.Stat(path); err == nil {
			iniFile, err := ini.Load(path)
			if err != nil {
				return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
			}

			section := iniFile.Section("")

			// Load port
			if section.HasKey("port") {
				cfg.Port = section.Key("port").String()
			}

			// Load database path
			if section.HasKey("db_path") {
				cfg.DBPath = section.Key("db_path").String()
			}

			// Load debug enabled
			if section.HasKey("debug_enabled") {
				debugStr := strings.ToLower(section.Key("debug_enabled").String())
				cfg.DebugEnabled = debugStr == "true" || debugStr == "1" || debugStr == "yes"
			}

			// Load web UI enabled
			if section.HasKey("web_ui_enabled") {
				val := strings.ToLower(section.Key("web_ui_enabled").String())
				cfg.WebUIEnabled = val == "true" || val == "1" || val == "yes"
			}

			// Load auto-update settings
			if section.HasKey("auto_update_enabled") {
				val := strings.ToLower(section.Key("auto_update_enabled").String())
				cfg.AutoUpdateEnabled = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("auto_update_check_interval") {
				if duration, err := time.ParseDuration(section.Key("auto_update_check_interval").String()); err == nil {
					cfg.AutoUpdateCheckInterval = duration
				}
			}
			if section.HasKey("auto_update_minor_versions") {
				val := strings.ToLower(section.Key("auto_update_minor_versions").String())
				cfg.AutoUpdateMinorVersions = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("auto_update_major_versions") {
				val := strings.ToLower(section.Key("auto_update_major_versions").String())
				cfg.AutoUpdateMajorVersions = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("auto_update_pinned_version") {
				cfg.AutoUpdatePinnedVersion = section.Key("auto_update_pinned_version").String()
			}
			if section.HasKey("auto_update_min_version") {
				cfg.AutoUpdateMinVersion = section.Key("auto_update_min_version").String()
			}
			if section.HasKey("auto_update_max_version") {
				cfg.AutoUpdateMaxVersion = section.Key("auto_update_max_version").String()
			}
			if section.HasKey("update_feed_url") {
				cfg.UpdateFeedURL = section.Key("update_feed_url").String()
			}
			if section.HasKey("update_asset_base_url") {
				cfg.UpdateAssetBaseURL = section.Key("update_asset_base_url").String()
			}
			if section.HasKey("update_verify_signatures") {
				val := strings.ToLower(section.Key("update_verify_signatures").String())
				cfg.UpdateVerifySignatures = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("update_rollback_enabled") {
				val := strings.ToLower(section.Key("update_rollback_enabled").String())
				cfg.UpdateRollbackEnabled = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("update_health_check_timeout") {
				if duration, err := time.ParseDuration(section.Key("update_health_check_timeout").String()); err == nil {
					cfg.UpdateHealthCheckTimeout = duration
				} else if seconds, err := strconv.Atoi(section.Key("update_health_check_timeout").String()); err == nil {
					cfg.UpdateHealthCheckTimeout = time.Duration(seconds) * time.Second
				}
			}
			if section.HasKey("update_cosign_identity_regexp") {
				cfg.UpdateCosignIdentityRegexp = section.Key("update_cosign_identity_regexp").String()
			}
			if section.HasKey("update_cosign_oidc_issuer") {
				cfg.UpdateCosignOIDCIssuer = section.Key("update_cosign_oidc_issuer").String()
			}
			if section.HasKey("update_download_max_retries") {
				if retries, err := strconv.Atoi(section.Key("update_download_max_retries").String()); err == nil && retries >= 0 {
					cfg.UpdateDownloadMaxRetries = retries
				}
			}
			if section.HasKey("update_download_validate_assets") {
				val := strings.ToLower(section.Key("update_download_validate_assets").String())
				cfg.UpdateDownloadValidateAssets = val == "true" || val == "1" || val == "yes"
			}

			// Load jobs configuration
			if section.HasKey("jobs_enabled") {
				val := strings.ToLower(section.Key("jobs_enabled").String())
				cfg.JobsEnabled = val == "true" || val == "1" || val == "yes"
			}

			// Rescan database job
			if section.HasKey("jobs_rescan_database_enabled") {
				val := strings.ToLower(section.Key("jobs_rescan_database_enabled").String())
				cfg.JobsRescanDatabaseEnabled = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("jobs_rescan_database_interval") {
				if duration, err := time.ParseDuration(section.Key("jobs_rescan_database_interval").String()); err == nil {
					cfg.JobsRescanDatabaseInterval = duration
				}
			}
			if section.HasKey("jobs_rescan_database_timeout") {
				if duration, err := time.ParseDuration(section.Key("jobs_rescan_database_timeout").String()); err == nil {
					cfg.JobsRescanDatabaseTimeout = duration
				}
			}

			// Refresh images job
			if section.HasKey("jobs_refresh_images_enabled") {
				val := strings.ToLower(section.Key("jobs_refresh_images_enabled").String())
				cfg.JobsRefreshImagesEnabled = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("jobs_refresh_images_interval") {
				if duration, err := time.ParseDuration(section.Key("jobs_refresh_images_interval").String()); err == nil {
					cfg.JobsRefreshImagesInterval = duration
				}
			}
			if section.HasKey("jobs_refresh_images_timeout") {
				if duration, err := time.ParseDuration(section.Key("jobs_refresh_images_timeout").String()); err == nil {
					cfg.JobsRefreshImagesTimeout = duration
				}
			}

			// Cleanup job
			if section.HasKey("jobs_cleanup_enabled") {
				val := strings.ToLower(section.Key("jobs_cleanup_enabled").String())
				cfg.JobsCleanupEnabled = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("jobs_cleanup_interval") {
				if duration, err := time.ParseDuration(section.Key("jobs_cleanup_interval").String()); err == nil {
					cfg.JobsCleanupInterval = duration
				}
			}
			if section.HasKey("jobs_cleanup_timeout") {
				if duration, err := time.ParseDuration(section.Key("jobs_cleanup_timeout").String()); err == nil {
					cfg.JobsCleanupTimeout = duration
				}
			}

			// OpenTelemetry metrics configuration
			if section.HasKey("otel_metrics_enabled") {
				val := strings.ToLower(section.Key("otel_metrics_enabled").String())
				cfg.OTELMetricsEnabled = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("otel_metrics_endpoint") {
				cfg.OTELMetricsEndpoint = section.Key("otel_metrics_endpoint").String()
			}
			if section.HasKey("otel_metrics_protocol") {
				protocol := strings.ToLower(section.Key("otel_metrics_protocol").String())
				if protocol == "grpc" || protocol == "http" {
					cfg.OTELMetricsProtocol = protocol
				}
			}
			if section.HasKey("otel_metrics_push_interval") {
				if duration, err := time.ParseDuration(section.Key("otel_metrics_push_interval").String()); err == nil {
					cfg.OTELMetricsPushInterval = duration
				}
			}
			if section.HasKey("otel_metrics_insecure") {
				val := strings.ToLower(section.Key("otel_metrics_insecure").String())
				cfg.OTELMetricsInsecure = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("otel_use_direct_export") {
				val := strings.ToLower(section.Key("otel_use_direct_export").String())
				cfg.OTELUseDirectExport = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("otel_direct_batch_size") {
				if batchSize, err := strconv.Atoi(section.Key("otel_direct_batch_size").String()); err == nil && batchSize > 0 {
					cfg.OTELDirectBatchSize = batchSize
				}
			}

			// Individual metric toggles
			if section.HasKey("metrics_deployment_enabled") {
				val := strings.ToLower(section.Key("metrics_deployment_enabled").String())
				cfg.MetricsDeploymentEnabled = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("metrics_scanned_containers_enabled") {
				val := strings.ToLower(section.Key("metrics_scanned_containers_enabled").String())
				cfg.MetricsScannedContainersEnabled = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("metrics_vulnerabilities_enabled") {
				val := strings.ToLower(section.Key("metrics_vulnerabilities_enabled").String())
				cfg.MetricsVulnerabilitiesEnabled = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("metrics_vulnerability_exploited_enabled") {
				val := strings.ToLower(section.Key("metrics_vulnerability_exploited_enabled").String())
				cfg.MetricsVulnerabilityExploitedEnabled = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("metrics_vulnerability_risk_enabled") {
				val := strings.ToLower(section.Key("metrics_vulnerability_risk_enabled").String())
				cfg.MetricsVulnerabilityRiskEnabled = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("metrics_image_scan_status_enabled") {
				val := strings.ToLower(section.Key("metrics_image_scan_status_enabled").String())
				cfg.MetricsImageScanStatusEnabled = val == "true" || val == "1" || val == "yes"
			}

			// Metrics staleness window
			if section.HasKey("metrics_staleness_window") {
				if duration, err := time.ParseDuration(section.Key("metrics_staleness_window").String()); err == nil {
					cfg.MetricsStalenessWindow = duration
				}
			}

			// Host scanning configuration
			if section.HasKey("host_scanning_enabled") {
				val := strings.ToLower(section.Key("host_scanning_enabled").String())
				cfg.HostScanningEnabled = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("host_scanning_interval") {
				if duration, err := time.ParseDuration(section.Key("host_scanning_interval").String()); err == nil {
					cfg.HostScanningInterval = duration
				}
			}
			if section.HasKey("host_scanning_extra_exclusions") {
				cfg.HostScanningExtraExclusions = parseCommaSeparated(section.Key("host_scanning_extra_exclusions").String())
			}
			if section.HasKey("host_scanning_auto_detect_nfs") {
				val := strings.ToLower(section.Key("host_scanning_auto_detect_nfs").String())
				cfg.HostScanningAutoDetectNFS = val == "true" || val == "1" || val == "yes"
			}
			if section.HasKey("host_scanning_extra_network_fs_types") {
				cfg.HostScanningExtraNetworkFSTypes = parseCommaSeparated(section.Key("host_scanning_extra_network_fs_types").String())
			}
		} else if !os.IsNotExist(err) {
			// File exists but can't be read
			return nil, fmt.Errorf("cannot access config file %s: %w", path, err)
		}
		// If file doesn't exist, just use defaults (no error)
	}

	// Override with environment variables
	if portEnv := os.Getenv("PORT"); portEnv != "" {
		cfg.Port = portEnv
	}

	if dbPathEnv := os.Getenv("DB_PATH"); dbPathEnv != "" {
		cfg.DBPath = dbPathEnv
	}

	if debugEnv := os.Getenv("DEBUG_ENABLED"); debugEnv != "" {
		debugStr := strings.ToLower(debugEnv)
		cfg.DebugEnabled = debugStr == "true" || debugStr == "1" || debugStr == "yes"
	}

	if webUIEnv := os.Getenv("WEB_UI_ENABLED"); webUIEnv != "" {
		val := strings.ToLower(webUIEnv)
		cfg.WebUIEnabled = val == "true" || val == "1" || val == "yes"
	}

	// Jobs enabled
	if jobsEnv := os.Getenv("JOBS_ENABLED"); jobsEnv != "" {
		val := strings.ToLower(jobsEnv)
		cfg.JobsEnabled = val == "true" || val == "1" || val == "yes"
	}

	// Rescan database job
	if enabledEnv := os.Getenv("JOBS_RESCAN_DATABASE_ENABLED"); enabledEnv != "" {
		val := strings.ToLower(enabledEnv)
		cfg.JobsRescanDatabaseEnabled = val == "true" || val == "1" || val == "yes"
	}
	if intervalEnv := os.Getenv("JOBS_RESCAN_DATABASE_INTERVAL"); intervalEnv != "" {
		if duration, err := time.ParseDuration(intervalEnv); err == nil {
			cfg.JobsRescanDatabaseInterval = duration
		}
	}
	if timeoutEnv := os.Getenv("JOBS_RESCAN_DATABASE_TIMEOUT"); timeoutEnv != "" {
		if duration, err := time.ParseDuration(timeoutEnv); err == nil {
			cfg.JobsRescanDatabaseTimeout = duration
		}
	}

	// Refresh images job
	if enabledEnv := os.Getenv("JOBS_REFRESH_IMAGES_ENABLED"); enabledEnv != "" {
		val := strings.ToLower(enabledEnv)
		cfg.JobsRefreshImagesEnabled = val == "true" || val == "1" || val == "yes"
	}
	if intervalEnv := os.Getenv("JOBS_REFRESH_IMAGES_INTERVAL"); intervalEnv != "" {
		if duration, err := time.ParseDuration(intervalEnv); err == nil {
			cfg.JobsRefreshImagesInterval = duration
		}
	}
	if timeoutEnv := os.Getenv("JOBS_REFRESH_IMAGES_TIMEOUT"); timeoutEnv != "" {
		if duration, err := time.ParseDuration(timeoutEnv); err == nil {
			cfg.JobsRefreshImagesTimeout = duration
		}
	}

	// Cleanup job
	if enabledEnv := os.Getenv("JOBS_CLEANUP_ENABLED"); enabledEnv != "" {
		val := strings.ToLower(enabledEnv)
		cfg.JobsCleanupEnabled = val == "true" || val == "1" || val == "yes"
	}
	if intervalEnv := os.Getenv("JOBS_CLEANUP_INTERVAL"); intervalEnv != "" {
		if duration, err := time.ParseDuration(intervalEnv); err == nil {
			cfg.JobsCleanupInterval = duration
		}
	}
	if timeoutEnv := os.Getenv("JOBS_CLEANUP_TIMEOUT"); timeoutEnv != "" {
		if duration, err := time.ParseDuration(timeoutEnv); err == nil {
			cfg.JobsCleanupTimeout = duration
		}
	}

	// OpenTelemetry metrics configuration
	if enabledEnv := os.Getenv("OTEL_METRICS_ENABLED"); enabledEnv != "" {
		val := strings.ToLower(enabledEnv)
		cfg.OTELMetricsEnabled = val == "true" || val == "1" || val == "yes"
	}
	if endpointEnv := os.Getenv("OTEL_METRICS_ENDPOINT"); endpointEnv != "" {
		cfg.OTELMetricsEndpoint = endpointEnv
	}
	if protocolEnv := os.Getenv("OTEL_METRICS_PROTOCOL"); protocolEnv != "" {
		protocol := strings.ToLower(protocolEnv)
		if protocol == "grpc" || protocol == "http" {
			cfg.OTELMetricsProtocol = protocol
		}
	}
	if intervalEnv := os.Getenv("OTEL_METRICS_PUSH_INTERVAL"); intervalEnv != "" {
		if duration, err := time.ParseDuration(intervalEnv); err == nil {
			cfg.OTELMetricsPushInterval = duration
		}
	}
	if insecureEnv := os.Getenv("OTEL_METRICS_INSECURE"); insecureEnv != "" {
		val := strings.ToLower(insecureEnv)
		cfg.OTELMetricsInsecure = val == "true" || val == "1" || val == "yes"
	}
	if useDirectExportEnv := os.Getenv("OTEL_USE_DIRECT_EXPORT"); useDirectExportEnv != "" {
		val := strings.ToLower(useDirectExportEnv)
		cfg.OTELUseDirectExport = val == "true" || val == "1" || val == "yes"
	}
	if directBatchSizeEnv := os.Getenv("OTEL_DIRECT_BATCH_SIZE"); directBatchSizeEnv != "" {
		if batchSize, err := strconv.Atoi(directBatchSizeEnv); err == nil && batchSize > 0 {
			cfg.OTELDirectBatchSize = batchSize
		}
	}

	// Individual metric toggles
	if deploymentEnabledEnv := os.Getenv("METRICS_DEPLOYMENT_ENABLED"); deploymentEnabledEnv != "" {
		val := strings.ToLower(deploymentEnabledEnv)
		cfg.MetricsDeploymentEnabled = val == "true" || val == "1" || val == "yes"
	}
	if scannedContainersEnabledEnv := os.Getenv("METRICS_SCANNED_CONTAINERS_ENABLED"); scannedContainersEnabledEnv != "" {
		val := strings.ToLower(scannedContainersEnabledEnv)
		cfg.MetricsScannedContainersEnabled = val == "true" || val == "1" || val == "yes"
	}
	if vulnerabilitiesEnabledEnv := os.Getenv("METRICS_VULNERABILITIES_ENABLED"); vulnerabilitiesEnabledEnv != "" {
		val := strings.ToLower(vulnerabilitiesEnabledEnv)
		cfg.MetricsVulnerabilitiesEnabled = val == "true" || val == "1" || val == "yes"
	}
	if vulnerabilityExploitedEnabledEnv := os.Getenv("METRICS_VULNERABILITY_EXPLOITED_ENABLED"); vulnerabilityExploitedEnabledEnv != "" {
		val := strings.ToLower(vulnerabilityExploitedEnabledEnv)
		cfg.MetricsVulnerabilityExploitedEnabled = val == "true" || val == "1" || val == "yes"
	}
	if vulnerabilityRiskEnabledEnv := os.Getenv("METRICS_VULNERABILITY_RISK_ENABLED"); vulnerabilityRiskEnabledEnv != "" {
		val := strings.ToLower(vulnerabilityRiskEnabledEnv)
		cfg.MetricsVulnerabilityRiskEnabled = val == "true" || val == "1" || val == "yes"
	}
	if imageScanStatusEnabledEnv := os.Getenv("METRICS_IMAGE_SCAN_STATUS_ENABLED"); imageScanStatusEnabledEnv != "" {
		val := strings.ToLower(imageScanStatusEnabledEnv)
		cfg.MetricsImageScanStatusEnabled = val == "true" || val == "1" || val == "yes"
	}

	// Metrics staleness window
	if stalenessWindowEnv := os.Getenv("METRICS_STALENESS_WINDOW"); stalenessWindowEnv != "" {
		if duration, err := time.ParseDuration(stalenessWindowEnv); err == nil {
			cfg.MetricsStalenessWindow = duration
		}
	}

	// Host scanning configuration
	if hostScanningEnabledEnv := os.Getenv("HOST_SCANNING_ENABLED"); hostScanningEnabledEnv != "" {
		val := strings.ToLower(hostScanningEnabledEnv)
		cfg.HostScanningEnabled = val == "true" || val == "1" || val == "yes"
	}
	if hostScanningIntervalEnv := os.Getenv("HOST_SCANNING_INTERVAL"); hostScanningIntervalEnv != "" {
		if duration, err := time.ParseDuration(hostScanningIntervalEnv); err == nil {
			cfg.HostScanningInterval = duration
		}
	}
	if extraExclusionsEnv := os.Getenv("HOST_SCANNING_EXTRA_EXCLUSIONS"); extraExclusionsEnv != "" {
		cfg.HostScanningExtraExclusions = parseCommaSeparated(extraExclusionsEnv)
	}
	if autoDetectNFSEnv := os.Getenv("HOST_SCANNING_AUTO_DETECT_NFS"); autoDetectNFSEnv != "" {
		val := strings.ToLower(autoDetectNFSEnv)
		cfg.HostScanningAutoDetectNFS = val == "true" || val == "1" || val == "yes"
	}
	if extraNetworkFSTypesEnv := os.Getenv("HOST_SCANNING_EXTRA_NETWORK_FS_TYPES"); extraNetworkFSTypesEnv != "" {
		cfg.HostScanningExtraNetworkFSTypes = parseCommaSeparated(extraNetworkFSTypesEnv)
	}

	// Node metrics toggles
	if nodeScannedEnabledEnv := os.Getenv("METRICS_NODE_SCANNED_ENABLED"); nodeScannedEnabledEnv != "" {
		val := strings.ToLower(nodeScannedEnabledEnv)
		cfg.MetricsNodeScannedEnabled = val == "true" || val == "1" || val == "yes"
	}
	if nodeScanStatusEnabledEnv := os.Getenv("METRICS_NODE_SCAN_STATUS_ENABLED"); nodeScanStatusEnabledEnv != "" {
		val := strings.ToLower(nodeScanStatusEnabledEnv)
		cfg.MetricsNodeScanStatusEnabled = val == "true" || val == "1" || val == "yes"
	}
	if nodeVulnerabilitiesEnabledEnv := os.Getenv("METRICS_NODE_VULNERABILITIES_ENABLED"); nodeVulnerabilitiesEnabledEnv != "" {
		val := strings.ToLower(nodeVulnerabilitiesEnabledEnv)
		cfg.MetricsNodeVulnerabilitiesEnabled = val == "true" || val == "1" || val == "yes"
	}
	if nodeVulnerabilityRiskEnabledEnv := os.Getenv("METRICS_NODE_VULNERABILITY_RISK_ENABLED"); nodeVulnerabilityRiskEnabledEnv != "" {
		val := strings.ToLower(nodeVulnerabilityRiskEnabledEnv)
		cfg.MetricsNodeVulnerabilityRiskEnabled = val == "true" || val == "1" || val == "yes"
	}
	if nodeVulnerabilityExploitedEnabledEnv := os.Getenv("METRICS_NODE_VULNERABILITY_EXPLOITED_ENABLED"); nodeVulnerabilityExploitedEnabledEnv != "" {
		val := strings.ToLower(nodeVulnerabilityExploitedEnabledEnv)
		cfg.MetricsNodeVulnerabilityExploitedEnabled = val == "true" || val == "1" || val == "yes"
	}

	return cfg, nil
}

// parseCommaSeparated splits a comma-separated string into a slice of trimmed strings.
// Empty strings are filtered out.
func parseCommaSeparated(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// LoadConfigWithDefaults tries to load configuration from default locations.
// It checks locations in order:
// 1. /etc/bjorn2scan/agent.conf
// 2. ./agent.conf (current directory)
// 3. Hardcoded defaults
//
// Environment variables override file values.
func LoadConfigWithDefaults() (*Config, error) {
	// Check default locations in order
	defaultPaths := []string{
		"/etc/bjorn2scan/agent.conf",
		"./agent.conf",
	}

	for _, path := range defaultPaths {
		if _, err := os.Stat(path); err == nil {
			// File exists, try to load it
			cfg, err := LoadConfig(path)
			if err != nil {
				// File exists but failed to parse - return error
				return nil, err
			}
			return cfg, nil
		}
	}

	// No config file found, use defaults with env var overrides
	return LoadConfig("")
}
