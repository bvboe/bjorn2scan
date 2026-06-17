// Package config provides configuration loading for bjorn2scan components.
// It supports loading from properties/INI files with environment variable overrides.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/ini.v1"
)

// Config holds all configuration options for bjorn2scan components.
type Config struct {
	Port         string
	DBPath       string
	DebugEnabled bool

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
}

// defaultConfig returns a Config with hardcoded defaults.
func defaultConfig() *Config {
	return &Config{
		Port:         "9999",
		DBPath:       "/var/lib/bjorn2scan/containers.db",
		DebugEnabled: false,

		// Jobs enabled by default
		JobsEnabled: true,

		// Rescan database job - check every 30 minutes
		JobsRescanDatabaseEnabled:  true,
		JobsRescanDatabaseInterval: 30 * time.Minute,
		JobsRescanDatabaseTimeout:  30 * time.Minute,

		// Refresh images job - check every 6 hours
		JobsRefreshImagesEnabled:  true,
		JobsRefreshImagesInterval: 6 * time.Hour,
		JobsRefreshImagesTimeout:  10 * time.Minute,

		// Cleanup job - run daily
		JobsCleanupEnabled:  true,
		JobsCleanupInterval: 24 * time.Hour,
		JobsCleanupTimeout:  1 * time.Hour,
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

			// Load jobs enabled
			if section.HasKey("jobs_enabled") {
				jobsStr := strings.ToLower(section.Key("jobs_enabled").String())
				cfg.JobsEnabled = jobsStr == "true" || jobsStr == "1" || jobsStr == "yes"
			}

			// Load rescan database job configuration
			if section.HasKey("jobs_rescan_database_enabled") {
				enabledStr := strings.ToLower(section.Key("jobs_rescan_database_enabled").String())
				cfg.JobsRescanDatabaseEnabled = enabledStr == "true" || enabledStr == "1" || enabledStr == "yes"
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

			// Load refresh images job configuration
			if section.HasKey("jobs_refresh_images_enabled") {
				enabledStr := strings.ToLower(section.Key("jobs_refresh_images_enabled").String())
				cfg.JobsRefreshImagesEnabled = enabledStr == "true" || enabledStr == "1" || enabledStr == "yes"
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

			// Load cleanup job configuration
			if section.HasKey("jobs_cleanup_enabled") {
				enabledStr := strings.ToLower(section.Key("jobs_cleanup_enabled").String())
				cfg.JobsCleanupEnabled = enabledStr == "true" || enabledStr == "1" || enabledStr == "yes"
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

	// Jobs enabled
	if jobsEnv := os.Getenv("JOBS_ENABLED"); jobsEnv != "" {
		jobsStr := strings.ToLower(jobsEnv)
		cfg.JobsEnabled = jobsStr == "true" || jobsStr == "1" || jobsStr == "yes"
	}

	// Rescan database job
	if enabledEnv := os.Getenv("JOBS_RESCAN_DATABASE_ENABLED"); enabledEnv != "" {
		enabledStr := strings.ToLower(enabledEnv)
		cfg.JobsRescanDatabaseEnabled = enabledStr == "true" || enabledStr == "1" || enabledStr == "yes"
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
		enabledStr := strings.ToLower(enabledEnv)
		cfg.JobsRefreshImagesEnabled = enabledStr == "true" || enabledStr == "1" || enabledStr == "yes"
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
		enabledStr := strings.ToLower(enabledEnv)
		cfg.JobsCleanupEnabled = enabledStr == "true" || enabledStr == "1" || enabledStr == "yes"
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

	return cfg, nil
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
