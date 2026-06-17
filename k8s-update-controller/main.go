package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/bvboe/b2s-go/k8s-update-controller/config"
	"github.com/bvboe/b2s-go/k8s-update-controller/controller"
)

var version = "dev" // Set via ldflags at build time

// initLogging initializes structured logging for k8s-update-controller
// This is a standalone implementation since k8s-update-controller doesn't import scanner-core
func initLogging() {
	level := slog.LevelInfo
	jsonFormat := false

	// Check environment variable overrides
	if envLevel := os.Getenv("LOG_LEVEL"); envLevel != "" {
		switch strings.ToLower(envLevel) {
		case "debug":
			level = slog.LevelDebug
		case "warn", "warning":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		}
	}
	if envFormat := os.Getenv("LOG_FORMAT"); envFormat != "" {
		jsonFormat = strings.ToLower(envFormat) == "json"
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if jsonFormat {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
}

func main() {
	// Initialize structured logging from environment variables
	initLogging()

	log := slog.Default().With("component", "k8s-update-controller")
	ctx := context.Background()

	log.Info("Bjorn2Scan Update Controller", "version", version)
	log.Info("starting update check")

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Error("error loading configuration", "error", err)
		os.Exit(1)
	}

	if !cfg.Enabled {
		log.Info("auto-update is disabled in configuration")
		os.Exit(0)
	}

	log.Info("configuration loaded",
		"namespace", cfg.Helm.Namespace,
		"release", cfg.Helm.ReleaseName,
		"chart_registry", cfg.Helm.ChartRegistry,
		"auto_update_minor", cfg.VersionConstraints.AutoUpdateMinor,
		"auto_update_major", cfg.VersionConstraints.AutoUpdateMajor,
		"pinned_version", cfg.VersionConstraints.PinnedVersion)

	// Create controller
	ctrl, err := controller.New(cfg)
	if err != nil {
		log.Error("error creating controller", "error", err)
		os.Exit(1)
	}

	// Run update check (one-shot execution)
	startTime := time.Now()
	result, err := ctrl.CheckAndUpdate(ctx)
	duration := time.Since(startTime)

	if err != nil {
		log.Error("error during update check", "error", err)
		os.Exit(1)
	}

	// Print results
	log.Info("update check completed",
		"duration", duration.Round(time.Second),
		"current_version", result.CurrentVersion,
		"latest_version", result.LatestVersion)

	if result.UpdatePerformed {
		log.Info("update performed",
			"from_version", result.CurrentVersion,
			"to_version", result.UpdatedToVersion,
			"message", "next scheduled run will use the new version")
	} else if result.UpdateAvailable {
		log.Info("update available but not applied", "reason", result.Reason)
	} else {
		log.Info("system is up to date")
	}

	os.Exit(0)
}
