package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/bvboe/b2s-go/bjorn2scan-agent/docker"
	"github.com/bvboe/b2s-go/bjorn2scan-agent/syft"
	"github.com/bvboe/b2s-go/bjorn2scan-agent/updater"
	"github.com/bvboe/b2s-go/scanner-core/config"
	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/debug"
	"github.com/bvboe/b2s-go/scanner-core/deployment"
	"github.com/bvboe/b2s-go/scanner-core/grype"
	"github.com/bvboe/b2s-go/scanner-core/handlers"
	"github.com/bvboe/b2s-go/scanner-core/jobs"
	"github.com/bvboe/b2s-go/scanner-core/logging"
	"github.com/bvboe/b2s-go/scanner-core/metrics"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
	"github.com/bvboe/b2s-go/scanner-core/scanning"
	"github.com/bvboe/b2s-go/scanner-core/scheduler"
	"github.com/bvboe/b2s-go/scanner-core/vulndb"
)

// version is set at build time via ldflags
var version = "dev"

type InfoResponse struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Hostname  string `json:"hostname"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

type AgentInfo struct {
	port               string
	webUIEnabled       bool
	hostScanningEnabled bool
	// Cached values computed at startup
	deploymentIP string
	consoleURL   string
	// Grype database status getter (returns RFC3339 timestamp or empty string)
	grypeDBStatusGetter func() string
}

func NewAgentInfo(port string, webUIEnabled bool, hostScanningEnabled bool) *AgentInfo {
	info := &AgentInfo{
		port:               port,
		webUIEnabled:       webUIEnabled,
		hostScanningEnabled: hostScanningEnabled,
	}

	// Cache deployment IP at startup
	info.deploymentIP = info.detectOutboundIP()

	// Cache console URL at startup
	if webUIEnabled && info.deploymentIP != "" {
		if port == "80" {
			info.consoleURL = fmt.Sprintf("http://%s/", info.deploymentIP)
		} else {
			info.consoleURL = fmt.Sprintf("http://%s:%s/", info.deploymentIP, port)
		}
	}

	return info
}

func (a *AgentInfo) GetInfo() interface{} {
	hostname, _ := os.Hostname()

	return InfoResponse{
		Component: "bjorn2scan-agent",
		Version:   version,
		Hostname:  hostname,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

func (a *AgentInfo) GetClusterName() string {
	// For agent, use hostname as cluster name
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return "localhost"
	}
	return hostname
}

func (a *AgentInfo) GetDeploymentName() string {
	// For agent, deployment name is the hostname
	return a.GetClusterName()
}

func (a *AgentInfo) GetDeploymentType() string {
	return "agent"
}

func (a *AgentInfo) GetVersion() string {
	return version
}

func (a *AgentInfo) GetScanContainers() bool {
	// Agent scans containers via Docker
	return true
}

func (a *AgentInfo) GetScanNodes() bool {
	return a.hostScanningEnabled
}

// detectOutboundIP determines the primary outbound IP address.
// Called once at startup and cached.
func (a *AgentInfo) detectOutboundIP() string {
	// Get primary outbound IP address by dialing a well-known address
	// This determines which local IP would be used for outbound connections
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		logging.For(logging.ComponentHTTP).Warn("failed to determine primary outbound IP", "error", err)
		return ""
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			logging.For(logging.ComponentHTTP).Warn("failed to close connection", "error", closeErr)
		}
	}()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// GetDeploymentIP returns the cached deployment IP address.
func (a *AgentInfo) GetDeploymentIP() string {
	return a.deploymentIP
}

// GetConsoleURL returns the cached console URL.
func (a *AgentInfo) GetConsoleURL() string {
	return a.consoleURL
}

// SetGrypeDBStatusGetter sets a callback function to get the grype database build timestamp.
func (a *AgentInfo) SetGrypeDBStatusGetter(getter func() string) {
	a.grypeDBStatusGetter = getter
}

// GetGrypeDBBuilt returns the grype vulnerability database build timestamp in RFC3339 format.
// Returns empty string if the database status is unavailable.
func (a *AgentInfo) GetGrypeDBBuilt() string {
	if a.grypeDBStatusGetter == nil {
		return ""
	}
	return a.grypeDBStatusGetter()
}

// registerUpdaterHandlers registers HTTP handlers for the updater
func registerUpdaterHandlers(mux *http.ServeMux, u *updater.Updater) {
	// GET /api/update/status - Get current update status
	mux.HandleFunc("/api/update/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		status, errorMsg, lastCheck, lastUpdate, latestVersion, currentVersion := u.GetStatus()
		response := map[string]interface{}{
			"status":         status,
			"error":          errorMsg,
			"lastCheck":      lastCheck,
			"lastUpdate":     lastUpdate,
			"latestVersion":  latestVersion,
			"currentVersion": currentVersion,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	})

	// POST /api/update/trigger - Manually trigger an update check
	mux.HandleFunc("/api/update/trigger", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		u.TriggerCheck()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if err := json.NewEncoder(w).Encode(map[string]string{"message": "Update check triggered"}); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	})

	// POST /api/update/pause - Pause automatic updates
	mux.HandleFunc("/api/update/pause", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		u.Pause()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"message": "Auto-updates paused"}); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	})

	// POST /api/update/resume - Resume automatic updates
	mux.HandleFunc("/api/update/resume", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		u.Resume()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(map[string]string{"message": "Auto-updates resumed"}); err != nil {
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		}
	})
}

// setupLogging configures logging to write to both stderr (journald) and a log file.
// Returns the open log file so the caller can defer its Close().
func setupLogging() *os.File {
	logDir := "/var/log/bjorn2scan"
	logFile := filepath.Join(logDir, "agent.log")

	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// Can't open log file — fall back to stderr only
		logging.InitFromEnv()
		logging.For(logging.ComponentHTTP).Warn("could not open log file (logging to stderr only)", "path", logFile, "error", err)
		return nil
	}

	// Tee all structured logs to both stderr (journald) and the file
	w := io.MultiWriter(os.Stderr, file)
	logging.InitWithWriter(w, slog.LevelInfo, false)

	// Also redirect stdlib log to the same writer for any third-party log.Printf calls
	log.SetOutput(w)
	log.SetFlags(log.LstdFlags)

	return file
}

func main() {
	// Setup logging to both stderr (journald) and file; logging.Init is called inside
	if logFile := setupLogging(); logFile != nil {
		defer func() { _ = logFile.Close() }()
	}

	// Load configuration from file with environment variable overrides
	cfg, err := config.LoadConfigWithDefaults()
	if err != nil {
		logging.For(logging.ComponentHTTP).Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	port := cfg.Port
	dbPath := cfg.DBPath

	// Initialize debug configuration
	debugConfig := debug.NewDebugConfig(cfg.DebugEnabled)
	if debugConfig.IsEnabled() {
		logging.For(logging.ComponentHTTP).Info("debug mode ENABLED - /debug endpoints available")
	}

	logging.For(logging.ComponentHTTP).Info("bjorn2scan-agent starting", "version", version)
	logging.For(logging.ComponentHTTP).Info("configuration loaded", "port", port, "db_path", dbPath, "debug", cfg.DebugEnabled)

	// Initialize deployment UUID
	dbDir := filepath.Dir(dbPath)
	deploymentUUID, err := deployment.NewUUID(dbDir)
	if err != nil {
		logging.For(logging.ComponentHTTP).Error("failed to initialize deployment UUID", "error", err)
		os.Exit(1)
	}
	logging.For(logging.ComponentHTTP).Info("deployment UUID initialized", "uuid", deploymentUUID)

	// Create container manager
	manager := containers.NewManager()

	// Initialize database
	db, err := database.New(dbPath)
	if err != nil {
		logging.For(logging.ComponentDatabase).Error("failed to initialize database", "error", err)
		os.Exit(1)
	}
	defer func() { _ = database.Close(db) }()

	// Connect database to manager
	manager.SetDatabase(db)

	// Create SBOM retriever using syft library
	// For the agent, we scan local Docker images directly
	sbomRetriever := func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error) {
		// nodeName and runtime are ignored for local agent - we scan from local Docker daemon
		return syft.GenerateSBOM(ctx, image)
	}

	// Configure Grype to store vulnerability database in /var/lib/bjorn2scan/cache
	grypeCfg := grype.Config{
		DBRootDir: "/var/lib/bjorn2scan/cache",
	}

	// Initialize database readiness state for tracking Grype DB initialization
	dbReadinessState := handlers.NewDatabaseReadinessState(grypeCfg)

	// Create database updater for grype DB status and rescan job
	// Pass the database as TimestampStore for persistent tracking of grype DB changes
	dbUpdater, err := vulndb.NewDatabaseUpdaterWithConfig(grypeCfg.DBRootDir, vulndb.DatabaseUpdaterConfig{
		TimestampStore: db,
	})
	if err != nil {
		logging.For(logging.ComponentVulnDB).Warn("failed to create database updater", "error", err)
	}

	// Initialize grype database status at startup (for metrics)
	// This ensures grype_db_built is available in metrics immediately
	if dbUpdater != nil {
		if _, err := dbUpdater.GetCurrentStatus(context.Background()); err != nil {
			logging.For(logging.ComponentVulnDB).Warn("failed to get initial database status", "error", err)
		}
	}

	// Initialize scan queue with SBOM and vulnerability scanning
	// Using default queue config (unbounded queue with single worker)
	queueConfig := scanning.QueueConfig{
		MaxDepth:     0, // Unbounded
		FullBehavior: scanning.QueueFullDrop,
	}
	scanQueue := scanning.NewJobQueue(db, sbomRetriever, grypeCfg, queueConfig)
	defer scanQueue.Shutdown()

	// Connect scan queue to DB readiness state so it waits for grype DB before processing vuln scans
	scanQueue.SetDBReadinessChecker(dbReadinessState)

	// Connect scan queue to manager
	manager.SetScanQueue(scanQueue)

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start WAL monitor: logs a warning if unmerged WAL frames exceed ~2GB.
	// Agents are long-running processes that may accumulate WAL over weeks without
	// a restart (which would otherwise trigger the startup TRUNCATE checkpoint).
	database.StartWALMonitor(ctx, db)

	// Warm the node vulnerability metrics cache so /metrics scrapes don't hit disk.
	db.StartNodeVulnCacheRefresh(ctx)
	// Same for the container × image_vulnerability join.
	db.StartContainerVulnCacheRefresh(ctx)

	// Configure host scanning if enabled
	if cfg.HostScanningEnabled {
		logging.For(logging.ComponentNodes).Info("host scanning enabled, configuring host SBOM retriever")

		// Configure host scan exclusions
		hostScanCfg := syft.HostScanConfig{
			ExtraExclusions:     cfg.HostScanningExtraExclusions,
			AutoDetectNFS:       cfg.HostScanningAutoDetectNFS,
			ExtraNetworkFSTypes: cfg.HostScanningExtraNetworkFSTypes,
		}
		syft.SetHostScanConfig(hostScanCfg)
		if len(cfg.HostScanningExtraExclusions) > 0 {
			logging.For(logging.ComponentNodes).Info("host scanning extra exclusions configured", "exclusions", cfg.HostScanningExtraExclusions)
		}
		if len(cfg.HostScanningExtraNetworkFSTypes) > 0 {
			logging.For(logging.ComponentNodes).Info("host scanning extra network FS types configured", "fs_types", cfg.HostScanningExtraNetworkFSTypes)
		}

		// Create host SBOM retriever that uses syft to scan local filesystem
		hostSBOMRetriever := func(ctx context.Context, nodeName string) ([]byte, error) {
			return syft.GenerateHostSBOM(ctx)
		}
		scanQueue.SetHostSBOMRetriever(hostSBOMRetriever)

		// Get hostname for node name
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "localhost"
		}

		// Add this host as a node and trigger initial scan
		go func() {
			// Wait a moment for grype DB to initialize
			time.Sleep(5 * time.Second)

			// Create node entry if it doesn't exist
			nodeInfo := nodes.Node{
				Name:     hostname,
				Hostname: hostname,
			}

			// Try to get OS info
			if data, err := os.ReadFile("/etc/os-release"); err == nil {
				lines := string(data)
				for _, line := range strings.Split(lines, "\n") {
					if strings.HasPrefix(line, "PRETTY_NAME=") {
						nodeInfo.OSRelease = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
						break
					}
				}
			}

			// Get kernel version
			if data, err := os.ReadFile("/proc/version"); err == nil {
				parts := strings.Fields(string(data))
				if len(parts) >= 3 {
					nodeInfo.KernelVersion = parts[2]
				}
			}

			// Get architecture
			nodeInfo.Architecture = runtime.GOARCH

			// AddNode returns (isNew, error) - we don't care if it already exists
			if _, err := db.AddNode(nodeInfo); err != nil {
				logging.For(logging.ComponentNodes).Error("failed to create node entry", "error", err)
				return
			}

			logging.For(logging.ComponentNodes).Info("host node registered", "hostname", hostname, "os_release", nodeInfo.OSRelease, "arch", nodeInfo.Architecture)

			// Enqueue initial host scan
			scanQueue.EnqueueHostScan(hostname)
		}()
	}

	// Check if Docker is available and start watcher
	if docker.IsDockerAvailable() {
		logging.For(logging.ComponentContainers).Info("Docker detected, starting container watcher")
		go func() {
			if err := docker.WatchContainers(ctx, manager); err != nil {
				logging.For(logging.ComponentContainers).Error("Docker watcher error", "error", err)
			}
		}()
	} else {
		logging.For(logging.ComponentContainers).Info("Docker not available or not accessible, container watching disabled")
	}

	// Initialize auto-updater if enabled
	var agentUpdater *updater.Updater
	if cfg.AutoUpdateEnabled {
		logging.For(logging.ComponentHTTP).Info("initializing auto-updater")
		updaterConfig := &updater.Config{
			Enabled:                cfg.AutoUpdateEnabled,
			CheckInterval:          cfg.AutoUpdateCheckInterval,
			FeedURL:                cfg.UpdateFeedURL,
			AssetBaseURL:           cfg.UpdateAssetBaseURL,
			CurrentVersion:         version,
			VerifySignatures:       cfg.UpdateVerifySignatures,
			RollbackEnabled:        cfg.UpdateRollbackEnabled,
			HealthCheckTimeout:     cfg.UpdateHealthCheckTimeout,
			CosignIdentityRegexp:   cfg.UpdateCosignIdentityRegexp,
			CosignOIDCIssuer:       cfg.UpdateCosignOIDCIssuer,
			DownloadMaxRetries:     cfg.UpdateDownloadMaxRetries,
			DownloadValidateAssets: cfg.UpdateDownloadValidateAssets,
			VersionConstraints: &updater.VersionConstraints{
				AutoUpdateMinor: cfg.AutoUpdateMinorVersions,
				AutoUpdateMajor: cfg.AutoUpdateMajorVersions,
				PinnedVersion:   cfg.AutoUpdatePinnedVersion,
				MinVersion:      cfg.AutoUpdateMinVersion,
				MaxVersion:      cfg.AutoUpdateMaxVersion,
			},
		}

		var err error
		agentUpdater, err = updater.New(updaterConfig)
		if err != nil {
			logging.For(logging.ComponentHTTP).Warn("failed to initialize updater", "error", err)
		} else {
			// Check if there's a pending update from previous run
			// This must be done BEFORE starting the HTTP server and before starting the updater
			installer := updater.NewInstaller("", "", cfg.UpdateHealthCheckTimeout)
			if installer.ShouldCheckRollback() {
				logging.For(logging.ComponentHTTP).Info("pending update detected from previous run")
				// Perform health check in background after server starts
				// We can't do it now because the server isn't running yet
				go func() {
					// Wait for server to be ready
					time.Sleep(3 * time.Second)
					if err := installer.PerformPostUpdateHealthCheck(); err != nil {
						logging.For(logging.ComponentHTTP).Error("post-update verification failed", "error", err)
					}
				}()
			}

			// Start updater in background
			go agentUpdater.Start()
			logging.For(logging.ComponentHTTP).Info("auto-updater started")
		}
	}

	// Initialize scheduler for periodic jobs
	var sched *scheduler.Scheduler
	if cfg.JobsEnabled {
		logging.For(logging.ComponentJobs).Info("initializing scheduled jobs")
		sched = scheduler.New()

		// Add rescan database job - uses grype's native update mechanism
		if cfg.JobsRescanDatabaseEnabled && dbUpdater != nil {
			rescanJob := jobs.NewRescanDatabaseJob(dbUpdater, db, scanQueue)
			// Connect readiness state so db-updater can mark ready after a successful DB update
			// This fixes the case where initial download fails but db-updater succeeds later
			rescanJob.SetReadinessSetter(dbReadinessState)
			// Enable node rescanning on grype DB updates if host scanning is enabled
			if cfg.HostScanningEnabled {
				rescanJob.SetNodeScanning(db, scanQueue)
			}
			if err := sched.AddJob(
				rescanJob,
				scheduler.NewIntervalSchedule(cfg.JobsRescanDatabaseInterval),
				scheduler.JobConfig{
					Enabled:        true,
					Timeout:        cfg.JobsRescanDatabaseTimeout,
					RunImmediately: true,
				},
			); err != nil {
				logging.For(logging.ComponentJobs).Error("failed to add rescan database job", "error", err)
				os.Exit(1)
			}
			logging.For(logging.ComponentJobs).Info("scheduled rescan-database job", "interval", cfg.JobsRescanDatabaseInterval, "timeout", cfg.JobsRescanDatabaseTimeout)
		}

		// Add cleanup orphaned images job
		if cfg.JobsCleanupEnabled {
			cleanupJob := jobs.NewCleanupOrphanedImagesJob(db)
			if err := sched.AddJob(
				cleanupJob,
				scheduler.NewIntervalSchedule(cfg.JobsCleanupInterval),
				scheduler.JobConfig{
					Enabled: true,
					Timeout: cfg.JobsCleanupTimeout,
				},
			); err != nil {
				logging.For(logging.ComponentJobs).Error("failed to add cleanup job", "error", err)
				os.Exit(1)
			}
			logging.For(logging.ComponentJobs).Info("scheduled cleanup-orphaned-images job", "interval", cfg.JobsCleanupInterval, "timeout", cfg.JobsCleanupTimeout)
		}

		// Add refresh images job - periodic container reconciliation
		// This catches any Docker events that were missed (daemon restart, network issues, etc.)
		if cfg.JobsRefreshImagesEnabled && docker.IsDockerAvailable() {
			refreshTrigger := docker.NewRefreshTrigger(manager)
			refreshJob := jobs.NewRefreshImagesJob(refreshTrigger)
			if err := sched.AddJob(
				refreshJob,
				scheduler.NewIntervalSchedule(cfg.JobsRefreshImagesInterval),
				scheduler.JobConfig{
					Enabled: true,
					Timeout: cfg.JobsRefreshImagesTimeout,
				},
			); err != nil {
				logging.For(logging.ComponentJobs).Error("failed to add refresh images job", "error", err)
				os.Exit(1)
			}
			logging.For(logging.ComponentJobs).Info("scheduled refresh-images job", "interval", cfg.JobsRefreshImagesInterval, "timeout", cfg.JobsRefreshImagesTimeout)
		}

		// Start scheduler
		if err := sched.Start(ctx); err != nil {
			logging.For(logging.ComponentJobs).Error("failed to start scheduler", "error", err)
			os.Exit(1)
		}
		logging.For(logging.ComponentJobs).Info("scheduler started")
	}

	// Setup HTTP server
	infoProvider := NewAgentInfo(cfg.Port, cfg.WebUIEnabled, cfg.HostScanningEnabled)

	// Wire up grype database status getter for metrics
	// Uses GetCurrentVersion() which returns cached in-memory value (fast)
	if dbUpdater != nil {
		infoProvider.SetGrypeDBStatusGetter(func() string {
			version := dbUpdater.GetCurrentVersion()
			if version == nil || version.Built.IsZero() {
				return ""
			}
			return version.Built.Format(time.RFC3339)
		})
	}

	mux := http.NewServeMux()
	handlers.RegisterHandlers(mux, infoProvider, nil)
	handlers.RegisterDatabaseReadinessHandlers(mux, dbReadinessState)
	handlers.RegisterDatabaseHandlers(mux, db, nil) // Use all default handlers

	// Register static handlers only if web UI is enabled
	if cfg.WebUIEnabled {
		handlers.RegisterStaticHandlers(mux)
	}

	// Register node handlers if host scanning is enabled
	if cfg.HostScanningEnabled {
		handlers.RegisterNodeHandlers(mux, db)
		logging.For(logging.ComponentHTTP).Info("node API endpoints registered: /api/nodes, /api/nodes/{name}, /api/summary/by-node")
	}

	// Register updater API endpoints if updater is initialized
	if agentUpdater != nil {
		registerUpdaterHandlers(mux, agentUpdater)
	}

	// Register debug handlers if debug mode is enabled
	handlers.RegisterDebugHandlers(mux, db, debugConfig, scanQueue)

	// Register jobs debug handlers for listing, triggering, and viewing execution history
	handlers.RegisterJobsHandlersWithDB(mux, sched, db)

	// Create unified metrics config (shared between /metrics and OTEL)
	unifiedConfig := metrics.UnifiedConfig{
		DeploymentEnabled:                 cfg.MetricsDeploymentEnabled,
		ScannedContainersEnabled:          cfg.MetricsScannedContainersEnabled,
		VulnerabilitiesEnabled:            cfg.MetricsVulnerabilitiesEnabled,
		VulnerabilityExploitedEnabled:     cfg.MetricsVulnerabilityExploitedEnabled,
		VulnerabilityRiskEnabled:          cfg.MetricsVulnerabilityRiskEnabled,
		ImageScanStatusEnabled:            cfg.MetricsImageScanStatusEnabled,
		NodeScannedEnabled:                cfg.MetricsNodeScannedEnabled && cfg.HostScanningEnabled,
		NodeScanStatusEnabled:             cfg.MetricsNodeScanStatusEnabled && cfg.HostScanningEnabled,
		NodeVulnerabilitiesEnabled:        cfg.MetricsNodeVulnerabilitiesEnabled && cfg.HostScanningEnabled,
		NodeVulnerabilityRiskEnabled:      cfg.MetricsNodeVulnerabilityRiskEnabled && cfg.HostScanningEnabled,
		NodeVulnerabilityExploitedEnabled: cfg.MetricsNodeVulnerabilityExploitedEnabled && cfg.HostScanningEnabled,
		StalenessWindow:                   int64(cfg.MetricsStalenessWindow.Seconds()),
	}

	staleness := metrics.NewStalenessStore(db, cfg.MetricsStalenessWindow)
	logging.For(logging.ComponentMetrics).Info("metric staleness tracking enabled", "window", cfg.MetricsStalenessWindow)

	// Register Prometheus metrics endpoint
	metrics.RegisterMetricsHandler(mux, infoProvider, deploymentUUID.String(), db, unifiedConfig, staleness)

	// Initialize OpenTelemetry metrics exporter if enabled
	var otelExporter *metrics.OTELExporter
	if cfg.OTELMetricsEnabled {
		logging.For(logging.ComponentMetrics).Info("initializing OpenTelemetry metrics exporter",
			"endpoint", cfg.OTELMetricsEndpoint,
			"protocol", cfg.OTELMetricsProtocol,
			"interval", cfg.OTELMetricsPushInterval)

		otelConfig := metrics.OTELConfig{
			Endpoint:        cfg.OTELMetricsEndpoint,
			Protocol:        metrics.OTELProtocol(cfg.OTELMetricsProtocol),
			PushInterval:    cfg.OTELMetricsPushInterval,
			Insecure:        cfg.OTELMetricsInsecure,
			UseDirectExport: cfg.OTELUseDirectExport,
			DirectBatchSize: cfg.OTELDirectBatchSize,
		}

		var err error
		otelExporter, err = metrics.NewOTELExporter(ctx, infoProvider, deploymentUUID.String(), db, unifiedConfig, otelConfig, staleness)
		if err != nil {
			logging.For(logging.ComponentMetrics).Warn("failed to initialize OTEL exporter (continuing without OTEL)", "error", err)
		} else {
			otelExporter.Start()
			logging.For(logging.ComponentMetrics).Info("OpenTelemetry metrics exporter started")
		}
	}

	// Wrap with logging middleware if debug enabled
	var handler http.Handler = mux
	if debugConfig.IsEnabled() {
		handler = debug.LoggingMiddleware(debugConfig, mux)
	}

	server := &http.Server{
		Addr:    ":" + port,
		Handler: handler,
	}

	// Handle shutdown gracefully
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		logging.For(logging.ComponentHTTP).Info("bjorn2scan-agent listening", "port", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.For(logging.ComponentHTTP).Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	logging.For(logging.ComponentHTTP).Info("shutdown signal received, shutting down gracefully")

	// Cancel context to stop Docker watcher
	cancel()

	// Shutdown OTEL exporter if running
	if otelExporter != nil {
		logging.For(logging.ComponentMetrics).Info("shutting down OpenTelemetry exporter")
		if err := otelExporter.Shutdown(); err != nil {
			logging.For(logging.ComponentMetrics).Error("error shutting down OTEL exporter", "error", err)
		}
	}

	// Shutdown HTTP server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logging.For(logging.ComponentHTTP).Error("error during shutdown", "error", err)
	}

	logging.For(logging.ComponentHTTP).Info("bjorn2scan-agent stopped")
}
