package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/bvboe/b2s-go/k8s-scan-server/k8s"
	"github.com/bvboe/b2s-go/k8s-scan-server/podscanner"
	scannerconfig "github.com/bvboe/b2s-go/scanner-core/config"
	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/debug"
	"github.com/bvboe/b2s-go/scanner-core/deployment"
	"github.com/bvboe/b2s-go/scanner-core/grype"
	corehandlers "github.com/bvboe/b2s-go/scanner-core/handlers"
	"github.com/bvboe/b2s-go/scanner-core/jobs"
	"github.com/bvboe/b2s-go/scanner-core/logging"
	"github.com/bvboe/b2s-go/scanner-core/metrics"
	"github.com/bvboe/b2s-go/scanner-core/nodes"
	"github.com/bvboe/b2s-go/scanner-core/scanning"
	"github.com/bvboe/b2s-go/scanner-core/scheduler"
	"github.com/bvboe/b2s-go/scanner-core/vulndb"
	// SQLite driver is registered by Grype's dependencies
	_ "github.com/KimMachineGun/automemlimit" // Automatically set GOMEMLIMIT based on cgroup limits

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// version is set at build time via ldflags
var version = "dev"

// formatConsoleURL creates a console URL, omitting port 80 for cleaner URLs
func formatConsoleURL(host, port string) string {
	if port == "80" {
		return fmt.Sprintf("http://%s/", host)
	}
	return fmt.Sprintf("http://%s:%s/", host, port)
}

type InfoResponse struct {
	Version   string `json:"version"`
	PodName   string `json:"pod_name"`
	Namespace string `json:"namespace"`
}

type K8sScanServerInfo struct {
	port         string
	webUIEnabled bool
	k8sClient    kubernetes.Interface
	serviceName  string
	servicePort  string
	// Cached values computed at startup and refreshed periodically
	deploymentIP     string
	cachedConsoleURL string
	consoleMu        sync.RWMutex // Protects cachedConsoleURL
	// Database readiness state for grype DB status
	dbReadinessState *corehandlers.DatabaseReadinessState
}

func NewK8sScanServerInfo(port string, webUIEnabled bool, customConsoleURL string, k8sClient kubernetes.Interface, serviceName, servicePort string) *K8sScanServerInfo {
	info := &K8sScanServerInfo{
		port:         port,
		webUIEnabled: webUIEnabled,
		k8sClient:    k8sClient,
		serviceName:  serviceName,
		servicePort:  servicePort,
	}

	// Cache deployment IP (node IP from downward API)
	info.deploymentIP = os.Getenv("NODE_IP")
	if info.deploymentIP == "" {
		logging.For(logging.ComponentK8s).Warn("NODE_IP environment variable not set")
	}

	// Cache console URL at startup
	if customConsoleURL != "" {
		info.cachedConsoleURL = customConsoleURL
	} else if webUIEnabled {
		info.cachedConsoleURL = info.detectConsoleURL()
	}

	if info.cachedConsoleURL != "" {
		logging.For(logging.ComponentK8s).Info("console URL set", "url", info.cachedConsoleURL)
	}

	return info
}

// StartPeriodicRefresh starts a background goroutine that periodically refreshes
// the console URL. This handles cases where the service configuration changes
// after startup (e.g., LoadBalancer IP becomes available).
// Only call this if auto-detecting the console URL (no custom URL override).
func (k *K8sScanServerInfo) StartPeriodicRefresh(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				newURL := k.detectConsoleURL()
				k.consoleMu.Lock()
				if newURL != k.cachedConsoleURL {
					logging.For(logging.ComponentK8s).Info("console URL updated", "url", newURL)
					k.cachedConsoleURL = newURL
				}
				k.consoleMu.Unlock()
			}
		}
	}()
}

func (k *K8sScanServerInfo) GetInfo() interface{} {
	return InfoResponse{
		Version:   version,
		PodName:   os.Getenv("HOSTNAME"),
		Namespace: os.Getenv("NAMESPACE"),
	}
}

func (k *K8sScanServerInfo) GetClusterName() string {
	// Try to get cluster name from environment variable first
	clusterName := os.Getenv("CLUSTER_NAME")
	if clusterName != "" {
		return clusterName
	}

	// Fall back to namespace if available
	namespace := os.Getenv("NAMESPACE")
	if namespace != "" {
		return namespace
	}

	// Final fallback
	return "kubernetes"
}

func (k *K8sScanServerInfo) GetDeploymentName() string {
	// For k8s, deployment name is the cluster name
	return k.GetClusterName()
}

func (k *K8sScanServerInfo) GetDeploymentType() string {
	return "kubernetes"
}

func (k *K8sScanServerInfo) GetVersion() string {
	return version
}

func (k *K8sScanServerInfo) GetScanContainers() bool {
	// Default to true, can be disabled via env var
	scanContainers := os.Getenv("SCAN_CONTAINERS")
	if scanContainers == "false" || scanContainers == "0" {
		return false
	}
	return true
}

func (k *K8sScanServerInfo) GetScanNodes() bool {
	// Default to false, can be enabled via env var
	scanNodes := os.Getenv("SCAN_NODES")
	if scanNodes == "true" || scanNodes == "1" {
		return true
	}
	return false
}

// GetDeploymentIP returns the cached deployment IP (node IP).
func (k *K8sScanServerInfo) GetDeploymentIP() string {
	return k.deploymentIP
}

// GetConsoleURL returns the cached console URL.
func (k *K8sScanServerInfo) GetConsoleURL() string {
	k.consoleMu.RLock()
	defer k.consoleMu.RUnlock()
	return k.cachedConsoleURL
}

// SetDBReadinessState sets the database readiness state for grype DB status reporting.
func (k *K8sScanServerInfo) SetDBReadinessState(state *corehandlers.DatabaseReadinessState) {
	k.dbReadinessState = state
}

// GetGrypeDBBuilt returns the grype vulnerability database build timestamp in RFC3339 format.
// Returns empty string if the database status is unavailable.
func (k *K8sScanServerInfo) GetGrypeDBBuilt() string {
	if k.dbReadinessState == nil {
		return ""
	}
	status := k.dbReadinessState.GetStatus()
	if status == nil || status.Built.IsZero() {
		return ""
	}
	return status.Built.Format(time.RFC3339)
}

// detectConsoleURL determines the console URL based on service configuration.
// Called once at startup and cached.
func (k *K8sScanServerInfo) detectConsoleURL() string {
	namespace := os.Getenv("NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}

	// Try to get service information from Kubernetes API
	if k.k8sClient != nil && k.serviceName != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		svc, err := k.k8sClient.CoreV1().Services(namespace).Get(ctx, k.serviceName, metav1.GetOptions{})
		if err != nil {
			logging.For(logging.ComponentK8s).Warn("failed to get service", "service", k.serviceName, "error", err)
		} else {
			// Determine URL based on service type
			switch svc.Spec.Type {
			case corev1.ServiceTypeLoadBalancer:
				// Use LoadBalancer IP if available
				if len(svc.Status.LoadBalancer.Ingress) > 0 {
					ingress := svc.Status.LoadBalancer.Ingress[0]
					if ingress.IP != "" {
						port := k.servicePort
						if port == "" && len(svc.Spec.Ports) > 0 {
							port = fmt.Sprintf("%d", svc.Spec.Ports[0].Port)
						}
						return formatConsoleURL(ingress.IP, port)
					}
					if ingress.Hostname != "" {
						port := k.servicePort
						if port == "" && len(svc.Spec.Ports) > 0 {
							port = fmt.Sprintf("%d", svc.Spec.Ports[0].Port)
						}
						return formatConsoleURL(ingress.Hostname, port)
					}
				}

			case corev1.ServiceTypeNodePort:
				// Use Node IP + NodePort (NodePort is never 80, so always include it)
				if k.deploymentIP != "" && len(svc.Spec.Ports) > 0 {
					nodePort := svc.Spec.Ports[0].NodePort
					return fmt.Sprintf("http://%s:%d/", k.deploymentIP, nodePort)
				}

			case corev1.ServiceTypeClusterIP:
				// Use internal cluster DNS name
				port := k.servicePort
				if port == "" && len(svc.Spec.Ports) > 0 {
					port = fmt.Sprintf("%d", svc.Spec.Ports[0].Port)
				}
				return formatConsoleURL(fmt.Sprintf("%s.%s.svc.cluster.local", k.serviceName, namespace), port)
			}
		}
	}

	// Fallback: construct internal cluster DNS name
	if k.serviceName != "" {
		port := k.servicePort
		if port == "" {
			port = "80"
		}
		return formatConsoleURL(fmt.Sprintf("%s.%s.svc.cluster.local", k.serviceName, namespace), port)
	}

	return ""
}

func main() {
	// Initialize structured logging from environment variables
	// LOG_LEVEL: debug, info, warn, error (default: info)
	// LOG_FORMAT: text, json (default: text)
	logging.InitFromEnv()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	logging.For(logging.ComponentK8s).Info("k8s-scan-server starting", "version", version)

	// Create Kubernetes client
	config, err := rest.InClusterConfig()
	if err != nil {
		logging.For(logging.ComponentK8s).Error("error creating Kubernetes config", "error", err)
		os.Exit(1)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		logging.For(logging.ComponentK8s).Error("error creating Kubernetes client", "error", err)
		os.Exit(1)
	}

	// Create container manager
	manager := containers.NewManager()

	// Initialize database
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "/var/lib/bjorn2scan/data/containers.db"
	}

	// Initialize debug configuration
	debugEnabled := os.Getenv("DEBUG_ENABLED")
	debugConfig := debug.NewDebugConfig(debugEnabled == "true")
	if debugConfig.IsEnabled() {
		logging.For(logging.ComponentK8s).Info("debug mode enabled", "endpoints", "/debug")
	}

	// Initialize database (will auto-delete and recreate if corrupted)
	db, err := database.New(dbPath)
	if err != nil {
		logging.For(logging.ComponentK8s).Error("error initializing database", "error", err)
		os.Exit(1)
	}
	defer func() { _ = database.Close(db) }()

	// Reset any nodes/images left in transient states from a previous crash or OOM kill.
	// Must run before watchers and the scan queue are started.
	if err := db.ResetInterruptedScans(); err != nil {
		logging.For(logging.ComponentK8s).Error("failed to reset interrupted scans", "error", err)
		os.Exit(1)
	}

	// Initialize deployment UUID
	dbDir := filepath.Dir(dbPath)
	deploymentUUID, err := deployment.NewUUID(dbDir)
	if err != nil {
		logging.For(logging.ComponentK8s).Error("failed to initialize deployment UUID", "error", err)
		os.Exit(1)
	}
	logging.For(logging.ComponentK8s).Info("deployment UUID initialized", "uuid", deploymentUUID)

	// Load configuration with environment variable overrides from Helm values
	cfg, err := scannerconfig.LoadConfig("")
	if err != nil {
		logging.For(logging.ComponentK8s).Error("error loading configuration", "error", err)
		os.Exit(1)
	}

	// Connect database to manager
	manager.SetDatabase(db)

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start pod watcher - performs initial sync via informer cache then watches for changes
	go k8s.WatchPods(ctx, clientset, manager)

	// Create pod-scanner client for SBOM routing
	podScannerClient := podscanner.NewClient()

	// Initialize node manager for host scanning (if enabled)
	var nodeManager *nodes.Manager
	if cfg.HostScanningEnabled {
		logging.For(logging.ComponentK8s).Info("host scanning enabled", "initializing", "node manager")
		nodeManager = nodes.NewManager()
		nodeManager.SetDatabase(db)

		// Start node watcher - performs initial sync via informer cache then watches for changes
		go k8s.WatchNodes(ctx, clientset, nodeManager)
	}

	// Create SBOM retriever function that uses pod-scanner
	sbomRetriever := func(ctx context.Context, image containers.ImageID, nodeName string, runtime string) ([]byte, error) {
		return podScannerClient.GetSBOMFromNode(ctx, clientset, nodeName, image.Digest)
	}

	// Configure Grype database location
	// GRYPE_DB_PATH allows storing the grype database separately from the main data
	// This is important for NFS deployments where grype's in-place database updates
	// can fail due to NFS "silly rename" behavior when files are replaced while open
	grypeDBPath := os.Getenv("GRYPE_DB_PATH")
	if grypeDBPath == "" {
		// Default: use the same directory as the main database
		grypeDBPath = filepath.Dir(dbPath)
	}
	grypeCfg := grype.Config{
		DBRootDir: grypeDBPath,
	}
	logging.For(logging.ComponentK8s).Info("grype database configured", "path", grypeDBPath+"/grype/")

	// Initialize database readiness state
	dbReadinessState := corehandlers.NewDatabaseReadinessState(grypeCfg)

	// Create scan queue for automatic SBOM generation and vulnerability scanning
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

	// Configure host SBOM retriever and connect node manager (if enabled)
	if nodeManager != nil {
		// Create host SBOM retriever that calls pod-scanner on the target node
		hostSBOMRetriever := func(ctx context.Context, nodeName string) ([]byte, error) {
			return podScannerClient.GetHostSBOMFromNode(ctx, clientset, nodeName)
		}
		scanQueue.SetHostSBOMRetriever(hostSBOMRetriever)
		nodeManager.SetScanQueue(scanQueue)
		logging.For(logging.ComponentK8s).Info("host scanning configured and ready")
	}

	// Initialize scheduler for periodic jobs
	var sched *scheduler.Scheduler
	if cfg.JobsEnabled {
		logging.For(logging.ComponentK8s).Info("initializing scheduled jobs")
		sched = scheduler.New()

		// Add rescan database job - uses grype's native update mechanism
		if cfg.JobsRescanDatabaseEnabled {
			// Pass the database as TimestampStore for persistent tracking of grype DB changes
			dbUpdater, err := vulndb.NewDatabaseUpdaterWithConfig(grypeCfg.DBRootDir, vulndb.DatabaseUpdaterConfig{
				TimestampStore: db,
			})
			if err != nil {
				logging.For(logging.ComponentK8s).Warn("failed to create database updater", "error", err)
			} else {
				rescanJob := jobs.NewRescanDatabaseJob(dbUpdater, db, scanQueue)
				// Connect readiness state so db-updater can mark pod ready after successful DB update
				// This fixes the case where initial download fails but db-updater succeeds later
				rescanJob.SetReadinessSetter(dbReadinessState)
				// Connect node scanning if enabled - nodes will also be rescanned when grype DB updates
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
					logging.For(logging.ComponentK8s).Error("failed to add rescan database job", "error", err)
					os.Exit(1)
				}
				logging.For(logging.ComponentK8s).Info("scheduled rescan-database job", "interval", cfg.JobsRescanDatabaseInterval, "timeout", cfg.JobsRescanDatabaseTimeout)
			}
		}

		// Add cleanup orphaned images job
		if cfg.JobsCleanupEnabled {
			cleanupJob := jobs.NewCleanupOrphanedImagesJob(db)
			cleanupJob.SetContainerLister(manager)
			if err := sched.AddJob(
				cleanupJob,
				scheduler.NewIntervalSchedule(cfg.JobsCleanupInterval),
				scheduler.JobConfig{
					Enabled: true,
					Timeout: cfg.JobsCleanupTimeout,
				},
			); err != nil {
				logging.For(logging.ComponentK8s).Error("failed to add cleanup job", "error", err)
				os.Exit(1)
			}
			logging.For(logging.ComponentK8s).Info("scheduled cleanup-orphaned-images job", "interval", cfg.JobsCleanupInterval, "timeout", cfg.JobsCleanupTimeout)
		}

		// Start scheduler
		if err := sched.Start(ctx); err != nil {
			logging.For(logging.ComponentK8s).Error("failed to start scheduler", "error", err)
			os.Exit(1)
		}
		logging.For(logging.ComponentK8s).Info("scheduler started")
	}

	// Setup HTTP server
	// Get console URL configuration from environment (can be overridden via Helm)
	consoleURL := os.Getenv("CONSOLE_URL")
	serviceName := os.Getenv("SERVICE_NAME")
	servicePort := os.Getenv("SERVICE_PORT")
	if servicePort == "" {
		servicePort = "80" // Default service port
	}

	infoProvider := NewK8sScanServerInfo(port, cfg.WebUIEnabled, consoleURL, clientset, serviceName, servicePort)

	// Connect database readiness state for grype DB status reporting in metrics
	infoProvider.SetDBReadinessState(dbReadinessState)

	// Start periodic refresh for console URL detection (only if auto-detecting)
	// This handles LoadBalancer IPs that aren't available immediately at startup
	if consoleURL == "" && cfg.WebUIEnabled {
		infoProvider.StartPeriodicRefresh(ctx, 5*time.Minute)
	}

	// Start WAL monitor: logs a warning if unmerged WAL frames exceed ~2GB.
	// Runs in background every 5 minutes so slow NFS I/O does not affect /health.
	database.StartWALMonitor(ctx, db)

	// Warm the node vulnerability metrics cache so /metrics scrapes don't hit NFS.
	db.StartNodeVulnCacheRefresh(ctx)
	// Same for the container × image_vulnerability join.
	db.StartContainerVulnCacheRefresh(ctx)

	mux := http.NewServeMux()

	// Register standard handlers
	corehandlers.RegisterHandlers(mux, infoProvider, db)

	// Register database readiness handlers (/ready, /api/db/status, /api/debug/db/reinit)
	corehandlers.RegisterDatabaseReadinessHandlers(mux, dbReadinessState)

	// Register database handlers (use all default handlers)
	corehandlers.RegisterDatabaseHandlers(mux, db, nil)

	// Register static file handlers (web UI) only if enabled
	if cfg.WebUIEnabled {
		corehandlers.RegisterStaticHandlers(mux)
	}

	// Register debug handlers if debug mode is enabled
	corehandlers.RegisterDebugHandlers(mux, db, debugConfig, scanQueue)

	// Register jobs debug handlers for listing, triggering, and viewing execution history
	corehandlers.RegisterJobsHandlersWithDB(mux, sched, db)

	// Register node API handlers (if host scanning is enabled)
	if cfg.HostScanningEnabled {
		corehandlers.RegisterNodeHandlers(mux, db)
		logging.For(logging.ComponentK8s).Info("node API endpoints registered", "endpoints", "/api/nodes, /api/nodes/{name}, /api/summary/by-node")
	}

	// Create unified config for metrics (image + node + staleness)
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

	// Create staleness store (DB-backed, shared between /metrics and OTEL)
	staleness := metrics.NewStalenessStore(db, cfg.MetricsStalenessWindow)
	logging.For(logging.ComponentK8s).Info("metric staleness tracking enabled", "window", cfg.MetricsStalenessWindow)

	// Register Prometheus metrics endpoint
	metrics.RegisterMetricsHandler(mux, infoProvider, deploymentUUID.String(), db, unifiedConfig, staleness)

	// Initialize OpenTelemetry metrics exporter if enabled
	var otelExporter *metrics.OTELExporter
	if cfg.OTELMetricsEnabled {
		logging.For(logging.ComponentK8s).Info("initializing OpenTelemetry metrics exporter",
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
			logging.For(logging.ComponentK8s).Warn("failed to initialize OTEL exporter (continuing without OTEL)", "error", err)
		} else {
			otelExporter.Start()
			logging.For(logging.ComponentK8s).Info("OpenTelemetry metrics exporter started")
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
		logging.For(logging.ComponentK8s).Info("k8s-scan-server listening", "port", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.For(logging.ComponentK8s).Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	logging.For(logging.ComponentK8s).Info("shutdown signal received, shutting down gracefully")

	// Cancel context to stop pod watcher
	cancel()

	// Shutdown OTEL exporter if running
	if otelExporter != nil {
		logging.For(logging.ComponentK8s).Info("shutting down OpenTelemetry exporter")
		if err := otelExporter.Shutdown(); err != nil {
			logging.For(logging.ComponentK8s).Error("error shutting down OTEL exporter", "error", err)
		}
	}

	// Shutdown HTTP server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logging.For(logging.ComponentK8s).Error("error during shutdown", "error", err)
	}

	logging.For(logging.ComponentK8s).Info("k8s-scan-server stopped")
}
