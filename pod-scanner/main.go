package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bvboe/b2s-go/pod-scanner/handlers"
	"github.com/bvboe/b2s-go/pod-scanner/runtime"
)

// version is set at build time via ldflags
var version = "dev"

// parseCommaSeparated splits a comma-separated string into a slice of trimmed strings.
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

type InfoResponse struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	NodeName  string `json:"node_name"`
	PodName   string `json:"pod_name"`
	Namespace string `json:"namespace"`
}

// healthHandler returns a simple OK response for health checks
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprintln(w, "OK"); err != nil {
		slog.Default().With("component", "pod-scanner").Error("error writing health response", "error", err)
	}
}

// infoHandler returns component information as JSON
func infoHandler(w http.ResponseWriter, r *http.Request) {
	info := InfoResponse{
		Component: "pod-scanner",
		Version:   version,
		NodeName:  os.Getenv("NODE_NAME"),
		PodName:   os.Getenv("HOSTNAME"),
		Namespace: os.Getenv("NAMESPACE"),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(info); err != nil {
		slog.Default().With("component", "pod-scanner").Error("error encoding info response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// initLogging initializes structured logging for pod-scanner
// This is a standalone implementation since pod-scanner doesn't import scanner-core
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

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Initialize runtime manager for SBOM generation
	runtimeMgr, err := runtime.NewManager()
	if err != nil {
		slog.Default().With("component", "pod-scanner").Error("failed to initialize container runtime", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := runtimeMgr.Close(); err != nil {
			slog.Default().With("component", "pod-scanner").Warn("failed to close runtime manager", "error", err)
		}
	}()

	slog.Default().With("component", "pod-scanner").Info("using container runtime", "runtime", runtimeMgr.ActiveRuntime())

	// Register HTTP endpoints
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/info", infoHandler)
	http.HandleFunc("/sbom/", handlers.SBOMHandler(runtimeMgr))

	// Register host SBOM endpoint for host-level scanning
	// This scans the host filesystem (mounted at /host) for packages
	hostSBOMCfg := handlers.DefaultHostSBOMConfig()

	// Apply configuration from environment variables
	if extraExclusions := os.Getenv("HOST_SCANNING_EXTRA_EXCLUSIONS"); extraExclusions != "" {
		hostSBOMCfg.ExtraExclusions = parseCommaSeparated(extraExclusions)
		slog.Default().With("component", "pod-scanner").Info("host scanning extra exclusions configured", "exclusions", hostSBOMCfg.ExtraExclusions)
	}
	if autoDetectNFS := os.Getenv("HOST_SCANNING_AUTO_DETECT_NFS"); autoDetectNFS != "" {
		val := strings.ToLower(autoDetectNFS)
		hostSBOMCfg.AutoDetectNFS = val == "true" || val == "1" || val == "yes"
	}
	if extraNetworkFSTypes := os.Getenv("HOST_SCANNING_EXTRA_NETWORK_FS_TYPES"); extraNetworkFSTypes != "" {
		hostSBOMCfg.ExtraNetworkFSTypes = parseCommaSeparated(extraNetworkFSTypes)
		slog.Default().With("component", "pod-scanner").Info("host scanning extra network FS types configured", "types", hostSBOMCfg.ExtraNetworkFSTypes)
	}

	http.HandleFunc("/host-sbom", handlers.HostSBOMHandler(hostSBOMCfg))

	server := &http.Server{
		Addr: ":" + port,
	}

	slog.Default().With("component", "pod-scanner").Info("pod-scanner starting", "version", version, "port", port, "node", os.Getenv("NODE_NAME"))
	slog.Default().With("component", "pod-scanner").Info("endpoints registered", "endpoints", "/health, /info, /sbom/{digest}, /host-sbom")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Default().With("component", "pod-scanner").Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	<-sigChan
	slog.Default().With("component", "pod-scanner").Info("shutdown signal received, shutting down gracefully")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Default().With("component", "pod-scanner").Error("error during shutdown", "error", err)
	}

	slog.Default().With("component", "pod-scanner").Info("pod-scanner stopped")
}
