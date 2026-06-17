// Package logging provides structured logging for bjorn2scan components.
//
// Usage:
//
//	// Initialize once at startup
//	logging.Init(slog.LevelInfo, false)
//
//	// Get a logger for a component
//	log := logging.For(logging.ComponentQueue)
//	log.Info("processing job", "image", image, "node", nodeName)
//
//	// With additional context
//	log.With("digest", digest).Info("scan complete", "vulns", count)
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Component names for structured logging
const (
	ComponentScheduler        = "scheduler"
	ComponentGrype            = "grype"
	ComponentQueue            = "scan-queue"
	ComponentDatabase         = "database"
	ComponentNodes            = "nodes"
	ComponentContainers       = "containers"
	ComponentHTTP             = "http"
	ComponentPodScanner       = "pod-scanner"
	ComponentPodScannerClient = "pod-scanner-client"
	ComponentK8s              = "k8s"
	ComponentMetrics          = "metrics"
	ComponentJobs             = "jobs"
	ComponentVulnDB           = "vulndb"
)

var (
	defaultLogger *slog.Logger
	once          sync.Once
	mu            sync.RWMutex
)

// Init initializes the default logger with the specified level and format.
// Should be called once at application startup.
//
// Parameters:
//   - level: The minimum log level (slog.LevelDebug, slog.LevelInfo, etc.)
//   - jsonFormat: If true, output JSON format; if false, output text format
//
// Environment variable overrides:
//   - LOG_LEVEL: debug, info, warn, error (overrides level parameter)
//   - LOG_FORMAT: text, json (overrides jsonFormat parameter)
func Init(level slog.Level, jsonFormat bool) {
	once.Do(func() {
		// Check environment variable overrides
		if envLevel := os.Getenv("LOG_LEVEL"); envLevel != "" {
			level = parseLevel(envLevel)
		}
		if envFormat := os.Getenv("LOG_FORMAT"); envFormat != "" {
			jsonFormat = strings.ToLower(envFormat) == "json"
		}

		opts := &slog.HandlerOptions{
			Level: level,
		}

		var handler slog.Handler
		if jsonFormat {
			handler = slog.NewJSONHandler(os.Stderr, opts)
		} else {
			handler = slog.NewTextHandler(os.Stderr, opts)
		}

		mu.Lock()
		defaultLogger = slog.New(handler)
		mu.Unlock()

		// Also set as default slog logger for stdlib compatibility
		slog.SetDefault(defaultLogger)
	})
}

// InitWithWriter initializes the logger writing to w instead of os.Stderr.
// Use this to tee logs to multiple destinations (e.g. journald + file):
//
//	w := io.MultiWriter(os.Stderr, logFile)
//	logging.InitWithWriter(w, slog.LevelInfo, false)
func InitWithWriter(w io.Writer, level slog.Level, jsonFormat bool) {
	once.Do(func() {
		if envLevel := os.Getenv("LOG_LEVEL"); envLevel != "" {
			level = parseLevel(envLevel)
		}
		if envFormat := os.Getenv("LOG_FORMAT"); envFormat != "" {
			jsonFormat = strings.ToLower(envFormat) == "json"
		}

		opts := &slog.HandlerOptions{Level: level}

		var handler slog.Handler
		if jsonFormat {
			handler = slog.NewJSONHandler(w, opts)
		} else {
			handler = slog.NewTextHandler(w, opts)
		}

		mu.Lock()
		defaultLogger = slog.New(handler)
		mu.Unlock()

		slog.SetDefault(defaultLogger)
	})
}

// InitFromEnv initializes the logger using only environment variables.
// Defaults to INFO level with text format if not specified.
//
// Environment variables:
//   - LOG_LEVEL: debug, info, warn, error (default: info)
//   - LOG_FORMAT: text, json (default: text)
func InitFromEnv() {
	Init(slog.LevelInfo, false)
}

// For returns a logger with the specified component name.
// The component is added as a "component" attribute to all log entries.
//
// Example:
//
//	log := logging.For(logging.ComponentQueue)
//	log.Info("job enqueued", "image", img)
//	// Output: level=INFO msg="job enqueued" component=scan-queue image=nginx:latest
func For(component string) *slog.Logger {
	mu.RLock()
	logger := defaultLogger
	mu.RUnlock()

	if logger == nil {
		// Fallback if Init() hasn't been called
		Init(slog.LevelInfo, false)
		mu.RLock()
		logger = defaultLogger
		mu.RUnlock()
	}

	return logger.With("component", component)
}

// Default returns the default logger without any component context.
// Prefer using For() with a component name for better log filtering.
func Default() *slog.Logger {
	mu.RLock()
	logger := defaultLogger
	mu.RUnlock()

	if logger == nil {
		Init(slog.LevelInfo, false)
		mu.RLock()
		logger = defaultLogger
		mu.RUnlock()
	}

	return logger
}

// parseLevel converts a string level to slog.Level
func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// GetLevel returns the current log level as a string
func GetLevel() string {
	if envLevel := os.Getenv("LOG_LEVEL"); envLevel != "" {
		return strings.ToLower(envLevel)
	}
	return "info"
}

// GetFormat returns the current log format as a string
func GetFormat() string {
	if envFormat := os.Getenv("LOG_FORMAT"); envFormat != "" {
		return strings.ToLower(envFormat)
	}
	return "text"
}
