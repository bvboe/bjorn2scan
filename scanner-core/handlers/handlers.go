package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/logging"
)

var log = logging.For(logging.ComponentHTTP)

// InfoProvider is an interface for components to provide their specific information
type InfoProvider interface {
	GetInfo() interface{}
}

// AppInfoProvider is a combined interface that provides both info and config data
// This simplifies the API by requiring only one provider instance
type AppInfoProvider interface {
	InfoProvider
	ConfigProvider
}

// HealthHandler returns a simple OK response for health checks
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprintln(w, "OK"); err != nil {
		log.Error("error writing health response", "error", err)
	}
}

// HealthHandlerWithDB returns a health check handler that also verifies the
// database is responsive and not stuck (e.g. unbounded WAL growth from OOM kills).
// Returns 503 if the database health check fails, causing Kubernetes to restart the pod.
func HealthHandlerWithDB(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := database.HealthCheck(db); err != nil {
			log.Error("health check failed", "error", err)
			http.Error(w, "Service Unavailable: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := fmt.Fprintln(w, "OK"); err != nil {
			log.Error("error writing health response", "error", err)
		}
	}
}

// InfoHandler creates an HTTP handler for the /info endpoint
// It accepts an InfoProvider to get component-specific information
func InfoHandler(provider InfoProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		info := provider.GetInfo()

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(info); err != nil {
			log.Error("error encoding info response", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// RegisterHandlers registers the standard scanner endpoints (/health, /info, and /api/config) on the provided mux.
// If db is non-nil, /health performs a database liveness check and returns 503 if the DB is stuck.
func RegisterHandlers(mux *http.ServeMux, provider AppInfoProvider, db *database.DB) {
	if db != nil {
		mux.HandleFunc("/health", HealthHandlerWithDB(db))
	} else {
		mux.HandleFunc("/health", HealthHandler)
	}
	mux.HandleFunc("/info", InfoHandler(provider))
	mux.HandleFunc("/api/config", ConfigHandler(provider))
}

// RegisterDefaultHandlers registers the standard scanner endpoints (/health and /info) on the default mux
func RegisterDefaultHandlers(provider InfoProvider) {
	http.HandleFunc("/health", HealthHandler)
	http.HandleFunc("/info", InfoHandler(provider))
}
