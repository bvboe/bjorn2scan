package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"

	"github.com/bvboe/b2s-go/scanner-core/grype"
)


// DatabaseReadinessState tracks the current database readiness
type DatabaseReadinessState struct {
	mu       sync.RWMutex
	ready    bool
	status   *grype.DatabaseStatus
	grypeCfg grype.Config
	waitCh   chan struct{} // Closed when ready, allows waiting for readiness
}

// NewDatabaseReadinessState creates a new readiness state tracker
func NewDatabaseReadinessState(cfg grype.Config) *DatabaseReadinessState {
	return &DatabaseReadinessState{
		grypeCfg: cfg,
		ready:    false,
		waitCh:   make(chan struct{}),
	}
}

// SetReady marks the database as ready with the given status
func (d *DatabaseReadinessState) SetReady(status *grype.DatabaseStatus) {
	d.mu.Lock()
	defer d.mu.Unlock()
	wasReady := d.ready
	d.ready = status != nil && status.Available
	d.status = status

	// Signal waiters when becoming ready for the first time
	if d.ready && !wasReady && d.waitCh != nil {
		close(d.waitCh)
	}
}

// IsReady returns whether the database is ready
func (d *DatabaseReadinessState) IsReady() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.ready
}

// WaitForReady blocks until the database is ready or context is cancelled
// Returns true if ready, false if context was cancelled
func (d *DatabaseReadinessState) WaitForReady(ctx context.Context) bool {
	// Fast path: already ready
	d.mu.RLock()
	if d.ready {
		d.mu.RUnlock()
		return true
	}
	ch := d.waitCh
	d.mu.RUnlock()

	// Wait for ready signal or context cancellation
	select {
	case <-ch:
		return true
	case <-ctx.Done():
		return false
	}
}

// GetStatus returns the current database status
func (d *DatabaseReadinessState) GetStatus() *grype.DatabaseStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.status != nil {
		// Return a copy
		statusCopy := *d.status
		return &statusCopy
	}
	return nil
}

// ReadinessHandler returns a handler for readiness checks.
// Always returns 200 OK since the server can accept requests immediately.
// The scan queue handles waiting for the vulnerability database internally.
func ReadinessHandler(state *DatabaseReadinessState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	}
}

// DatabaseStatusHandler returns the current database status as JSON
func DatabaseStatusHandler(state *DatabaseReadinessState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := state.GetStatus()
		if status == nil {
			status = &grype.DatabaseStatus{
				Available: false,
				Error:     "database not initialized",
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(status); err != nil {
			log.Error("error encoding database status", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// DatabaseReinitHandler triggers a database re-initialization (for testing)
// POST /api/debug/db/reinit - deletes and re-downloads the database
func DatabaseReinitHandler(state *DatabaseReadinessState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		log.Info("database re-initialization requested")

		// Mark as not ready during re-init
		state.SetReady(&grype.DatabaseStatus{Available: false, Error: "re-initializing"})

		// Delete existing database
		if err := grype.DeleteDatabase(state.grypeCfg); err != nil {
			log.Error("failed to delete database", "error", err)
			state.SetReady(&grype.DatabaseStatus{Available: false, Error: err.Error()})
			http.Error(w, "Failed to delete database: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Re-initialize (download fresh)
		status, err := grype.InitializeDatabase(state.grypeCfg)
		if err != nil {
			log.Error("failed to re-initialize database", "error", err)
			state.SetReady(status)
			http.Error(w, "Failed to initialize database: "+err.Error(), http.StatusInternalServerError)
			return
		}

		state.SetReady(status)
		log.Info("database re-initialized successfully")

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(status); err != nil {
			log.Error("error encoding response", "error", err)
		}
	}
}

// RegisterDatabaseReadinessHandlers registers the database readiness endpoints
func RegisterDatabaseReadinessHandlers(mux *http.ServeMux, state *DatabaseReadinessState) {
	mux.HandleFunc("/ready", ReadinessHandler(state))
	mux.HandleFunc("/api/db/status", DatabaseStatusHandler(state))
	mux.HandleFunc("/api/debug/db/reinit", DatabaseReinitHandler(state))
}
