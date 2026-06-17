package handlers

import (
	"fmt"
	"net/http"

)


// LastUpdatedProvider interface for getting the most recent update timestamp
type LastUpdatedProvider interface {
	GetLastUpdatedTimestamp(dataType string) (string, error)
}

// LastUpdatedHandler returns the most recent update timestamp from the database
// Supports optional ?datatype=image query parameter for compatibility
//
// Response format: Plain text timestamp (RFC3339 format)
// Example: 2025-12-24T17:30:45Z
func LastUpdatedHandler(provider LastUpdatedProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get datatype parameter (optional, for compatibility with oldui)
		dataType := r.URL.Query().Get("datatype")
		if dataType == "" {
			dataType = "all"
		}

		timestamp, err := provider.GetLastUpdatedTimestamp(dataType)
		if err != nil {
			log.Error("error getting last updated timestamp", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		if _, err := fmt.Fprint(w, timestamp); err != nil {
			log.Error("error writing response", "error", err)
		}
	}
}
