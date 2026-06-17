package handlers

import (
	"encoding/json"
	"net/http"

)


// ConfigProvider is an interface for components to provide scanner configuration
type ConfigProvider interface {
	GetClusterName() string
	GetVersion() string
	GetScanContainers() bool
	GetScanNodes() bool
}

// ConfigResponse represents the scanner configuration returned by /api/config
type ConfigResponse struct {
	ClusterName    string `json:"clusterName"`
	Version        string `json:"version"`
	ScanContainers bool   `json:"scanContainers"`
	ScanNodes      bool   `json:"scanNodes"`
}

// ConfigHandler creates an HTTP handler for the /api/config endpoint
// It returns scanner configuration including cluster name, version, and scan settings
func ConfigHandler(provider ConfigProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		config := ConfigResponse{
			ClusterName:    provider.GetClusterName(),
			Version:        provider.GetVersion(),
			ScanContainers: provider.GetScanContainers(),
			ScanNodes:      provider.GetScanNodes(),
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(config); err != nil {
			log.Error("error encoding config response", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}
