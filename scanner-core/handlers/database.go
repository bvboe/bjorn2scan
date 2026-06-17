package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

)


// DatabaseProvider defines the interface for querying database contents
type DatabaseProvider interface {
	GetAllContainers() (interface{}, error)
	GetAllImages() (interface{}, error)
	GetAllImageDetails() (interface{}, error)
	GetImageDetails(digest string) (interface{}, error)
	GetPackagesByImage(digest string) (interface{}, error)
	GetVulnerabilitiesByImage(digest string) (interface{}, error)
	GetImageSummary(digest string) (interface{}, error)
	GetSBOM(digest string) ([]byte, error)
	GetVulnerabilities(digest string) ([]byte, error)
}

// DatabaseProviderWithNodeLookup extends DatabaseProvider with node lookup capability
type DatabaseProviderWithNodeLookup interface {
	DatabaseProvider
	GetFirstContainerForImage(digest string) (NodeInfo, error)
}

// NodeInfo contains information about which node has an image
type NodeInfo struct {
	NodeName         string
	ContainerRuntime string
}

// DatabaseImagesHandler creates an HTTP handler for /containers/images endpoint
func DatabaseImagesHandler(provider DatabaseProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		images, err := provider.GetAllImages()
		if err != nil {
			log.Error("error querying images", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Wrap response in an object with "images" key
		response := map[string]interface{}{
			"images": images,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding images response", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// SBOMDownloadHandler creates an HTTP handler for /api/sbom/{digest} endpoint
// Downloads SBOM as a JSON file
func SBOMDownloadHandler(provider DatabaseProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path
		// Expected format: /api/sbom/sha256:abc123...
		path := r.URL.Path
		if len(path) <= 10 { // "/api/sbom/" is 10 characters
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		digest := path[10:] // Remove "/api/sbom/" prefix

		if digest == "" {
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}

		// Get SBOM from database
		sbomData, err := provider.GetSBOM(digest)
		if err != nil {
			log.Error("error retrieving SBOM", "digest", digest, "error", err)
			http.Error(w, "SBOM not found", http.StatusNotFound)
			return
		}

		// Create a safe filename from digest
		filename := digest
		if len(filename) > 20 {
			// Use shortened version for filename: sha256_abc123.json
			filename = filename[:7] + "_" + filename[7:19]
		}
		filename += ".json"

		// Set headers for file download
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=\"sbom_"+filename+"\"")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(sbomData)))

		// Write SBOM data
		if _, err := w.Write(sbomData); err != nil {
			log.Error("error writing SBOM response", "error", err)
		}
	}
}

// VulnerabilitiesDownloadHandler creates an HTTP handler for /api/vulnerabilities/{digest} endpoint
// Downloads vulnerability report as a JSON file
func VulnerabilitiesDownloadHandler(provider DatabaseProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path
		// Expected format: /api/vulnerabilities/sha256:abc123...
		path := r.URL.Path
		if len(path) <= 21 { // "/api/vulnerabilities/" is 21 characters
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		digest := path[21:] // Remove "/api/vulnerabilities/" prefix

		if digest == "" {
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}

		// Get vulnerabilities from database
		vulnData, err := provider.GetVulnerabilities(digest)
		if err != nil {
			log.Error("error retrieving vulnerabilities", "digest", digest, "error", err)
			http.Error(w, "Vulnerabilities not found", http.StatusNotFound)
			return
		}

		// Create a safe filename from digest
		filename := digest
		if len(filename) > 20 {
			// Use shortened version for filename: sha256_abc123.json
			filename = filename[:7] + "_" + filename[7:19]
		}
		filename += ".json"

		// Set headers for file download
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=\"vulnerabilities_"+filename+"\"")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(vulnData)))

		// Write vulnerability data
		if _, err := w.Write(vulnData); err != nil {
			log.Error("error writing vulnerabilities response", "error", err)
		}
	}
}

// ImageDetailsHandler creates an HTTP handler for /api/images endpoint
// Returns detailed image information including vulnerability counts
func ImageDetailsHandler(provider DatabaseProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		images, err := provider.GetAllImageDetails()
		if err != nil {
			log.Error("error querying image details", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"images": images,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding image details response", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// ImageDetailHandler creates an HTTP handler for /api/images/{digest} endpoint
// Returns detailed information for a specific image
func ImageDetailHandler(provider DatabaseProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path
		path := r.URL.Path
		if len(path) <= 12 { // "/api/images/" is 12 characters
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		digest := path[12:] // Remove "/api/images/" prefix

		if digest == "" {
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}

		details, err := provider.GetImageDetails(digest)
		if err != nil {
			log.Error("error querying image details", "digest", digest, "error", err)
			http.Error(w, "Image not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(details); err != nil {
			log.Error("error encoding image detail response", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// PackagesHandler creates an HTTP handler for /api/images/{digest}/packages endpoint
// Returns all packages for a specific image
func PackagesHandler(provider DatabaseProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path
		// Expected format: /api/images/{digest}/packages
		path := r.URL.Path
		if len(path) <= 12 { // "/api/images/" is 12 characters
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		// Remove "/api/images/" prefix and "/packages" suffix
		pathWithoutPrefix := path[12:]
		if len(pathWithoutPrefix) <= 9 || pathWithoutPrefix[len(pathWithoutPrefix)-9:] != "/packages" {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		digest := pathWithoutPrefix[:len(pathWithoutPrefix)-9]

		packages, err := provider.GetPackagesByImage(digest)
		if err != nil {
			log.Error("error querying packages", "digest", digest, "error", err)
			http.Error(w, "Packages not found", http.StatusNotFound)
			return
		}

		response := map[string]interface{}{
			"packages": packages,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding packages response", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// VulnerabilitiesHandler creates an HTTP handler for /api/images/{digest}/vulnerabilities endpoint
// Returns all vulnerabilities for a specific image
func VulnerabilitiesHandler(provider DatabaseProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path
		// Expected format: /api/images/{digest}/vulnerabilities
		path := r.URL.Path
		if len(path) <= 12 { // "/api/images/" is 12 characters
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		// Remove "/api/images/" prefix and "/vulnerabilities" suffix
		pathWithoutPrefix := path[12:]
		// "/vulnerabilities" is 16 characters, not 17!
		if len(pathWithoutPrefix) <= 16 || pathWithoutPrefix[len(pathWithoutPrefix)-16:] != "/vulnerabilities" {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		digest := pathWithoutPrefix[:len(pathWithoutPrefix)-16]

		vulns, err := provider.GetVulnerabilitiesByImage(digest)
		if err != nil {
			log.Error("error querying vulnerabilities", "digest", digest, "error", err)
			http.Error(w, "Vulnerabilities not found", http.StatusNotFound)
			return
		}

		response := map[string]interface{}{
			"vulnerabilities": vulns,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding vulnerabilities response", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// HandlerOverrides allows customization of specific handlers during registration
type HandlerOverrides struct {
	// SBOMHandler optionally overrides the default SBOM download handler
	// Used by k8s-scan-server to route SBOM requests to pod-scanner
	SBOMHandler http.HandlerFunc
	// VulnerabilitiesHandler optionally overrides the default vulnerabilities download handler
	VulnerabilitiesHandler http.HandlerFunc
}

// RegisterDatabaseHandlers registers database query endpoints on the provided mux
// Pass nil for overrides to use all default handlers
func RegisterDatabaseHandlers(mux *http.ServeMux, provider DatabaseProvider, overrides *HandlerOverrides) {
	// Register legacy endpoints under /api/
	mux.HandleFunc("/api/containers/images", ImageDetailsHandler(provider))

	// Register download endpoints under /api/ with optional overrides
	if overrides != nil && overrides.SBOMHandler != nil {
		mux.HandleFunc("/api/sbom/", overrides.SBOMHandler)
	} else {
		mux.HandleFunc("/api/sbom/", SBOMDownloadHandler(provider))
	}

	if overrides != nil && overrides.VulnerabilitiesHandler != nil {
		mux.HandleFunc("/api/vulnerabilities/", overrides.VulnerabilitiesHandler)
	} else {
		mux.HandleFunc("/api/vulnerabilities/", func(w http.ResponseWriter, r *http.Request) {
			// Check if this is a request for vulnerability details
			path := r.URL.Path
			log.Debug("vulnerability route handler", "path", path)
			if len(path) > 8 && path[len(path)-8:] == "/details" {
				log.Debug("path ends with /details, checking for ImageQueryProvider")
				// Route to details handler if ImageQueryProvider is available
				if queryProvider, ok := provider.(ImageQueryProvider); ok {
					log.Debug("routing to VulnerabilityDetailsHandler")
					VulnerabilityDetailsHandler(queryProvider)(w, r)
					return
				}
				log.Debug("ImageQueryProvider not available, falling through")
			}
			// Otherwise, use the download handler
			log.Debug("routing to VulnerabilitiesDownloadHandler")
			VulnerabilitiesDownloadHandler(provider)(w, r)
		})
	}

	// Register new API endpoints for aggregated data
	// Note: ImagesHandler provides filtering, pagination, sorting, and CSV export
	// It requires the provider to implement ImageQueryProvider interface
	if queryProvider, ok := provider.(ImageQueryProvider); ok {
		mux.HandleFunc("/api/images", ImagesHandler(queryProvider))
		mux.HandleFunc("/api/containers", ContainersHandler(queryProvider))
		mux.HandleFunc("/api/container-cves", ContainerCVEsHandler(queryProvider))
		mux.HandleFunc("/api/container-cves/affected", ContainerCVEAffectedHandler(queryProvider))
		mux.HandleFunc("/api/container-cves/details", ContainerCVEDetailVariantsHandler(queryProvider))
		if filterProvider, ok := provider.(FilterOptionsProvider); ok {
			mux.HandleFunc("/api/filter-options", FilterOptionsHandler(filterProvider))
		}
		mux.HandleFunc("/api/summary/deployment-metrics", DeploymentMetricsHandler(queryProvider))
		mux.HandleFunc("/api/summary/node-metrics", NodeMetricsSummaryHandler(queryProvider))
		mux.HandleFunc("/api/summary/by-namespace", NamespaceSummaryHandler(queryProvider))
		mux.HandleFunc("/api/summary/by-distribution", DistributionSummaryHandler(queryProvider))
	} else {
		// Fallback to basic handler if provider doesn't support ExecuteReadOnlyQuery
		mux.HandleFunc("/api/images", ImageDetailsHandler(provider))
	}

	// Register last updated endpoint for auto-refresh functionality
	if lastUpdatedProvider, ok := provider.(LastUpdatedProvider); ok {
		mux.HandleFunc("/api/lastupdated", LastUpdatedHandler(lastUpdatedProvider))
	}
	mux.HandleFunc("/api/images/", func(w http.ResponseWriter, r *http.Request) {
		// Route to appropriate handler based on path suffix
		path := r.URL.Path
		log.Debug("routing /api/images/", "path", path)

		// "/api/images/" is 12 characters
		if len(path) > 12 {
			pathWithoutPrefix := path[12:]
			log.Debug("routing /api/images/", "path_without_prefix", pathWithoutPrefix)

			// Check if we have ImageQueryProvider for enhanced handlers
			if queryProvider, ok := provider.(ImageQueryProvider); ok {
				log.Debug("routing /api/images/ - using ImageQueryProvider")

				// Check for /packages suffix
				if len(pathWithoutPrefix) > 9 && pathWithoutPrefix[len(pathWithoutPrefix)-9:] == "/packages" {
					log.Debug("routing to ImagePackagesDetailHandler")
					ImagePackagesDetailHandler(queryProvider)(w, r)
					return
				}
				// Check for /vulnerabilities suffix
				// "/vulnerabilities" is 16 characters
				if len(pathWithoutPrefix) > 16 && pathWithoutPrefix[len(pathWithoutPrefix)-16:] == "/vulnerabilities" {
					log.Debug("routing to ImageVulnerabilitiesDetailHandler")
					ImageVulnerabilitiesDetailHandler(queryProvider)(w, r)
					return
				}
				// Check for /stats suffix
				if len(pathWithoutPrefix) > 6 && pathWithoutPrefix[len(pathWithoutPrefix)-6:] == "/stats" {
					log.Debug("routing to ImageStatsHandler")
					ImageStatsHandler(queryProvider)(w, r)
					return
				}
				// Single image detail with full info (references and containers)
				log.Debug("routing to ImageDetailFullHandler")
				ImageDetailFullHandler(queryProvider)(w, r)
			} else {
				// Fallback to basic handlers if provider doesn't support ExecuteReadOnlyQuery
				if len(pathWithoutPrefix) > 9 && pathWithoutPrefix[len(pathWithoutPrefix)-9:] == "/packages" {
					PackagesHandler(provider)(w, r)
					return
				}
				if len(pathWithoutPrefix) > 16 && pathWithoutPrefix[len(pathWithoutPrefix)-16:] == "/vulnerabilities" {
					VulnerabilitiesHandler(provider)(w, r)
					return
				}
				ImageDetailHandler(provider)(w, r)
			}
		}
	})

	// Route for package details (separate from image packages)
	// This handles /api/packages/{id}/details for showing individual package JSON details
	mux.HandleFunc("/api/packages/", func(w http.ResponseWriter, r *http.Request) {
		// Check if this is a request for package details
		path := r.URL.Path
		if len(path) > 8 && path[len(path)-8:] == "/details" {
			// Route to details handler if ImageQueryProvider is available
			if queryProvider, ok := provider.(ImageQueryProvider); ok {
				log.Debug("routing to PackageDetailsHandler")
				PackageDetailsHandler(queryProvider)(w, r)
				return
			}
		}
		http.Error(w, "Not found", http.StatusNotFound)
	})
}
