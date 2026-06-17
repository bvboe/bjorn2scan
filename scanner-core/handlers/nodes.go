package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/bvboe/b2s-go/scanner-core/database"
)


// RegisterNodeHandlers registers all node-related HTTP handlers
func RegisterNodeHandlers(mux *http.ServeMux, db *database.DB) {
	mux.HandleFunc("/api/nodes", ListNodesHandler(db))
	mux.HandleFunc("/api/nodes/", NodeDetailHandler(db))
	mux.HandleFunc("/api/summary/by-node", NodeSummaryHandler(db))
	mux.HandleFunc("/api/summary/by-node-distro", NodeDistributionSummaryHandler(db))
	mux.HandleFunc("/api/node-filter-options", NodeFilterOptionsHandler(db))
	mux.HandleFunc("/api/node-vulnerabilities/", NodeVulnerabilityDetailsHandler(db))
	mux.HandleFunc("/api/node-packages/", NodePackageDetailsHandler(db))
	mux.HandleFunc("/api/node-cves", NodeCVEsHandler(db))
	mux.HandleFunc("/api/node-cves/affected", NodeCVEAffectedHandler(db))
	mux.HandleFunc("/api/node-cves/details", NodeCVEDetailVariantsHandler(db))
}

// ListNodesHandler returns a handler that lists all nodes with their scan status
func ListNodesHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		nodes, err := db.GetAllNodes()
		if err != nil {
			log.Error("error getting nodes", "error", err)
			http.Error(w, "Failed to get nodes", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(nodes); err != nil {
			log.Error("error encoding nodes response", "error", err)
		}
	}
}

// NodeDetailHandler returns a handler for node detail endpoints
// Routes:
//
//	GET /api/nodes/{name} - Get node details
//	GET /api/nodes/{name}/packages - Get node packages
//	GET /api/nodes/{name}/vulnerabilities - Get node vulnerabilities
func NodeDetailHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse the path: /api/nodes/{name} or /api/nodes/{name}/{subresource}
		path := strings.TrimPrefix(r.URL.Path, "/api/nodes/")
		if path == "" {
			http.Error(w, "Node name required", http.StatusBadRequest)
			return
		}

		parts := strings.SplitN(path, "/", 2)
		nodeName := parts[0]
		subResource := ""
		if len(parts) > 1 {
			subResource = parts[1]
		}

		var result interface{}
		var err error

		switch subResource {
		case "":
			// GET /api/nodes/{name} - Get node details
			node, getErr := db.GetNode(nodeName)
			if getErr != nil {
				log.Error("error getting node", "node_name", nodeName, "error", getErr)
				http.Error(w, "Failed to get node", http.StatusInternalServerError)
				return
			}
			if node == nil {
				http.Error(w, "Node not found", http.StatusNotFound)
				return
			}
			result = node

		case "packages":
			// GET /api/nodes/{name}/packages - Get node packages
			format := r.URL.Query().Get("format")
			if format == "json" {
				// Export raw SBOM JSON (Syft output)
				sbom, sbomErr := db.GetNodeSBOM(nodeName)
				if sbomErr != nil {
					log.Error("error getting node SBOM", "node_name", nodeName, "error", sbomErr)
					http.Error(w, "Failed to get node SBOM", http.StatusInternalServerError)
					return
				}
				if sbom == nil {
					http.Error(w, "SBOM not found", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"syft-sbom-%s.json\"", nodeName))
				if _, writeErr := w.Write(sbom); writeErr != nil {
					log.Error("error writing node SBOM response", "error", writeErr)
				}
				return
			}
			if format == "csv" {
				// Export packages as CSV
				packages, csvErr := db.GetNodePackages(nodeName)
				if csvErr != nil {
					log.Error("error getting node packages", "node_name", nodeName, "error", csvErr)
					http.Error(w, "Failed to get node packages", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "text/csv")
				w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"packages-%s.csv\"", nodeName))
				writer := csv.NewWriter(w)
				defer writer.Flush()
				_ = writer.Write([]string{"name", "version", "type", "purl", "count"})
				for _, pkg := range packages {
					_ = writer.Write([]string{pkg.Name, pkg.Version, pkg.Type, pkg.PURL, fmt.Sprintf("%d", pkg.Count)})
				}
				return
			}
			result, err = db.GetNodePackages(nodeName)

		case "vulnerabilities":
			// GET /api/nodes/{name}/vulnerabilities - Get node vulnerabilities
			format := r.URL.Query().Get("format")
			if format == "json" {
				// Export raw vulnerability JSON (Grype output)
				vulns, vulnErr := db.GetNodeVulnerabilitiesRaw(nodeName)
				if vulnErr != nil {
					log.Error("error getting node vulnerabilities", "node_name", nodeName, "error", vulnErr)
					http.Error(w, "Failed to get node vulnerabilities", http.StatusInternalServerError)
					return
				}
				if vulns == nil {
					http.Error(w, "Vulnerabilities not found", http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"grype-vulnerabilities-%s.json\"", nodeName))
				if _, writeErr := w.Write(vulns); writeErr != nil {
					log.Error("error writing node vulnerabilities response", "error", writeErr)
				}
				return
			}
			if format == "csv" {
				// Export vulnerabilities as CSV
				vulns, csvErr := db.GetNodeVulnerabilities(nodeName)
				if csvErr != nil {
					log.Error("error getting node vulnerabilities", "node_name", nodeName, "error", csvErr)
					http.Error(w, "Failed to get node vulnerabilities", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "text/csv")
				w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"vulnerabilities-%s.csv\"", nodeName))
				writer := csv.NewWriter(w)
				defer writer.Flush()
				_ = writer.Write([]string{"cve_id", "severity", "score", "package_name", "package_version", "package_type", "fix_status", "fix_version", "known_exploited", "count"})
				for _, v := range vulns {
					_ = writer.Write([]string{
						v.CVEID,
						v.Severity,
						fmt.Sprintf("%.1f", v.Risk),
						v.PackageName,
						v.PackageVersion,
						v.PackageType,
						v.FixStatus,
						v.FixVersion,
						fmt.Sprintf("%d", v.KnownExploited),
						fmt.Sprintf("%d", v.Count),
					})
				}
				return
			}
			result, err = db.GetNodeVulnerabilities(nodeName)

		default:
			http.Error(w, "Unknown subresource", http.StatusNotFound)
			return
		}

		if err != nil {
			log.Error("error getting node data", "node_name", nodeName, "sub_resource", subResource, "error", err)
			http.Error(w, "Failed to get node data", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(result); err != nil {
			log.Error("error encoding node response", "error", err)
		}
	}
}

// parseCommaSeparated splits a comma-separated string into a slice, filtering empty values
func parseCommaSeparated(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// NodeSummaryHandler returns a handler that provides vulnerability summary by node
// Supports filters: osNames, vulnStatuses, packageTypes (comma-separated)
// Supports format=csv for CSV export
func NodeSummaryHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse filter parameters
		params := r.URL.Query()
		filters := database.NodeSummaryFilters{
			OSNames:      parseCommaSeparated(params.Get("osNames")),
			VulnStatuses: parseCommaSeparated(params.Get("vulnStatuses")),
			PackageTypes: parseCommaSeparated(params.Get("packageTypes")),
		}

		summaries, err := db.GetNodeSummariesFiltered(filters)
		if err != nil {
			log.Error("error getting node summaries", "error", err)
			http.Error(w, "Failed to get node summaries", http.StatusInternalServerError)
			return
		}

		// Handle CSV export
		if params.Get("format") == "csv" {
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", "attachment; filename=node_summary.csv")

			writer := csv.NewWriter(w)
			defer writer.Flush()

			// Write header
			_ = writer.Write([]string{
				"Node Name", "OS Distribution", "Critical", "High", "Medium",
				"Low", "Negligible", "Unknown", "Total", "Risk Score", "Known Exploits", "Packages",
			})

			// Write data
			for _, s := range summaries {
				_ = writer.Write([]string{
					s.NodeName,
					s.OSRelease,
					fmt.Sprintf("%d", s.Critical),
					fmt.Sprintf("%d", s.High),
					fmt.Sprintf("%d", s.Medium),
					fmt.Sprintf("%d", s.Low),
					fmt.Sprintf("%d", s.Negligible),
					fmt.Sprintf("%d", s.Unknown),
					fmt.Sprintf("%d", s.Total),
					fmt.Sprintf("%.1f", s.TotalRisk),
					fmt.Sprintf("%d", s.ExploitCount),
					fmt.Sprintf("%d", s.PackageCount),
				})
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(summaries); err != nil {
			log.Error("error encoding node summaries response", "error", err)
		}
	}
}

// NodeDistributionSummaryHandler returns a handler that provides averaged vulnerability summary by node OS distribution
// Supports format=csv for CSV export
func NodeDistributionSummaryHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		summaries, err := db.GetNodeDistributionSummary()
		if err != nil {
			log.Error("error getting node distribution summary", "error", err)
			http.Error(w, "Failed to get node distribution summary", http.StatusInternalServerError)
			return
		}

		// Handle CSV export
		if r.URL.Query().Get("format") == "csv" {
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", "attachment; filename=node_distribution_summary.csv")

			writer := csv.NewWriter(w)
			defer writer.Flush()

			// Write header
			_ = writer.Write([]string{
				"OS Distribution", "Node Count", "Avg Critical", "Avg High", "Avg Medium",
				"Avg Low", "Avg Negligible", "Avg Unknown", "Avg Risk Score", "Avg Exploits", "Avg Packages",
			})

			// Write data
			for _, s := range summaries {
				_ = writer.Write([]string{
					s.OSName,
					fmt.Sprintf("%d", s.NodeCount),
					fmt.Sprintf("%.1f", s.AvgCritical),
					fmt.Sprintf("%.1f", s.AvgHigh),
					fmt.Sprintf("%.1f", s.AvgMedium),
					fmt.Sprintf("%.1f", s.AvgLow),
					fmt.Sprintf("%.1f", s.AvgNegligible),
					fmt.Sprintf("%.1f", s.AvgUnknown),
					fmt.Sprintf("%.1f", s.AvgRisk),
					fmt.Sprintf("%.1f", s.AvgExploits),
					fmt.Sprintf("%.1f", s.AvgPackages),
				})
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(summaries); err != nil {
			log.Error("error encoding node distribution summary response", "error", err)
		}
	}
}

// NodeFilterOptionsHandler returns a handler that provides filter options for node-related pages
func NodeFilterOptionsHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		options, err := db.GetNodeFilterOptions()
		if err != nil {
			log.Error("error getting node filter options", "error", err)
			http.Error(w, "Failed to get node filter options", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(options); err != nil {
			log.Error("error encoding node filter options response", "error", err)
		}
	}
}

// NodeVulnerabilityDetailsHandler returns JSON details for a specific node vulnerability
// Route: GET /api/node-vulnerabilities/{id}/details
func NodeVulnerabilityDetailsHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse path: /api/node-vulnerabilities/{id}/details
		path := strings.TrimPrefix(r.URL.Path, "/api/node-vulnerabilities/")
		if !strings.HasSuffix(path, "/details") {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}

		idStr := strings.TrimSuffix(path, "/details")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid vulnerability ID", http.StatusBadRequest)
			return
		}

		details, err := db.GetNodeVulnerabilityDetails(id)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				http.Error(w, "Vulnerability not found", http.StatusNotFound)
				return
			}
			log.Error("error getting node vulnerability details", "error", err)
			http.Error(w, "Failed to get vulnerability details", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(details)); err != nil {
			log.Error("error writing vulnerability details response", "error", err)
		}
	}
}

// NodePackageDetailsHandler returns JSON details for a specific node package
// Route: GET /api/node-packages/{id}/details
func NodePackageDetailsHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse path: /api/node-packages/{id}/details
		path := strings.TrimPrefix(r.URL.Path, "/api/node-packages/")
		if !strings.HasSuffix(path, "/details") {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}

		idStr := strings.TrimSuffix(path, "/details")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			http.Error(w, "Invalid package ID", http.StatusBadRequest)
			return
		}

		details, err := db.GetNodePackageDetails(id)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				http.Error(w, "Package not found", http.StatusNotFound)
				return
			}
			log.Error("error getting node package details", "error", err)
			http.Error(w, "Failed to get package details", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(details)); err != nil {
			log.Error("error writing package details response", "error", err)
		}
	}
}
