package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/bvboe/b2s-go/scanner-core/database"
)


// ImageQueryProvider defines the interface for executing image queries
type ImageQueryProvider interface {
	ExecuteReadOnlyQuery(query string) (*database.QueryResult, error)
	GetSBOM(digest string) ([]byte, error)
	GetVulnerabilities(digest string) ([]byte, error)
}

// FilterOptionsProvider provides cached image filter options.
type FilterOptionsProvider interface {
	GetFilterOptions() (*database.FilterOptions, error)
}

// FilterOptionsHandler creates an HTTP handler for /api/filter-options endpoint.
// Returns distinct values for all filter dropdowns, served from an in-memory cache.
func FilterOptionsHandler(provider FilterOptionsProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		opts, err := provider.GetFilterOptions()
		if err != nil {
			log.Error("error fetching filter options", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		response := map[string][]string{
			"namespaces":   opts.Namespaces,
			"osNames":      opts.OSNames,
			"vulnStatuses": opts.VulnStatuses,
			"packageTypes": opts.PackageTypes,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding filter options", "error", err)
		}
	}
}

// ImagesHandler creates an HTTP handler for /api/images endpoint
func ImagesHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse query parameters
		params := r.URL.Query()

		// Export format
		format := params.Get("format")

		// Pagination (skip for CSV export - export all data)
		page, _ := strconv.Atoi(params.Get("page"))
		if page < 1 {
			page = 1
		}
		pageSize, _ := strconv.Atoi(params.Get("pageSize"))
		if pageSize < 1 || pageSize > 1000 {
			pageSize = 50
		}
		offset := (page - 1) * pageSize

		// For CSV export, get all results
		if format == "csv" {
			pageSize = -1
			offset = 0
		}

		// Search
		search := params.Get("search")

		// Filters (multiselect - comma separated)
		namespaces := parseMultiSelect(params.Get("namespaces"))
		vulnStatuses := parseMultiSelect(params.Get("vulnStatuses"))
		packageTypes := parseMultiSelect(params.Get("packageTypes"))
		osNames := parseMultiSelect(params.Get("osNames"))

		// Sorting
		sortBy := params.Get("sortBy")
		sortOrder := params.Get("sortOrder")
		if sortOrder != "ASC" && sortOrder != "DESC" {
			sortOrder = "ASC"
		}

		// Build query
		query, countQuery := buildImagesQuery(search, namespaces, vulnStatuses, packageTypes, osNames, sortBy, sortOrder, pageSize, offset)

		// Execute count query for pagination
		countResult, err := provider.ExecuteReadOnlyQuery(countQuery)
		if err != nil {
			log.Error("error executing count query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		totalCount := 0
		if len(countResult.Rows) > 0 && len(countResult.Columns) > 0 {
			if count, ok := countResult.Rows[0][countResult.Columns[0]].(int64); ok {
				totalCount = int(count)
			}
		}

		// Execute main query
		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Error("error executing images query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Handle CSV export
		if format == "csv" {
			exportQueryResultAsCSV(w, result, "images.csv")
			return
		}

		// Rows are already maps, just use them directly
		response := map[string]interface{}{
			"images":     result.Rows,
			"page":       page,
			"pageSize":   pageSize,
			"totalCount": totalCount,
			"totalPages": (totalCount + pageSize - 1) / pageSize,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding JSON", "error", err)
		}
	}
}

// parseMultiSelect parses comma-separated values from query parameter
func parseMultiSelect(value string) []string {
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// buildImagesQuery constructs the SQL query with filters
func buildImagesQuery(search string, namespaces, vulnStatuses, packageTypes, osNames []string, sortBy, sortOrder string, limit, offset int) (string, string) {
	// Base query
	baseQuery := `
  FROM containers instances
  JOIN images images ON instances.image_id = images.id
  JOIN scan_status status ON images.status = status.status
  LEFT JOIN (
      SELECT image_id, COALESCE(SUM(number_of_instances), 0) as package_count
      FROM image_packages
      %s
      GROUP BY image_id
  ) pkg_counts ON images.id = pkg_counts.image_id
  LEFT JOIN (
      SELECT
          image_id,
          SUM(CASE WHEN LOWER(severity) = 'critical' THEN count ELSE 0 END) as critical_count,
          SUM(CASE WHEN LOWER(severity) = 'high' THEN count ELSE 0 END) as high_count,
          SUM(CASE WHEN LOWER(severity) = 'medium' THEN count ELSE 0 END) as medium_count,
          SUM(CASE WHEN LOWER(severity) = 'low' THEN count ELSE 0 END) as low_count,
          SUM(CASE WHEN LOWER(severity) = 'negligible' THEN count ELSE 0 END) as negligible_count,
          SUM(CASE WHEN LOWER(severity) = 'unknown' THEN count ELSE 0 END) as unknown_count,
          SUM(count) as total_cves,
          COUNT(DISTINCT cve_id) as unique_cves,
          SUM(risk * count) as total_risk,
          SUM(known_exploited * count) as exploit_count
      FROM image_vulnerabilities
      %s
      GROUP BY image_id
  ) vuln_counts ON images.id = vuln_counts.image_id
  WHERE 1=1`

	// Build subquery filters using helper functions
	packageTypeFilter := buildPackageTypeFilter(packageTypes)
	vulnStatusFilter := buildVulnerabilityFilter(vulnStatuses, packageTypes)

	baseQuery = fmt.Sprintf(baseQuery, packageTypeFilter, vulnStatusFilter)

	// Build WHERE conditions
	var conditions []string

	// Search filter (image name)
	conditions = appendCondition(conditions, buildLikeCondition("instances.reference", search))

	// Namespace filter
	conditions = appendCondition(conditions, buildINClause("instances.namespace", namespaces))

	// Note: Vulnerability fix status filter is now applied in the vulnerabilities subquery

	// OS name filter
	conditions = appendCondition(conditions, buildINClause("images.os_name", osNames))

	// Add conditions to base query
	whereClause := baseQuery + buildWhereClause(conditions)

	// Group by
	groupBy := " GROUP BY instances.reference, images.digest, images.os_name, status.status"

	// Build count query
	countQuery := "SELECT COUNT(*) FROM (" +
		"SELECT instances.reference as image" +
		whereClause +
		groupBy +
		") subquery"

	// Build main query with sorting
	selectClause := `SELECT
      instances.reference as image,
      images.digest,
      COUNT(*) as container_count,
      COALESCE(vuln_counts.critical_count, 0) as critical_count,
      COALESCE(vuln_counts.high_count, 0) as high_count,
      COALESCE(vuln_counts.medium_count, 0) as medium_count,
      COALESCE(vuln_counts.low_count, 0) as low_count,
      COALESCE(vuln_counts.negligible_count, 0) as negligible_count,
      COALESCE(vuln_counts.unknown_count, 0) as unknown_count,
      COALESCE(vuln_counts.total_cves, 0) as total_cves,
      COALESCE(vuln_counts.unique_cves, 0) as unique_cves,
      COALESCE(vuln_counts.total_risk, 0) as total_risk,
      COALESCE(vuln_counts.exploit_count, 0) as exploit_count,
      COALESCE(pkg_counts.package_count, 0) as package_count,
      status.description as status_description,
      images.os_name`

	mainQuery := selectClause + whereClause + groupBy

	// Add sorting with multi-level hierarchy:
	// 1. status.sort_order (always first - groups by scan status priority)
	// 2. User-selected column (if any)
	// 3. image (always last - for consistent tie-breaking)
	validSortColumns := map[string]bool{
		"image": true, "container_count": true, "critical_count": true,
		"high_count": true, "medium_count": true, "low_count": true,
		"negligible_count": true, "unknown_count": true, "total_risk": true,
		"exploit_count": true, "package_count": true, "os_name": true,
		"total_cves": true, "unique_cves": true,
	}

	if sortBy != "" && validSortColumns[sortBy] {
		mainQuery += fmt.Sprintf(" ORDER BY status.sort_order ASC, %s %s", sortBy, sortOrder)
		// Add image as tertiary sort (for tie-breaking), unless it's the secondary sort
		if sortBy != "image" {
			mainQuery += ", image ASC"
		}
	} else {
		mainQuery += " ORDER BY status.sort_order ASC, image ASC"
	}

	// Add pagination (skip if limit <= 0 for full export)
	if limit > 0 {
		mainQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}

	return mainQuery, countQuery
}

// ContainersHandler creates an HTTP handler for /api/containers endpoint
func ContainersHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse query parameters
		params := r.URL.Query()

		// Export format
		format := params.Get("format")

		// Pagination (skip for CSV export - export all data)
		page, _ := strconv.Atoi(params.Get("page"))
		if page < 1 {
			page = 1
		}
		pageSize, _ := strconv.Atoi(params.Get("pageSize"))
		if pageSize < 1 || pageSize > 1000 {
			pageSize = 50
		}
		offset := (page - 1) * pageSize

		// For CSV export, get all results
		if format == "csv" {
			pageSize = -1
			offset = 0
		}

		// Search
		search := params.Get("search")

		// Filters (multiselect - comma separated)
		namespaces := parseMultiSelect(params.Get("namespaces"))
		vulnStatuses := parseMultiSelect(params.Get("vulnStatuses"))
		packageTypes := parseMultiSelect(params.Get("packageTypes"))
		osNames := parseMultiSelect(params.Get("osNames"))

		// Sorting
		sortBy := params.Get("sortBy")
		sortOrder := params.Get("sortOrder")
		if sortOrder != "ASC" && sortOrder != "DESC" {
			sortOrder = "ASC"
		}

		// Build query
		query, countQuery := buildContainersQuery(search, namespaces, vulnStatuses, packageTypes, osNames, sortBy, sortOrder, pageSize, offset)

		// Execute count query for pagination
		countResult, err := provider.ExecuteReadOnlyQuery(countQuery)
		if err != nil {
			log.Error("error executing count query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		totalCount := 0
		if len(countResult.Rows) > 0 && len(countResult.Columns) > 0 {
			if count, ok := countResult.Rows[0][countResult.Columns[0]].(int64); ok {
				totalCount = int(count)
			}
		}

		// Execute main query
		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Error("error executing containers query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Handle CSV export
		if format == "csv" {
			exportQueryResultAsCSV(w, result, "containers.csv")
			return
		}

		// Rows are already maps, just use them directly
		response := map[string]interface{}{
			"containers": result.Rows,
			"page":       page,
			"pageSize":   pageSize,
			"totalCount": totalCount,
			"totalPages": (totalCount + pageSize - 1) / pageSize,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding JSON", "error", err)
		}
	}
}

// buildContainersQuery constructs the SQL query for containers with filters
func buildContainersQuery(search string, namespaces, vulnStatuses, packageTypes, osNames []string, sortBy, sortOrder string, limit, offset int) (string, string) {
	// Base query - individual containers
	baseQuery := `
  FROM containers instances
  JOIN images images ON instances.image_id = images.id
  JOIN scan_status status ON images.status = status.status
  LEFT JOIN (
      SELECT image_id, COALESCE(SUM(number_of_instances), 0) as package_count
      FROM image_packages
      %s
      GROUP BY image_id
  ) pkg_counts ON images.id = pkg_counts.image_id
  LEFT JOIN (
      SELECT
          image_id,
          SUM(CASE WHEN LOWER(severity) = 'critical' THEN count ELSE 0 END) as critical_count,
          SUM(CASE WHEN LOWER(severity) = 'high' THEN count ELSE 0 END) as high_count,
          SUM(CASE WHEN LOWER(severity) = 'medium' THEN count ELSE 0 END) as medium_count,
          SUM(CASE WHEN LOWER(severity) = 'low' THEN count ELSE 0 END) as low_count,
          SUM(CASE WHEN LOWER(severity) = 'negligible' THEN count ELSE 0 END) as negligible_count,
          SUM(CASE WHEN LOWER(severity) = 'unknown' THEN count ELSE 0 END) as unknown_count,
          SUM(count) as total_cves,
          COUNT(DISTINCT cve_id) as unique_cves,
          SUM(risk * count) as total_risk,
          SUM(known_exploited * count) as exploit_count
      FROM image_vulnerabilities
      %s
      GROUP BY image_id
  ) vuln_counts ON images.id = vuln_counts.image_id
  WHERE 1=1`

	// Build subquery filters using helper functions
	packageTypeFilter := buildPackageTypeFilter(packageTypes)
	vulnStatusFilter := buildVulnerabilityFilter(vulnStatuses, packageTypes)

	baseQuery = fmt.Sprintf(baseQuery, packageTypeFilter, vulnStatusFilter)

	// Build WHERE conditions
	var conditions []string

	// Search filter (pod, container, or namespace) - searches across multiple fields
	if search != "" {
		escapedSearch := escapeSQL(search)
		conditions = append(conditions, fmt.Sprintf("(instances.namespace LIKE '%%%s%%' OR instances.pod LIKE '%%%s%%' OR instances.name LIKE '%%%s%%')", escapedSearch, escapedSearch, escapedSearch))
	}

	// Namespace filter
	conditions = appendCondition(conditions, buildINClause("instances.namespace", namespaces))

	// OS name filter
	conditions = appendCondition(conditions, buildINClause("images.os_name", osNames))

	// Add conditions to base query
	whereClause := baseQuery + buildWhereClause(conditions)

	// Build count query
	countQuery := "SELECT COUNT(*) FROM (" +
		"SELECT instances.id" +
		whereClause +
		") subquery"

	// Build main query with sorting
	selectClause := `SELECT
      instances.namespace,
      instances.pod,
      instances.name,
      images.digest,
      COALESCE(vuln_counts.critical_count, 0) as critical_count,
      COALESCE(vuln_counts.high_count, 0) as high_count,
      COALESCE(vuln_counts.medium_count, 0) as medium_count,
      COALESCE(vuln_counts.low_count, 0) as low_count,
      COALESCE(vuln_counts.negligible_count, 0) as negligible_count,
      COALESCE(vuln_counts.unknown_count, 0) as unknown_count,
      COALESCE(vuln_counts.total_cves, 0) as total_cves,
      COALESCE(vuln_counts.unique_cves, 0) as unique_cves,
      COALESCE(vuln_counts.total_risk, 0) as total_risk,
      COALESCE(vuln_counts.exploit_count, 0) as exploit_count,
      COALESCE(pkg_counts.package_count, 0) as package_count,
      status.description as status_description,
      images.os_name`

	mainQuery := selectClause + whereClause

	// Add sorting with multi-level hierarchy:
	// 1. status.sort_order (always first - groups by scan status priority)
	// 2. User-selected column (if any)
	// 3. namespace/pod/container (always last - for consistent tie-breaking, avoiding duplicates)
	validSortColumns := map[string]bool{
		"namespace": true, "pod": true, "name": true,
		"critical_count": true, "high_count": true, "medium_count": true,
		"low_count": true, "negligible_count": true, "unknown_count": true,
		"total_risk": true, "exploit_count": true, "package_count": true,
		"os_name": true,
		"total_cves": true, "unique_cves": true,
	}

	if sortBy != "" && validSortColumns[sortBy] {
		mainQuery += fmt.Sprintf(" ORDER BY status.sort_order ASC, %s %s", sortBy, sortOrder)

		// Add namespace/pod/name as tie-breakers, skipping any already used
		if sortBy != "namespace" {
			mainQuery += ", instances.namespace ASC"
		}
		if sortBy != "pod" {
			mainQuery += ", instances.pod ASC"
		}
		if sortBy != "name" {
			mainQuery += ", instances.name ASC"
		}
	} else {
		mainQuery += " ORDER BY status.sort_order ASC, instances.namespace ASC, instances.pod ASC, instances.name ASC"
	}

	// Add pagination (skip if limit <= 0 for full export)
	if limit > 0 {
		mainQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}

	return mainQuery, countQuery
}

// exportQueryResultAsCSV exports query results as CSV with the specified filename
func exportQueryResultAsCSV(w http.ResponseWriter, result *database.QueryResult, filename string) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)

	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write headers
	if err := writer.Write(result.Columns); err != nil {
		log.Error("error writing CSV headers", "error", err)
		return
	}

	// Write rows
	for _, rowMap := range result.Rows {
		strRow := make([]string, len(result.Columns))
		for i, col := range result.Columns {
			strRow[i] = fmt.Sprintf("%v", rowMap[col])
		}
		if err := writer.Write(strRow); err != nil {
			log.Error("error writing CSV row", "error", err)
			return
		}
	}
}

// ImageDetailFullHandler creates an HTTP handler for /api/images/{digest} endpoint
// Returns detailed information for a specific image including references and containers
func ImageDetailFullHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path
		path := r.URL.Path
		log.Debug("received image detail request", "path", path)

		if len(path) <= 12 { // "/api/images/" is 12 characters
			log.Warn("path too short for image detail", "length", len(path))
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		digest := path[12:] // Remove "/api/images/" prefix
		log.Debug("extracted digest from path", "digest", digest)

		if digest == "" {
			log.Warn("empty digest provided")
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}

		// Build query to get basic image details
		escapedDigest := escapeSQL(digest)
		imageQuery := `
SELECT
    images.id,
    images.digest as image_id,
    images.status as scan_status,
    images.os_name as distro_display_name,
    status.description as status_description,
    images.vulns_scanned_at,
    images.grype_db_built
FROM images images
JOIN scan_status status ON images.status = status.status
WHERE images.digest = '` + escapedDigest + `'`

		log.Debug("executing image query", "digest", digest)
		imageResult, err := provider.ExecuteReadOnlyQuery(imageQuery)
		if err != nil {
			log.Error("error querying image details", "digest", digest, "error", err)
			http.Error(w, fmt.Sprintf("Error querying image: %v", err), http.StatusInternalServerError)
			return
		}

		if len(imageResult.Rows) == 0 {
			log.Warn("no image found", "digest", digest)
			http.Error(w, "Image not found", http.StatusNotFound)
			return
		}

		log.Debug("found image")
		imageRow := imageResult.Rows[0]
		imageID := imageRow["id"]

		// Get distinct references for this image
		refQuery := `
SELECT DISTINCT reference as ref
FROM containers
WHERE image_id = ` + fmt.Sprintf("%v", imageID) + `
ORDER BY reference`

		log.Debug("fetching references", "image_id", imageID)
		refResult, err := provider.ExecuteReadOnlyQuery(refQuery)
		if err != nil {
			log.Error("error querying references", "image_id", imageID, "error", err)
			http.Error(w, fmt.Sprintf("Error querying references: %v", err), http.StatusInternalServerError)
			return
		}

		references := []string{}
		for _, row := range refResult.Rows {
			if ref, ok := row["ref"].(string); ok && ref != "" {
				references = append(references, ref)
			}
		}
		log.Debug("found references", "count", len(references))

		// Get distinct containers for this image
		containerQuery := `
SELECT DISTINCT namespace || '.' || pod || '.' || name as container
FROM containers
WHERE image_id = ` + fmt.Sprintf("%v", imageID) + `
ORDER BY namespace, pod, name`

		log.Debug("fetching containers", "image_id", imageID)
		containerResult, err := provider.ExecuteReadOnlyQuery(containerQuery)
		if err != nil {
			log.Error("error querying containers", "image_id", imageID, "error", err)
			http.Error(w, fmt.Sprintf("Error querying containers: %v", err), http.StatusInternalServerError)
			return
		}

		containers := []string{}
		for _, row := range containerResult.Rows {
			if c, ok := row["container"].(string); ok && c != "" {
				containers = append(containers, c)
			}
		}
		log.Debug("found containers", "count", len(containers))

		// Get vulnerability summary stats
		// unique_cves and unique_exploits dedupe by cve_id alone — a single CVE that
		// affects multiple (package, version) tuples in the same image counts once.
		vulnStatsQuery := fmt.Sprintf(`
SELECT
    COALESCE(SUM(v.risk * v.count), 0) as total_risk,
    COALESCE(SUM(v.count), 0) as total_cves,
    COUNT(DISTINCT v.cve_id) as unique_cves,
    COALESCE(SUM(v.known_exploited * v.count), 0) as total_exploits,
    COUNT(DISTINCT CASE WHEN v.known_exploited > 0 THEN v.cve_id END) as unique_exploits,
    COALESCE(SUM(CASE WHEN v.severity = 'Critical'    THEN v.count ELSE 0 END), 0) as cves_critical,
    COALESCE(SUM(CASE WHEN v.severity = 'High'        THEN v.count ELSE 0 END), 0) as cves_high,
    COALESCE(SUM(CASE WHEN v.severity = 'Medium'      THEN v.count ELSE 0 END), 0) as cves_medium,
    COALESCE(SUM(CASE WHEN v.severity = 'Low'         THEN v.count ELSE 0 END), 0) as cves_low,
    COALESCE(SUM(CASE WHEN v.severity = 'Negligible'  THEN v.count ELSE 0 END), 0) as cves_negligible,
    COALESCE(SUM(CASE WHEN v.severity = 'Unknown'     THEN v.count ELSE 0 END), 0) as cves_unknown
FROM image_vulnerabilities v
JOIN images images ON v.image_id = images.id
WHERE images.digest = '%s'`, escapedDigest)

		vulnStatsResult, err := provider.ExecuteReadOnlyQuery(vulnStatsQuery)
		if err != nil {
			log.Error("error querying vuln stats", "digest", digest, "error", err)
			http.Error(w, fmt.Sprintf("Error querying vuln stats: %v", err), http.StatusInternalServerError)
			return
		}

		var totalRisk, totalCVEs, uniqueCVEs, totalExploits, uniqueExploits interface{}
		var cvesCritical, cvesHigh, cvesMedium, cvesLow, cvesNegligible, cvesUnknown interface{}
		if len(vulnStatsResult.Rows) > 0 {
			row := vulnStatsResult.Rows[0]
			totalRisk = row["total_risk"]
			totalCVEs = row["total_cves"]
			uniqueCVEs = row["unique_cves"]
			totalExploits = row["total_exploits"]
			uniqueExploits = row["unique_exploits"]
			cvesCritical = row["cves_critical"]
			cvesHigh = row["cves_high"]
			cvesMedium = row["cves_medium"]
			cvesLow = row["cves_low"]
			cvesNegligible = row["cves_negligible"]
			cvesUnknown = row["cves_unknown"]
		}

		// Get package summary stats
		pkgStatsQuery := fmt.Sprintf(`
SELECT
    COALESCE(SUM(p.number_of_instances), 0) as total_packages,
    COUNT(*) as unique_packages
FROM image_packages p
JOIN images images ON p.image_id = images.id
WHERE images.digest = '%s'`, escapedDigest)

		pkgStatsResult, err := provider.ExecuteReadOnlyQuery(pkgStatsQuery)
		if err != nil {
			log.Error("error querying package stats", "digest", digest, "error", err)
			http.Error(w, fmt.Sprintf("Error querying package stats: %v", err), http.StatusInternalServerError)
			return
		}

		var totalPackages, uniquePackages interface{}
		if len(pkgStatsResult.Rows) > 0 {
			row := pkgStatsResult.Rows[0]
			totalPackages = row["total_packages"]
			uniquePackages = row["unique_packages"]
		}

		response := map[string]interface{}{
			"image_id":            imageRow["image_id"],
			"references":          references,
			"containers":          containers,
			"distro_display_name": imageRow["distro_display_name"],
			"scan_status":         imageRow["scan_status"],
			"status_description":  imageRow["status_description"],
			"vulns_scanned_at":    imageRow["vulns_scanned_at"],
			"grype_db_built":      imageRow["grype_db_built"],
			"total_risk":          totalRisk,
			"total_cves":          totalCVEs,
			"unique_cves":         uniqueCVEs,
			"total_exploits":      totalExploits,
			"unique_exploits":     uniqueExploits,
			"total_packages":      totalPackages,
			"unique_packages":     uniquePackages,
			"cves_critical":       cvesCritical,
			"cves_high":           cvesHigh,
			"cves_medium":         cvesMedium,
			"cves_low":            cvesLow,
			"cves_negligible":     cvesNegligible,
			"cves_unknown":        cvesUnknown,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding image detail response", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// ImageVulnerabilitiesDetailHandler creates an HTTP handler for /api/images/{digest}/vulnerabilities endpoint
// Returns vulnerabilities for a specific image with filtering, sorting, and pagination
func ImageVulnerabilitiesDetailHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path
		path := r.URL.Path
		if len(path) <= 12 {
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		pathWithoutPrefix := path[12:]
		if len(pathWithoutPrefix) <= 16 || pathWithoutPrefix[len(pathWithoutPrefix)-16:] != "/vulnerabilities" {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		digest := pathWithoutPrefix[:len(pathWithoutPrefix)-16]

		// Parse query parameters
		params := r.URL.Query()

		// Export format
		format := params.Get("format")

		// Handle raw JSON export from Grype
		if format == "json" {
			exportRawVulnerabilitiesJSON(w, provider, digest)
			return
		}

		// Pagination (skip for CSV export - export all data)
		page, _ := strconv.Atoi(params.Get("page"))
		if page < 1 {
			page = 1
		}
		pageSize, _ := strconv.Atoi(params.Get("pageSize"))
		if pageSize < 1 || pageSize > 1000 {
			pageSize = 100
		}
		offset := (page - 1) * pageSize

		// For CSV export, get all results
		if format == "csv" {
			pageSize = -1
			offset = 0
		}

		// Filters
		severities := parseMultiSelect(params.Get("severity"))
		fixStatuses := parseMultiSelect(params.Get("fixStatus"))
		packageTypes := parseMultiSelect(params.Get("packageType"))

		// Sorting
		sortBy := params.Get("sortBy")
		sortOrder := params.Get("sortOrder")
		if sortOrder != "ASC" && sortOrder != "DESC" {
			sortOrder = "ASC"
		}

		// Build query
		query, countQuery := buildImageVulnerabilitiesQuery(digest, severities, fixStatuses, packageTypes, sortBy, sortOrder, pageSize, offset)

		// Execute count query for pagination
		countResult, err := provider.ExecuteReadOnlyQuery(countQuery)
		if err != nil {
			log.Error("error executing vulnerability count query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		totalCount := int64(0)
		if len(countResult.Rows) > 0 {
			if count, ok := countResult.Rows[0]["COUNT(*)"].(int64); ok {
				totalCount = count
			}
		}

		// Execute main query
		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Error("error executing vulnerability query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Handle CSV export
		if format == "csv" {
			exportQueryResultAsCSV(w, result, "vulnerabilities.csv")
			return
		}

		// Return JSON response
		totalPages := int(math.Ceil(float64(totalCount) / float64(pageSize)))
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"vulnerabilities": result.Rows,
			"page":            page,
			"pageSize":        pageSize,
			"totalCount":      totalCount,
			"totalPages":      totalPages,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding vulnerabilities response", "error", err)
		}
	}
}

// buildImageVulnerabilitiesQuery constructs the SQL query for image vulnerabilities
func buildImageVulnerabilitiesQuery(digest string, severities, fixStatuses, packageTypes []string, sortBy, sortOrder string, limit, offset int) (string, string) {
	escapedDigest := escapeSQL(digest)

	// Build WHERE conditions
	var conditions []string

	// Severity filter
	conditions = appendCondition(conditions, buildINClause("v.severity", severities))

	// Fix status filter
	conditions = appendCondition(conditions, buildINClause("v.fix_status", fixStatuses))

	// Package type filter
	conditions = appendCondition(conditions, buildINClause("v.package_type", packageTypes))

	whereClause := buildWhereClause(conditions)

	// Base query
	baseQuery := fmt.Sprintf(`
FROM image_vulnerabilities v
JOIN images images ON v.image_id = images.id
WHERE images.digest = '%s'%s`, escapedDigest, whereClause)

	// Build count query
	countQuery := "SELECT COUNT(*)" + baseQuery

	// Build main query with sorting
	selectClause := `SELECT
    v.id,
    v.cve_id as vulnerability_id,
    v.package_name as artifact_name,
    v.package_version as artifact_version,
    v.fixed_version as vulnerability_fix_versions,
    v.fix_status as vulnerability_fix_state,
    v.package_type as artifact_type,
    v.severity as vulnerability_severity,
    v.risk as vulnerability_risk,
    v.known_exploited as vulnerability_known_exploits,
    v.count as vulnerability_count`

	mainQuery := selectClause + baseQuery

	// Add sorting
	validSortColumns := map[string]bool{
		"vulnerability_severity": true, "vulnerability_id": true, "artifact_name": true,
		"artifact_version": true, "vulnerability_fix_versions": true, "vulnerability_fix_state": true,
		"artifact_type": true, "vulnerability_risk": true, "vulnerability_known_exploits": true,
		"vulnerability_count": true,
	}

	// Build multi-level sort:
	// 1. User-selected column (if any, and not severity/vulnerability)
	// 2. Severity (always, using CASE for proper priority)
	// 3. Vulnerability ID (always, for consistent tie-breaking)

	mainQuery += "\nORDER BY\n"

	severityCase := `    CASE v.severity
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        WHEN 'Low' THEN 4
        WHEN 'Negligible' THEN 5
        ELSE 6
    END`

	if sortBy != "" && validSortColumns[sortBy] {
		// Map UI column names to database columns
		dbColumn := sortBy
		switch sortBy {
		case "vulnerability_severity":
			// User clicked severity - it becomes primary, vulnerability becomes secondary
			mainQuery += severityCase + " " + sortOrder + ",\n"
			mainQuery += "    v.cve_id ASC"
			if limit > 0 {
				mainQuery += fmt.Sprintf("\nLIMIT %d OFFSET %d", limit, offset)
			}
			return mainQuery, countQuery
		case "vulnerability_id":
			// User clicked vulnerability - it becomes primary, severity becomes secondary
			mainQuery += "    v.cve_id " + sortOrder + ",\n"
			mainQuery += severityCase + " ASC"
			if limit > 0 {
				mainQuery += fmt.Sprintf("\nLIMIT %d OFFSET %d", limit, offset)
			}
			return mainQuery, countQuery
		case "artifact_name":
			dbColumn = "v.package_name"
		case "artifact_version":
			dbColumn = "v.package_version"
		case "vulnerability_fix_versions":
			dbColumn = "v.fixed_version"
		case "vulnerability_fix_state":
			dbColumn = "v.fix_status"
		case "artifact_type":
			dbColumn = "v.package_type"
		case "vulnerability_risk":
			dbColumn = "v.risk"
		case "vulnerability_known_exploits":
			dbColumn = "v.known_exploited"
		case "vulnerability_count":
			dbColumn = "v.count"
		}

		// User clicked a column: [column], severity, vulnerability
		mainQuery += fmt.Sprintf("    %s %s,\n", dbColumn, sortOrder)
		mainQuery += severityCase + " ASC,\n"
		mainQuery += "    v.cve_id ASC"
	} else {
		// Default: severity, vulnerability
		mainQuery += severityCase + " ASC,\n"
		mainQuery += "    v.cve_id ASC"
	}

	// Add pagination (skip if limit <= 0 for full export)
	if limit > 0 {
		mainQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}

	return mainQuery, countQuery
}


// exportRawVulnerabilitiesJSON exports the raw Grype vulnerability JSON for an image
func exportRawVulnerabilitiesJSON(w http.ResponseWriter, provider ImageQueryProvider, digest string) {
	data, err := provider.GetVulnerabilities(digest)
	if err != nil || len(data) == 0 {
		log.Error("error fetching raw vulnerabilities JSON", "error", err)
		http.Error(w, "No vulnerabilities data available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=grype-vulnerabilities.json")
	if _, err := w.Write(data); err != nil {
		log.Error("error writing vulnerabilities JSON", "error", err)
	}
}

// ImagePackagesDetailHandler creates an HTTP handler for /api/images/{digest}/packages endpoint
// Returns packages for a specific image with filtering, sorting, and pagination
func ImagePackagesDetailHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path
		path := r.URL.Path
		if len(path) <= 12 {
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		pathWithoutPrefix := path[12:]
		if len(pathWithoutPrefix) <= 9 || pathWithoutPrefix[len(pathWithoutPrefix)-9:] != "/packages" {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		digest := pathWithoutPrefix[:len(pathWithoutPrefix)-9]

		// Parse query parameters
		params := r.URL.Query()

		// Export format
		format := params.Get("format")

		// Handle raw JSON export from Syft
		if format == "json" {
			exportRawSBOMJSON(w, provider, digest)
			return
		}

		// Pagination (skip for CSV export - export all data)
		page, _ := strconv.Atoi(params.Get("page"))
		if page < 1 {
			page = 1
		}
		pageSize, _ := strconv.Atoi(params.Get("pageSize"))
		if pageSize < 1 || pageSize > 1000 {
			pageSize = 100
		}
		offset := (page - 1) * pageSize

		// For CSV export, get all results
		if format == "csv" {
			pageSize = -1
			offset = 0
		}

		// Filters
		packageTypes := parseMultiSelect(params.Get("type"))

		// Sorting
		sortBy := params.Get("sortBy")
		sortOrder := params.Get("sortOrder")
		if sortOrder != "ASC" && sortOrder != "DESC" {
			sortOrder = "ASC"
		}

		// Build query
		query, countQuery := buildImagePackagesQuery(digest, packageTypes, sortBy, sortOrder, pageSize, offset)

		// Execute count query for pagination
		countResult, err := provider.ExecuteReadOnlyQuery(countQuery)
		if err != nil {
			log.Error("error executing package count query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		totalCount := int64(0)
		if len(countResult.Rows) > 0 {
			if count, ok := countResult.Rows[0]["COUNT(*)"].(int64); ok {
				totalCount = count
			}
		}

		// Execute main query
		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Error("error executing package query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Handle CSV export
		if format == "csv" {
			exportQueryResultAsCSV(w, result, "packages.csv")
			return
		}

		// Return JSON response
		totalPages := int(math.Ceil(float64(totalCount) / float64(pageSize)))
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"packages":   result.Rows,
			"page":       page,
			"pageSize":   pageSize,
			"totalCount": totalCount,
			"totalPages": totalPages,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding packages response", "error", err)
		}
	}
}

// buildImagePackagesQuery constructs the SQL query for image packages
func buildImagePackagesQuery(digest string, packageTypes []string, sortBy, sortOrder string, limit, offset int) (string, string) {
	escapedDigest := escapeSQL(digest)

	// Build WHERE conditions
	var conditions []string

	// Package type filter
	conditions = appendCondition(conditions, buildINClause("p.type", packageTypes))

	whereClause := buildWhereClause(conditions)

	// Base query
	baseQuery := fmt.Sprintf(`
FROM image_packages p
JOIN images images ON p.image_id = images.id
WHERE images.digest = '%s'%s`, escapedDigest, whereClause)

	// Build count query
	countQuery := "SELECT COUNT(*)" + baseQuery

	// Build main query with sorting
	selectClause := `SELECT
    p.id,
    p.name,
    p.version,
    p.type,
    p.number_of_instances as count`

	mainQuery := selectClause + baseQuery

	// Add sorting with multi-level sort:
	// Default: name, version, type
	// User clicks column: that column, name, version, type (avoiding duplicates)
	validSortColumns := map[string]bool{
		"name": true, "version": true, "type": true, "count": true,
	}

	if sortBy != "" && validSortColumns[sortBy] {
		dbColumn := "p." + sortBy
		if sortBy == "count" {
			dbColumn = "p.number_of_instances"
		}
		mainQuery += fmt.Sprintf(" ORDER BY %s %s", dbColumn, sortOrder)

		// Add tie-breakers (avoiding duplicates)
		if sortBy != "name" {
			mainQuery += ", p.name ASC"
		}
		if sortBy != "version" {
			mainQuery += ", p.version ASC"
		}
		if sortBy != "type" {
			mainQuery += ", p.type ASC"
		}
	} else {
		mainQuery += " ORDER BY p.name ASC, p.version ASC, p.type ASC"
	}

	// Add pagination (skip if limit <= 0 for full export)
	if limit > 0 {
		mainQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}

	return mainQuery, countQuery
}


// ImageStatsHandler creates an HTTP handler for /api/images/{digest}/stats endpoint.
// Returns aggregate vulnerability and package stats, respecting severity/fixStatus/packageType filters.
func ImageStatsHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if len(path) <= 12 {
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		pathWithoutPrefix := path[12:]
		if len(pathWithoutPrefix) <= 6 || pathWithoutPrefix[len(pathWithoutPrefix)-6:] != "/stats" {
			http.Error(w, "Invalid path", http.StatusBadRequest)
			return
		}
		digest := pathWithoutPrefix[:len(pathWithoutPrefix)-6]
		escapedDigest := escapeSQL(digest)

		params := r.URL.Query()
		severities := parseMultiSelect(params.Get("severity"))
		fixStatuses := parseMultiSelect(params.Get("fixStatus"))
		packageTypes := parseMultiSelect(params.Get("packageType"))

		// Query 1: table-1 stats (total risk, CVEs, exploits) — all three filters applied
		var vulnConditions []string
		vulnConditions = appendCondition(vulnConditions, buildINClause("v.severity", severities))
		vulnConditions = appendCondition(vulnConditions, buildINClause("v.fix_status", fixStatuses))
		vulnConditions = appendCondition(vulnConditions, buildINClause("v.package_type", packageTypes))
		vulnWhere := buildWhereClause(vulnConditions)

		// unique_cves and unique_exploits dedupe by cve_id alone — see note in
		// the unfiltered handler above.
		vulnStatsQuery := fmt.Sprintf(`
SELECT
    COALESCE(SUM(v.risk * v.count), 0) as total_risk,
    COALESCE(SUM(v.count), 0) as total_cves,
    COUNT(DISTINCT v.cve_id) as unique_cves,
    COALESCE(SUM(v.known_exploited * v.count), 0) as total_exploits,
    COUNT(DISTINCT CASE WHEN v.known_exploited > 0 THEN v.cve_id END) as unique_exploits
FROM image_vulnerabilities v
JOIN images images ON v.image_id = images.id
WHERE images.digest = '%s'%s`, escapedDigest, vulnWhere)

		vulnResult, err := provider.ExecuteReadOnlyQuery(vulnStatsQuery)
		if err != nil {
			log.Error("error querying vuln stats", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Query 2: severity breakdown — same filters as query 1
		sevStatsQuery := fmt.Sprintf(`
SELECT
    COALESCE(SUM(CASE WHEN v.severity = 'Critical'   THEN v.count ELSE 0 END), 0) as cves_critical,
    COALESCE(SUM(CASE WHEN v.severity = 'High'       THEN v.count ELSE 0 END), 0) as cves_high,
    COALESCE(SUM(CASE WHEN v.severity = 'Medium'     THEN v.count ELSE 0 END), 0) as cves_medium,
    COALESCE(SUM(CASE WHEN v.severity = 'Low'        THEN v.count ELSE 0 END), 0) as cves_low,
    COALESCE(SUM(CASE WHEN v.severity = 'Negligible' THEN v.count ELSE 0 END), 0) as cves_negligible,
    COALESCE(SUM(CASE WHEN v.severity = 'Unknown'    THEN v.count ELSE 0 END), 0) as cves_unknown
FROM image_vulnerabilities v
JOIN images images ON v.image_id = images.id
WHERE images.digest = '%s'%s`, escapedDigest, vulnWhere)

		sevResult, err := provider.ExecuteReadOnlyQuery(sevStatsQuery)
		if err != nil {
			log.Error("error querying severity stats", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Query 3: package stats — packageType only
		var pkgConditions []string
		pkgConditions = appendCondition(pkgConditions, buildINClause("p.type", packageTypes))
		pkgWhere := buildWhereClause(pkgConditions)

		pkgStatsQuery := fmt.Sprintf(`
SELECT
    COALESCE(SUM(p.number_of_instances), 0) as total_packages,
    COUNT(*) as unique_packages
FROM image_packages p
JOIN images images ON p.image_id = images.id
WHERE images.digest = '%s'%s`, escapedDigest, pkgWhere)

		pkgResult, err := provider.ExecuteReadOnlyQuery(pkgStatsQuery)
		if err != nil {
			log.Error("error querying package stats", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{}
		if len(vulnResult.Rows) > 0 {
			for k, v := range vulnResult.Rows[0] {
				response[k] = v
			}
		}
		if len(sevResult.Rows) > 0 {
			for k, v := range sevResult.Rows[0] {
				response[k] = v
			}
		}
		if len(pkgResult.Rows) > 0 {
			for k, v := range pkgResult.Rows[0] {
				response[k] = v
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding stats response", "error", err)
		}
	}
}

// exportRawSBOMJSON exports the raw Syft SBOM JSON for an image
func exportRawSBOMJSON(w http.ResponseWriter, provider ImageQueryProvider, digest string) {
	data, err := provider.GetSBOM(digest)
	if err != nil || len(data) == 0 {
		log.Error("error fetching raw SBOM JSON", "error", err)
		http.Error(w, "No SBOM data available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=syft-sbom.json")
	if _, err := w.Write(data); err != nil {
		log.Error("error writing SBOM JSON", "error", err)
	}
}

// VulnerabilityDetailsHandler returns the full JSON details for a specific vulnerability
func VulnerabilityDetailsHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract vulnerability ID from URL path
		// Expected format: /api/vulnerabilities/{id}/details
		path := r.URL.Path
		log.Debug("vulnerability details handler", "path", path)

		// Remove "/api/vulnerabilities/" prefix (21 characters) and "/details" suffix (8 characters)
		// Minimum valid path is 29 chars (with 1-digit ID), so check for < 29
		if len(path) < 29 {
			log.Warn("path too short for vulnerability details", "length", len(path))
			http.Error(w, "Invalid vulnerability ID", http.StatusBadRequest)
			return
		}

		vulnIDStr := path[21 : len(path)-8] // Extract ID from path (21 = length of "/api/vulnerabilities/")
		log.Debug("extracted vulnerability ID", "id_string", vulnIDStr)

		// Validate that the ID is a valid integer
		vulnID, err := strconv.ParseInt(vulnIDStr, 10, 64)
		if err != nil {
			log.Warn("invalid vulnerability ID format", "id_string", vulnIDStr, "error", err)
			http.Error(w, "Invalid vulnerability ID format", http.StatusBadRequest)
			return
		}

		log.Debug("fetching vulnerability details", "vulnerability_id", vulnID)

		// Query image_vulnerability_details table
		query := fmt.Sprintf(`
			SELECT vd.details
			FROM image_vulnerability_details vd
			WHERE vd.vulnerability_id = %d`, vulnID)

		log.Debug("executing vulnerability query", "query", query)

		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Error("error fetching vulnerability details", "error", err)
			http.Error(w, "Failed to fetch vulnerability details", http.StatusInternalServerError)
			return
		}

		log.Debug("vulnerability query returned rows", "count", len(result.Rows))

		if len(result.Rows) == 0 {
			log.Warn("no vulnerability details found", "vulnerability_id", vulnID)
			http.Error(w, "Vulnerability details not found", http.StatusNotFound)
			return
		}

		detailsJSON, ok := result.Rows[0]["details"].(string)
		if !ok || detailsJSON == "" {
			log.Warn("vulnerability details field is empty or wrong type")
			http.Error(w, "No details available", http.StatusNotFound)
			return
		}

		log.Debug("returning vulnerability details", "size_bytes", len(detailsJSON))
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(detailsJSON)); err != nil {
			log.Error("error writing vulnerability details", "error", err)
		}
	}
}

// PackageDetailsHandler returns the full JSON details for a specific package
func PackageDetailsHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract package ID from URL path
		// Expected format: /api/packages/{id}/details
		path := r.URL.Path
		log.Debug("package details handler", "path", path)

		// Remove "/api/packages/" prefix (14 characters) and "/details" suffix (8 characters)
		// Minimum valid path is 22 chars (with 1-digit ID), so check for < 22
		if len(path) < 22 {
			log.Warn("path too short for package details", "length", len(path))
			http.Error(w, "Invalid package ID", http.StatusBadRequest)
			return
		}

		pkgIDStr := path[14 : len(path)-8] // Extract ID from path
		log.Debug("extracted package ID", "id_string", pkgIDStr)

		// Validate that the ID is a valid integer
		pkgID, err := strconv.ParseInt(pkgIDStr, 10, 64)
		if err != nil {
			log.Warn("invalid package ID format", "id_string", pkgIDStr, "error", err)
			http.Error(w, "Invalid package ID format", http.StatusBadRequest)
			return
		}

		log.Debug("fetching package details", "package_id", pkgID)

		// Query image_package_details table
		query := fmt.Sprintf(`
			SELECT pd.details
			FROM image_package_details pd
			WHERE pd.package_id = %d`, pkgID)

		log.Debug("executing package query", "query", query)

		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Error("error fetching package details", "error", err)
			http.Error(w, "Failed to fetch package details", http.StatusInternalServerError)
			return
		}

		log.Debug("package query returned rows", "count", len(result.Rows))

		if len(result.Rows) == 0 {
			log.Warn("no package details found", "package_id", pkgID)
			http.Error(w, "Package details not found", http.StatusNotFound)
			return
		}

		detailsJSON, ok := result.Rows[0]["details"].(string)
		if !ok || detailsJSON == "" {
			log.Warn("package details field is empty or wrong type")
			http.Error(w, "No details available", http.StatusNotFound)
			return
		}

		log.Debug("returning package details", "size_bytes", len(detailsJSON))
		w.Header().Set("Content-Type", "application/json")
		if _, err := w.Write([]byte(detailsJSON)); err != nil {
			log.Error("error writing package details", "error", err)
		}
	}
}
