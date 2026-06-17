package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
)


// buildDeploymentMetricsQuery constructs the SQL for /api/summary/deployment-metrics.
//
// Structure:
//   vuln_agg  — aggregate total CVE count and exploit count per image from
//               vulnerabilities; uses idx_vulnerabilities_image for the GROUP BY
//   ctr_agg   — count containers per image (optionally filtered by namespace);
//               uses idx_containers_image
//   img_stats — join images → ctr_agg → vuln_agg, keeping only images that have
//               at least one running container (INNER JOIN ctr_agg); optionally
//               filtered by os_name
//
// The outer SELECT makes a single aggregation pass over img_stats.
// unique_cves uses a correlated subquery over the materialized img_stats CTE;
// the COUNT(DISTINCT cve_id) WHERE image_id IN (...) is served from the covering
// index idx_vulnerabilities_image_cve (image_id, cve_id) without touching table rows.
//
// When all filter slices are empty the generated SQL is equivalent to the
// original unfiltered query.
func buildDeploymentMetricsQuery(namespaces, vulnStatuses, packageTypes, osNames, severities []string) string {
	// vuln_agg WHERE: fix_status, package_type, and severity. Severity is the
	// CVE pages' filter; the summary must reflect it like the other vuln filters.
	var vulnConds []string
	if c := buildINClause("fix_status", vulnStatuses); c != "" {
		vulnConds = append(vulnConds, c)
	}
	if c := buildINClause("package_type", packageTypes); c != "" {
		vulnConds = append(vulnConds, c)
	}
	if c := buildINClause("severity", severities); c != "" {
		vulnConds = append(vulnConds, c)
	}
	vulnFilter := ""
	if len(vulnConds) > 0 {
		vulnFilter = "WHERE " + strings.Join(vulnConds, " AND ")
	}

	nsFilter := ""
	if c := buildINClause("namespace", namespaces); c != "" {
		nsFilter = "WHERE " + c
	}

	imgStatsWhere := ""
	if c := buildINClause("i.os_name", osNames); c != "" {
		imgStatsWhere = "WHERE " + c
	}

	containerInstancesExpr := "SELECT COUNT(*) FROM containers"
	if nsFilter != "" {
		containerInstancesExpr += " " + nsFilter
	}

	// unique_cves subquery applies the same vuln filters plus the image_id set
	var uniqueCVEsConds []string
	if c := buildINClause("fix_status", vulnStatuses); c != "" {
		uniqueCVEsConds = append(uniqueCVEsConds, c)
	}
	if c := buildINClause("package_type", packageTypes); c != "" {
		uniqueCVEsConds = append(uniqueCVEsConds, c)
	}
	if c := buildINClause("severity", severities); c != "" {
		uniqueCVEsConds = append(uniqueCVEsConds, c)
	}
	uniqueCVEsConds = append(uniqueCVEsConds,
		"image_id IN (SELECT id FROM img_stats WHERE status = 'completed')")
	uniqueCVEsWhere := "WHERE " + strings.Join(uniqueCVEsConds, "\n   AND ")

	return fmt.Sprintf(`WITH
  vuln_agg AS (
    SELECT
      image_id,
      SUM(count)                   AS total_cves,
      SUM(known_exploited * count) AS total_exploits
    FROM image_vulnerabilities
    %s
    GROUP BY image_id
  ),
  ctr_agg AS (
    SELECT image_id, COUNT(*) AS cnt
    FROM containers
    %s
    GROUP BY image_id
  ),
  img_stats AS (
    SELECT
      i.id,
      i.status,
      c.cnt,
      COALESCE(v.total_cves,    0) AS img_cves,
      COALESCE(v.total_exploits,0) AS img_exploits
    FROM images i
    JOIN  ctr_agg  c ON c.image_id = i.id
    LEFT JOIN vuln_agg v ON v.image_id = i.id
    %s
  )
SELECT
  (%s)                                                                                               AS container_instances,
  COALESCE(SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END), 0)                                AS images_scanned,
  COALESCE(SUM(CASE WHEN status = 'completed' THEN cnt * img_cves    END), 0)                       AS total_cves,
  (SELECT COUNT(DISTINCT cve_id) FROM image_vulnerabilities
   %s)                                                                                              AS unique_cves,
  COALESCE(SUM(CASE WHEN status = 'completed' THEN cnt * img_exploits END), 0)                      AS total_exploits,
  COALESCE(SUM(CASE WHEN status NOT IN ('completed','sbom_failed','vuln_scan_failed') THEN 1 ELSE 0 END), 0) AS images_pending,
  COALESCE(SUM(CASE WHEN status IN ('sbom_failed','vuln_scan_failed') THEN 1 ELSE 0 END), 0)        AS images_failed
FROM img_stats
`, vulnFilter, nsFilter, imgStatsWhere, containerInstancesExpr, uniqueCVEsWhere)
}

// DeploymentMetricsHandler returns a single-row JSON summary of the deployment,
// optionally filtered by the same query parameters accepted by /api/images.
// Endpoint: GET /api/summary/deployment-metrics
func DeploymentMetricsHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()
		namespaces := parseMultiSelect(params.Get("namespaces"))
		vulnStatuses := parseMultiSelect(params.Get("vulnStatuses"))
		packageTypes := parseMultiSelect(params.Get("packageTypes"))
		osNames := parseMultiSelect(params.Get("osNames"))
		severities := parseMultiSelect(params.Get("severity"))

		query := buildDeploymentMetricsQuery(namespaces, vulnStatuses, packageTypes, osNames, severities)
		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Error("error executing deployment metrics query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		type DeploymentMetrics struct {
			ContainerInstances int64 `json:"container_instances"`
			ImagesScanned      int64 `json:"images_scanned"`
			TotalCVEs          int64 `json:"total_cves"`
			UniqueCVEs         int64 `json:"unique_cves"`
			TotalExploits      int64 `json:"total_exploits"`
			ImagesPending      int64 `json:"images_pending,omitempty"`
			ImagesFailed       int64 `json:"images_failed,omitempty"`
		}

		metrics := DeploymentMetrics{}
		if len(result.Rows) > 0 {
			row := result.Rows[0]
			metrics.ContainerInstances = getInt64Value(row, "container_instances")
			metrics.ImagesScanned = getInt64Value(row, "images_scanned")
			metrics.TotalCVEs = getInt64Value(row, "total_cves")
			metrics.UniqueCVEs = getInt64Value(row, "unique_cves")
			metrics.TotalExploits = getInt64Value(row, "total_exploits")
			metrics.ImagesPending = getInt64Value(row, "images_pending")
			metrics.ImagesFailed = getInt64Value(row, "images_failed")
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(metrics); err != nil {
			log.Error("error encoding deployment metrics response", "error", err)
		}
	}
}

// buildNodeMetricsQuery constructs the SQL for /api/summary/node-metrics.
//
// Structure:
//   completed — IDs of nodes with status 'completed', optionally filtered by os_release
//   vuln_agg  — total CVE count, exploit count, and unique CVE count in a single pass;
//               optionally filtered by fix_status and/or package type
//
// unique_cves is computed inside vuln_agg (COUNT(DISTINCT cve_id)) to avoid a
// second scan of node_vulnerabilities. Previously it was a separate scalar subquery.
//
// When all filter slices are empty the generated SQL is equivalent to the
// original unfiltered query.
func buildNodeMetricsQuery(osNames, vulnStatuses, packageTypes, severities []string) string {
	// completed CTE: filter by os_release
	osFilter := ""
	if c := buildINClause("os_release", osNames); c != "" {
		osFilter = " AND " + c
	}

	// vuln_agg filters: fix_status and package type
	// unique_cves is computed in the same CTE to avoid a second scan of node_vulnerabilities
	var nvConds []string
	if c := buildINClause("nv.fix_status", vulnStatuses); c != "" {
		nvConds = append(nvConds, c)
	}
	pkgJoin := ""
	if c := buildINClause("np.type", packageTypes); c != "" {
		pkgJoin = "\n    JOIN node_packages np ON nv.package_id = np.id"
		nvConds = append(nvConds, c)
	}
	if c := buildINClause("nv.severity", severities); c != "" {
		nvConds = append(nvConds, c)
	}
	nvExtraWhere := ""
	if len(nvConds) > 0 {
		nvExtraWhere = "\n    AND " + strings.Join(nvConds, "\n    AND ")
	}

	return fmt.Sprintf(`WITH
  completed AS (
    SELECT id FROM nodes WHERE status = 'completed'%s
  ),
  vuln_agg AS (
    SELECT
      COALESCE(SUM(nv.count),                      0) AS total_cves,
      COALESCE(SUM(nv.known_exploited * nv.count), 0) AS total_exploits,
      COUNT(DISTINCT nv.cve_id)                        AS unique_cves
    FROM node_vulnerabilities nv%s
    WHERE nv.node_id IN (SELECT id FROM completed)%s
  )
SELECT
  (SELECT COUNT(*) FROM nodes WHERE 1=1%s)                                     AS total_nodes,
  v.total_cves,
  v.unique_cves,
  v.total_exploits,
  (SELECT COUNT(*) FROM nodes
   WHERE status NOT IN ('completed','sbom_failed','vuln_scan_failed')%s)       AS nodes_pending,
  (SELECT COUNT(*) FROM nodes
   WHERE status IN ('sbom_failed','vuln_scan_failed')%s)                       AS nodes_failed
FROM vuln_agg v
`, osFilter, pkgJoin, nvExtraWhere, osFilter, osFilter, osFilter)
}

// NodeMetricsSummaryHandler returns a single-row JSON summary of node scan results.
// Endpoint: GET /api/summary/node-metrics
// Accepts optional filter params: osNames, vulnStatuses, packageTypes
func NodeMetricsSummaryHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()
		osNames := parseMultiSelect(params.Get("osNames"))
		vulnStatuses := parseMultiSelect(params.Get("vulnStatuses"))
		packageTypes := parseMultiSelect(params.Get("packageTypes"))
		severities := parseMultiSelect(params.Get("severity"))

		query := buildNodeMetricsQuery(osNames, vulnStatuses, packageTypes, severities)
		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Error("error executing node metrics query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		type NodeMetrics struct {
			TotalNodes    int64 `json:"total_nodes"`
			TotalCVEs     int64 `json:"total_cves"`
			UniqueCVEs    int64 `json:"unique_cves"`
			TotalExploits int64 `json:"total_exploits"`
			NodesPending  int64 `json:"nodes_pending,omitempty"`
			NodesFailed   int64 `json:"nodes_failed,omitempty"`
		}

		metrics := NodeMetrics{}
		if len(result.Rows) > 0 {
			row := result.Rows[0]
			metrics.TotalNodes = getInt64Value(row, "total_nodes")
			metrics.TotalCVEs = getInt64Value(row, "total_cves")
			metrics.UniqueCVEs = getInt64Value(row, "unique_cves")
			metrics.TotalExploits = getInt64Value(row, "total_exploits")
			metrics.NodesPending = getInt64Value(row, "nodes_pending")
			metrics.NodesFailed = getInt64Value(row, "nodes_failed")
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(metrics); err != nil {
			log.Error("error encoding node metrics response", "error", err)
		}
	}
}

// NamespaceSummaryHandler creates an HTTP handler for /api/summary/by-namespace endpoint
// Returns namespace-level vulnerability aggregations (averages per container)
func NamespaceSummaryHandler(provider ImageQueryProvider) http.HandlerFunc {
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
			pageSize = 100
		}
		offset := (page - 1) * pageSize

		// For CSV export, get all results
		if format == "csv" {
			pageSize = -1
			offset = 0
		}

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
		query, countQuery := buildNamespaceSummaryQuery(namespaces, vulnStatuses, packageTypes, osNames, sortBy, sortOrder, pageSize, offset)

		// Execute count query for pagination
		countResult, err := provider.ExecuteReadOnlyQuery(countQuery)
		if err != nil {
			log.Error("error executing namespace count query", "error", err)
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
			log.Error("error executing namespace summary query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Parse results
		namespaceData := make([]map[string]interface{}, 0, len(result.Rows))
		for _, row := range result.Rows {
			namespaceData = append(namespaceData, map[string]interface{}{
				"namespace":        getStringValue(row, "namespace"),
				"container_count":   getIntValue(row, "container_count"),
				"avg_critical":     roundToOne(getFloatValue(row, "avg_critical")),
				"avg_high":         roundToOne(getFloatValue(row, "avg_high")),
				"avg_medium":       roundToOne(getFloatValue(row, "avg_medium")),
				"avg_low":          roundToOne(getFloatValue(row, "avg_low")),
				"avg_negligible":   roundToOne(getFloatValue(row, "avg_negligible")),
				"avg_unknown":      roundToOne(getFloatValue(row, "avg_unknown")),
				"avg_risk":         roundToOne(getFloatValue(row, "avg_risk")),
				"avg_exploits":     roundToOne(getFloatValue(row, "avg_exploits")),
				"avg_packages":     roundToOne(getFloatValue(row, "avg_packages")),
			})
		}

		// Handle CSV export
		if format == "csv" {
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", "attachment; filename=namespace_summary.csv")

			writer := csv.NewWriter(w)
			defer writer.Flush()

			// Write header
			if err := writer.Write([]string{
				"Namespace", "Containers", "Avg Critical", "Avg High", "Avg Medium",
				"Avg Low", "Avg Negligible", "Avg Unknown", "Avg Risk Score", "Avg Exploits", "Avg Packages",
			}); err != nil {
				log.Error("error writing CSV header", "error", err)
				http.Error(w, "Error generating CSV", http.StatusInternalServerError)
				return
			}

			// Write data
			for _, item := range namespaceData {
				if err := writer.Write([]string{
					fmt.Sprintf("%v", item["namespace"]),
					fmt.Sprintf("%v", item["container_count"]),
					fmt.Sprintf("%.1f", item["avg_critical"]),
					fmt.Sprintf("%.1f", item["avg_high"]),
					fmt.Sprintf("%.1f", item["avg_medium"]),
					fmt.Sprintf("%.1f", item["avg_low"]),
					fmt.Sprintf("%.1f", item["avg_negligible"]),
					fmt.Sprintf("%.1f", item["avg_unknown"]),
					fmt.Sprintf("%.1f", item["avg_risk"]),
					fmt.Sprintf("%.1f", item["avg_exploits"]),
					fmt.Sprintf("%.1f", item["avg_packages"]),
				}); err != nil {
					log.Error("error writing CSV row", "error", err)
					http.Error(w, "Error generating CSV", http.StatusInternalServerError)
					return
				}
			}
			return
		}

		// Return JSON response
		totalPages := int(math.Ceil(float64(totalCount) / float64(pageSize)))
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"namespaces": namespaceData,
			"page":       page,
			"pageSize":   pageSize,
			"totalCount": totalCount,
			"totalPages": totalPages,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding namespace summary response", "error", err)
		}
	}
}

// buildNamespaceSummaryQuery constructs the SQL query for namespace-level aggregations
func buildNamespaceSummaryQuery(namespaces, vulnStatuses, packageTypes, osNames []string, sortBy, sortOrder string, limit, offset int) (string, string) {
	// Build subquery filters using helper functions
	packageTypeFilter := buildPackageTypeFilter(packageTypes)
	vulnStatusFilter := buildVulnerabilityFilter(vulnStatuses, packageTypes)

	// Base query with subqueries
	baseQuery := fmt.Sprintf(`
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
        SUM(risk * count) as total_risk,
        SUM(known_exploited * count) as exploit_count
    FROM image_vulnerabilities
    %s
    GROUP BY image_id
) vuln_counts ON images.id = vuln_counts.image_id
WHERE status.status = 'completed'`, packageTypeFilter, vulnStatusFilter)

	// Build WHERE conditions
	var conditions []string

	// Namespace filter
	conditions = appendCondition(conditions, buildINClause("instances.namespace", namespaces))

	// OS name filter
	conditions = appendCondition(conditions, buildINClause("images.os_name", osNames))

	// Add conditions to base query
	whereClause := baseQuery + buildWhereClause(conditions)

	// Group by
	groupBy := " GROUP BY instances.namespace"

	// Build count query
	countQuery := "SELECT COUNT(*) FROM (" +
		"SELECT instances.namespace" +
		whereClause +
		groupBy +
		") subquery"

	// Build main query with sorting
	selectClause := `SELECT
    instances.namespace,
    COUNT(DISTINCT instances.id) as container_count,
    AVG(COALESCE(vuln_counts.critical_count, 0)) as avg_critical,
    AVG(COALESCE(vuln_counts.high_count, 0)) as avg_high,
    AVG(COALESCE(vuln_counts.medium_count, 0)) as avg_medium,
    AVG(COALESCE(vuln_counts.low_count, 0)) as avg_low,
    AVG(COALESCE(vuln_counts.negligible_count, 0)) as avg_negligible,
    AVG(COALESCE(vuln_counts.unknown_count, 0)) as avg_unknown,
    AVG(COALESCE(vuln_counts.total_risk, 0)) as avg_risk,
    AVG(COALESCE(vuln_counts.exploit_count, 0)) as avg_exploits,
    AVG(COALESCE(pkg_counts.package_count, 0)) as avg_packages`

	mainQuery := selectClause + whereClause + groupBy

	// Add sorting with namespace as secondary sort
	validSortColumns := map[string]bool{
		"namespace": true, "container_count": true, "avg_critical": true,
		"avg_high": true, "avg_medium": true, "avg_low": true,
		"avg_negligible": true, "avg_unknown": true, "avg_risk": true,
		"avg_exploits": true, "avg_packages": true,
	}

	if sortBy != "" && validSortColumns[sortBy] {
		mainQuery += fmt.Sprintf(" ORDER BY %s %s", sortBy, sortOrder)
		// Add namespace as secondary sort (for tie-breaking), unless it's the primary sort
		if sortBy != "namespace" {
			mainQuery += ", namespace ASC"
		}
	} else {
		mainQuery += " ORDER BY namespace ASC"
	}

	// Add pagination (skip if limit <= 0 for full export)
	if limit > 0 {
		mainQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}

	return mainQuery, countQuery
}

// DistributionSummaryHandler creates an HTTP handler for /api/summary/by-distribution endpoint
// Returns OS distribution-level vulnerability aggregations (averages per container)
func DistributionSummaryHandler(provider ImageQueryProvider) http.HandlerFunc {
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
			pageSize = 100
		}
		offset := (page - 1) * pageSize

		// For CSV export, get all results
		if format == "csv" {
			pageSize = -1
			offset = 0
		}

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
		query, countQuery := buildDistributionSummaryQuery(namespaces, vulnStatuses, packageTypes, osNames, sortBy, sortOrder, pageSize, offset)

		// Execute count query for pagination
		countResult, err := provider.ExecuteReadOnlyQuery(countQuery)
		if err != nil {
			log.Error("error executing distribution count query", "error", err)
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
			log.Error("error executing distribution summary query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Parse results
		distributionData := make([]map[string]interface{}, 0, len(result.Rows))
		for _, row := range result.Rows {
			distributionData = append(distributionData, map[string]interface{}{
				"os_name":          getStringValue(row, "os_name"),
				"container_count":   getIntValue(row, "container_count"),
				"avg_critical":     roundToOne(getFloatValue(row, "avg_critical")),
				"avg_high":         roundToOne(getFloatValue(row, "avg_high")),
				"avg_medium":       roundToOne(getFloatValue(row, "avg_medium")),
				"avg_low":          roundToOne(getFloatValue(row, "avg_low")),
				"avg_negligible":   roundToOne(getFloatValue(row, "avg_negligible")),
				"avg_unknown":      roundToOne(getFloatValue(row, "avg_unknown")),
				"avg_risk":         roundToOne(getFloatValue(row, "avg_risk")),
				"avg_exploits":     roundToOne(getFloatValue(row, "avg_exploits")),
				"avg_packages":     roundToOne(getFloatValue(row, "avg_packages")),
			})
		}

		// Handle CSV export
		if format == "csv" {
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", "attachment; filename=distribution_summary.csv")

			writer := csv.NewWriter(w)
			defer writer.Flush()

			// Write header
			if err := writer.Write([]string{
				"OS Distribution", "Containers", "Avg Critical", "Avg High", "Avg Medium",
				"Avg Low", "Avg Negligible", "Avg Unknown", "Avg Risk Score", "Avg Exploits", "Avg Packages",
			}); err != nil {
				log.Error("error writing CSV header", "error", err)
				http.Error(w, "Error generating CSV", http.StatusInternalServerError)
				return
			}

			// Write data
			for _, item := range distributionData {
				if err := writer.Write([]string{
					fmt.Sprintf("%v", item["os_name"]),
					fmt.Sprintf("%v", item["container_count"]),
					fmt.Sprintf("%.1f", item["avg_critical"]),
					fmt.Sprintf("%.1f", item["avg_high"]),
					fmt.Sprintf("%.1f", item["avg_medium"]),
					fmt.Sprintf("%.1f", item["avg_low"]),
					fmt.Sprintf("%.1f", item["avg_negligible"]),
					fmt.Sprintf("%.1f", item["avg_unknown"]),
					fmt.Sprintf("%.1f", item["avg_risk"]),
					fmt.Sprintf("%.1f", item["avg_exploits"]),
					fmt.Sprintf("%.1f", item["avg_packages"]),
				}); err != nil {
					log.Error("error writing CSV row", "error", err)
					http.Error(w, "Error generating CSV", http.StatusInternalServerError)
					return
				}
			}
			return
		}

		// Return JSON response
		totalPages := int(math.Ceil(float64(totalCount) / float64(pageSize)))
		w.Header().Set("Content-Type", "application/json")
		response := map[string]interface{}{
			"distributions": distributionData,
			"page":          page,
			"pageSize":      pageSize,
			"totalCount":    totalCount,
			"totalPages":    totalPages,
		}
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding distribution summary response", "error", err)
		}
	}
}

// buildDistributionSummaryQuery constructs the SQL query for distribution-level aggregations
func buildDistributionSummaryQuery(namespaces, vulnStatuses, packageTypes, osNames []string, sortBy, sortOrder string, limit, offset int) (string, string) {
	// Build subquery filters using helper functions
	packageTypeFilter := buildPackageTypeFilter(packageTypes)
	vulnStatusFilter := buildVulnerabilityFilter(vulnStatuses, packageTypes)

	// Base query with subqueries
	baseQuery := fmt.Sprintf(`
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
        SUM(risk * count) as total_risk,
        SUM(known_exploited * count) as exploit_count
    FROM image_vulnerabilities
    %s
    GROUP BY image_id
) vuln_counts ON images.id = vuln_counts.image_id
WHERE status.status = 'completed'
  AND images.os_name IS NOT NULL
  AND images.os_name != ''`, packageTypeFilter, vulnStatusFilter)

	// Build WHERE conditions
	var conditions []string

	// Namespace filter
	conditions = appendCondition(conditions, buildINClause("instances.namespace", namespaces))

	// OS name filter
	conditions = appendCondition(conditions, buildINClause("images.os_name", osNames))

	// Add conditions to base query
	whereClause := baseQuery + buildWhereClause(conditions)

	// Group by
	groupBy := " GROUP BY images.os_name"

	// Build count query
	countQuery := "SELECT COUNT(*) FROM (" +
		"SELECT images.os_name" +
		whereClause +
		groupBy +
		") subquery"

	// Build main query with sorting
	selectClause := `SELECT
    images.os_name,
    COUNT(DISTINCT instances.id) as container_count,
    AVG(COALESCE(vuln_counts.critical_count, 0)) as avg_critical,
    AVG(COALESCE(vuln_counts.high_count, 0)) as avg_high,
    AVG(COALESCE(vuln_counts.medium_count, 0)) as avg_medium,
    AVG(COALESCE(vuln_counts.low_count, 0)) as avg_low,
    AVG(COALESCE(vuln_counts.negligible_count, 0)) as avg_negligible,
    AVG(COALESCE(vuln_counts.unknown_count, 0)) as avg_unknown,
    AVG(COALESCE(vuln_counts.total_risk, 0)) as avg_risk,
    AVG(COALESCE(vuln_counts.exploit_count, 0)) as avg_exploits,
    AVG(COALESCE(pkg_counts.package_count, 0)) as avg_packages`

	mainQuery := selectClause + whereClause + groupBy

	// Add sorting with os_name as secondary sort
	validSortColumns := map[string]bool{
		"os_name": true, "container_count": true, "avg_critical": true,
		"avg_high": true, "avg_medium": true, "avg_low": true,
		"avg_negligible": true, "avg_unknown": true, "avg_risk": true,
		"avg_exploits": true, "avg_packages": true,
	}

	if sortBy != "" && validSortColumns[sortBy] {
		mainQuery += fmt.Sprintf(" ORDER BY %s %s", sortBy, sortOrder)
		// Add os_name as secondary sort (for tie-breaking), unless it's the primary sort
		if sortBy != "os_name" {
			mainQuery += ", os_name ASC"
		}
	} else {
		mainQuery += " ORDER BY os_name ASC"
	}

	// Add pagination (skip if limit <= 0 for full export)
	if limit > 0 {
		mainQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", limit, offset)
	}

	return mainQuery, countQuery
}

// Helper functions

func getInt64Value(row map[string]interface{}, key string) int64 {
	if val, ok := row[key].(int64); ok {
		return val
	}
	return 0
}

func getStringValue(row map[string]interface{}, key string) string {
	if val, ok := row[key].(string); ok {
		return val
	}
	return ""
}

func getIntValue(row map[string]interface{}, key string) int {
	if val, ok := row[key].(int64); ok {
		return int(val)
	}
	return 0
}

func getFloatValue(row map[string]interface{}, key string) float64 {
	if val, ok := row[key].(float64); ok {
		return val
	}
	if val, ok := row[key].(int64); ok {
		return float64(val)
	}
	return 0
}

func roundToOne(val float64) float64 {
	return math.Round(val*10) / 10
}
