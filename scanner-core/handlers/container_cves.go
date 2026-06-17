package handlers

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
)

// ContainerCVEsHandler creates an HTTP handler for the /api/container-cves endpoint.
//
// It returns a deployment-wide, deduplicated CVE listing across all running
// containers: one row per unique (cve_id, package_name, package_version,
// fixed_version, fix_status, package_type, severity). The count column reports
// the number of distinct affected container instances, not per-image
// occurrences. Only images that have at least one running container are
// included (enforced by the JOIN on the containers table).
func ContainerCVEsHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()

		// Export format (csv only; no JSON export for this listing)
		format := params.Get("format")

		// Pagination (skip for CSV export - export all data)
		page, _ := strconv.Atoi(params.Get("page"))
		if page < 1 {
			page = 1
		}
		pageSize, _ := strconv.Atoi(params.Get("pageSize"))
		if pageSize < 1 || pageSize > 10000 {
			pageSize = 100
		}
		offset := (page - 1) * pageSize

		// For CSV export, get all results
		if format == "csv" {
			pageSize = -1
			offset = 0
		}

		// Filters (multiselect - comma separated). Param names mirror the rest of
		// the app (namespaces/vulnStatuses/packageTypes/osNames) so the shared
		// summary strip and cross-page nav filters apply unchanged; severity is the
		// one extra filter specific to the CVE listing.
		namespaces := parseMultiSelect(params.Get("namespaces"))
		osNames := parseMultiSelect(params.Get("osNames"))
		severities := parseMultiSelect(params.Get("severity"))
		fixStatuses := parseMultiSelect(params.Get("vulnStatuses"))
		packageTypes := parseMultiSelect(params.Get("packageTypes"))

		// Sorting
		sortBy := params.Get("sortBy")
		sortOrder := params.Get("sortOrder")
		if sortOrder != "ASC" && sortOrder != "DESC" {
			sortOrder = "ASC"
		}

		// Build query
		query, countQuery := buildContainerCVEsQuery(namespaces, osNames, severities, fixStatuses, packageTypes, sortBy, sortOrder, pageSize, offset)

		// Execute count query for pagination
		countResult, err := provider.ExecuteReadOnlyQuery(countQuery)
		if err != nil {
			log.Error("error executing container CVE count query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		totalCount := int64(0)
		if len(countResult.Rows) > 0 && len(countResult.Columns) > 0 {
			if count, ok := countResult.Rows[0][countResult.Columns[0]].(int64); ok {
				totalCount = count
			}
		}

		// Execute main query
		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Error("error executing container CVE query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Handle CSV export
		if format == "csv" {
			exportQueryResultAsCSV(w, result, "container_cves.csv")
			return
		}

		// Return JSON response
		totalPages := 0
		if pageSize > 0 {
			totalPages = int(math.Ceil(float64(totalCount) / float64(pageSize)))
		}
		response := map[string]interface{}{
			"cves":       result.Rows,
			"page":       page,
			"pageSize":   pageSize,
			"totalCount": totalCount,
			"totalPages": totalPages,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding container CVEs response", "error", err)
		}
	}
}

// buildContainerCVEsQuery builds the deduplicated deployment-wide container CVE
// query and its matching count query.
//
// Rows are grouped by (cve_id, package_name, package_version, fixed_version,
// fix_status, package_type, severity); vulnerability_count reports the number of
// distinct affected container instances. The column aliases match the per-image
// vulnerabilities listing (image.html / buildImageVulnerabilitiesQuery) so the
// frontend table can be shared.
func buildContainerCVEsQuery(namespaces, osNames, severities, fixStatuses, packageTypes []string, sortBy, sortOrder string, limit, offset int) (string, string) {
	// Build WHERE conditions
	var conditions []string
	conditions = appendCondition(conditions, buildINClause("c.namespace", namespaces))
	conditions = appendCondition(conditions, buildINClause("i.os_name", osNames))
	conditions = appendCondition(conditions, buildINClause("v.severity", severities))
	conditions = appendCondition(conditions, buildINClause("v.fix_status", fixStatuses))
	conditions = appendCondition(conditions, buildINClause("v.package_type", packageTypes))
	whereClause := buildWhereClause(conditions)

	// Base query: every CVE row that is present in an image with >=1 running
	// container. The JOIN on containers both scopes the result to deployed
	// images and provides the affected-container count.
	baseQuery := fmt.Sprintf(`
FROM image_vulnerabilities v
JOIN images i ON v.image_id = i.id
JOIN containers c ON c.image_id = i.id
WHERE 1=1%s`, whereClause)

	groupBy := `
GROUP BY v.cve_id, v.package_name, v.package_version, v.fixed_version, v.fix_status, v.package_type, v.severity`

	// Count query: number of distinct CVE rows after grouping.
	countQuery := "SELECT COUNT(*) FROM (SELECT 1" + baseQuery + groupBy + ") sub"

	selectClause := `SELECT
    MAX(v.id) as id,
    v.cve_id as vulnerability_id,
    v.package_name as artifact_name,
    v.package_version as artifact_version,
    v.fixed_version as vulnerability_fix_versions,
    v.fix_status as vulnerability_fix_state,
    v.package_type as artifact_type,
    v.severity as vulnerability_severity,
    MAX(v.risk) as vulnerability_risk,
    MAX(v.known_exploited) as vulnerability_known_exploits,
    COUNT(DISTINCT c.id) as vulnerability_count`

	mainQuery := selectClause + baseQuery + groupBy

	// Multi-level sort, mirroring buildImageVulnerabilitiesQuery:
	// 1. user-selected column (if any, and not severity/vulnerability)
	// 2. severity (always, by priority)
	// 3. cve_id (always, for stable tie-breaking)
	validSortColumns := map[string]bool{
		"vulnerability_severity": true, "vulnerability_id": true, "artifact_name": true,
		"artifact_version": true, "vulnerability_fix_versions": true, "vulnerability_fix_state": true,
		"artifact_type": true, "vulnerability_risk": true, "vulnerability_known_exploits": true,
		"vulnerability_count": true,
	}

	severityCase := `    CASE v.severity
        WHEN 'Critical' THEN 1
        WHEN 'High' THEN 2
        WHEN 'Medium' THEN 3
        WHEN 'Low' THEN 4
        WHEN 'Negligible' THEN 5
        ELSE 6
    END`

	mainQuery += "\nORDER BY\n"

	switch {
	case sortBy == "vulnerability_severity":
		// Severity primary, cve_id secondary
		mainQuery += severityCase + " " + sortOrder + ",\n    v.cve_id ASC"
	case sortBy == "vulnerability_id":
		// Vulnerability primary, severity secondary
		mainQuery += "    v.cve_id " + sortOrder + ",\n" + severityCase + " ASC"
	case sortBy != "" && validSortColumns[sortBy]:
		// User column primary (referenced via its SELECT alias so aggregate
		// columns sort correctly), then severity, then cve_id.
		mainQuery += fmt.Sprintf("    %s %s,\n", sortBy, sortOrder)
		mainQuery += severityCase + " ASC,\n    v.cve_id ASC"
	default:
		// Default: severity, vulnerability
		mainQuery += severityCase + " ASC,\n    v.cve_id ASC"
	}

	// Add pagination (skip if limit <= 0 for full export)
	if limit > 0 {
		mainQuery += fmt.Sprintf("\nLIMIT %d OFFSET %d", limit, offset)
	}

	return mainQuery, countQuery
}

// ContainerCVEAffectedHandler creates an HTTP handler for the
// /api/container-cves/affected endpoint. Given a CVE finding (identified by
// cve plus the package name/version/type), it returns the images and namespaces
// where it is running, with per (image, namespace) affected-container counts.
// This backs the "affected images / namespaces" section of the CVE details modal.
func ContainerCVEAffectedHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()

		cve := params.Get("cve")
		if cve == "" {
			http.Error(w, "cve required", http.StatusBadRequest)
			return
		}

		// Identify the specific finding. cve is required; the package fields
		// narrow it to the exact grouped row the user clicked.
		conditions := []string{fmt.Sprintf("v.cve_id = '%s'", escapeSQL(cve))}
		if name := params.Get("name"); name != "" {
			conditions = append(conditions, fmt.Sprintf("v.package_name = '%s'", escapeSQL(name)))
		}
		if version := params.Get("version"); version != "" {
			conditions = append(conditions, fmt.Sprintf("v.package_version = '%s'", escapeSQL(version)))
		}
		if ptype := params.Get("type"); ptype != "" {
			conditions = append(conditions, fmt.Sprintf("v.package_type = '%s'", escapeSQL(ptype)))
		}

		query := fmt.Sprintf(`
SELECT
    c.reference as reference,
    i.digest as digest,
    c.namespace as namespace,
    COUNT(DISTINCT c.id) as container_count
FROM image_vulnerabilities v
JOIN images i ON v.image_id = i.id
JOIN containers c ON c.image_id = i.id
WHERE %s
GROUP BY c.reference, i.digest, c.namespace
ORDER BY container_count DESC, c.reference ASC, c.namespace ASC`, strings.Join(conditions, " AND "))

		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Error("error executing container CVE affected query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"affected": result.Rows,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding container CVE affected response", "error", err)
		}
	}
}

// ContainerCVEDetailVariantsHandler creates an HTTP handler for the
// /api/container-cves/details endpoint. For a CVE finding (cve plus the package
// name/version/type), it returns the *distinct* vulnerability-detail JSON
// records across all affected images that have >=1 running container.
//
// The stored detail is the per-image Grype match record, so two images can
// legitimately carry different detail JSON for the same CVE (e.g. different
// artifact locations). This collapses byte-identical records into a single
// variant and lists which images produce each one, so the UI can show every
// genuinely-different record rather than one arbitrary representative.
func ContainerCVEDetailVariantsHandler(provider ImageQueryProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()

		cve := params.Get("cve")
		if cve == "" {
			http.Error(w, "cve required", http.StatusBadRequest)
			return
		}

		conditions := []string{fmt.Sprintf("v.cve_id = '%s'", escapeSQL(cve))}
		if name := params.Get("name"); name != "" {
			conditions = append(conditions, fmt.Sprintf("v.package_name = '%s'", escapeSQL(name)))
		}
		if version := params.Get("version"); version != "" {
			conditions = append(conditions, fmt.Sprintf("v.package_version = '%s'", escapeSQL(version)))
		}
		if ptype := params.Get("type"); ptype != "" {
			conditions = append(conditions, fmt.Sprintf("v.package_type = '%s'", escapeSQL(ptype)))
		}

		// One detail row per affected image (UNIQUE(image_id, cve_id, package_*)
		// guarantees at most one image_vulnerabilities row per image). The
		// correlated subquery picks a human-readable reference for the image.
		query := fmt.Sprintf(`
SELECT
    i.digest as digest,
    (SELECT c.reference FROM containers c WHERE c.image_id = i.id ORDER BY c.reference LIMIT 1) as reference,
    vd.details as details
FROM image_vulnerabilities v
JOIN image_vulnerability_details vd ON vd.vulnerability_id = v.id
JOIN images i ON v.image_id = i.id
WHERE %s
  AND EXISTS (SELECT 1 FROM containers c WHERE c.image_id = i.id)
ORDER BY i.digest`, strings.Join(conditions, " AND "))

		result, err := provider.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Error("error executing container CVE detail variants query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		type imageRef struct {
			Digest    string `json:"digest"`
			Reference string `json:"reference"`
		}
		type variant struct {
			Details json.RawMessage `json:"details"`
			Images  []imageRef      `json:"images"`
		}

		variants := []variant{}
		indexByContent := map[string]int{} // detail JSON content -> index in variants
		for _, row := range result.Rows {
			details, _ := row["details"].(string)
			if details == "" {
				continue // skip rows without a usable detail record
			}
			digest, _ := row["digest"].(string)
			reference, _ := row["reference"].(string)

			idx, ok := indexByContent[details]
			if !ok {
				idx = len(variants)
				indexByContent[details] = idx
				variants = append(variants, variant{Details: json.RawMessage(details)})
			}
			variants[idx].Images = append(variants[idx].Images, imageRef{Digest: digest, Reference: reference})
		}

		response := map[string]interface{}{
			"variants":      variants,
			"variant_count": len(variants),
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding container CVE detail variants response", "error", err)
		}
	}
}
