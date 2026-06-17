package handlers

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

// NodeCVEsHandler creates an HTTP handler for the /api/node-cves endpoint.
//
// It returns a deployment-wide, deduplicated CVE listing across all scanned
// nodes: one row per unique (cve_id, package_name, package_version,
// fix_version, fix_status, package_type, severity). The count column reports
// the number of distinct affected nodes. This is the node-side analogue of
// ContainerCVEsHandler; nodes carry vulnerabilities directly (no image layer),
// so the query joins node_vulnerabilities straight to nodes.
func NodeCVEsHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

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

		if format == "csv" {
			pageSize = -1
			offset = 0
		}

		// Filters (multiselect - comma separated). Param names mirror the rest of
		// the node pages (osNames/vulnStatuses/packageTypes) so the shared summary
		// strip and cross-page nav filters apply unchanged; severity is the one
		// extra filter specific to the CVE listing.
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

		query, countQuery := buildNodeCVEsQuery(osNames, severities, fixStatuses, packageTypes, sortBy, sortOrder, pageSize, offset)

		countResult, err := db.ExecuteReadOnlyQuery(countQuery)
		if err != nil {
			log.Error("error executing node CVE count query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		totalCount := int64(0)
		if len(countResult.Rows) > 0 && len(countResult.Columns) > 0 {
			if count, ok := countResult.Rows[0][countResult.Columns[0]].(int64); ok {
				totalCount = count
			}
		}

		result, err := db.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Error("error executing node CVE query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if format == "csv" {
			exportQueryResultAsCSV(w, result, "node_cves.csv")
			return
		}

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
			log.Error("error encoding node CVEs response", "error", err)
		}
	}
}

// buildNodeCVEsQuery builds the deduplicated deployment-wide node CVE query and
// its matching count query. Rows are grouped by (cve_id, package_name,
// package_version, fix_version, fix_status, package_type, severity);
// vulnerability_count reports the number of distinct affected nodes. Column
// aliases match buildContainerCVEsQuery / image.html so the frontend table is
// shared. Note node_vulnerabilities uses fix_version (not fixed_version).
func buildNodeCVEsQuery(osNames, severities, fixStatuses, packageTypes []string, sortBy, sortOrder string, limit, offset int) (string, string) {
	var conditions []string
	conditions = appendCondition(conditions, buildINClause("n.os_release", osNames))
	conditions = appendCondition(conditions, buildINClause("v.severity", severities))
	conditions = appendCondition(conditions, buildINClause("v.fix_status", fixStatuses))
	conditions = appendCondition(conditions, buildINClause("v.package_type", packageTypes))
	whereClause := buildWhereClause(conditions)

	baseQuery := fmt.Sprintf(`
FROM node_vulnerabilities v
JOIN nodes n ON v.node_id = n.id
WHERE 1=1%s`, whereClause)

	groupBy := `
GROUP BY v.cve_id, v.package_name, v.package_version, v.fix_version, v.fix_status, v.package_type, v.severity`

	countQuery := "SELECT COUNT(*) FROM (SELECT 1" + baseQuery + groupBy + ") sub"

	selectClause := `SELECT
    MAX(v.id) as id,
    v.cve_id as vulnerability_id,
    v.package_name as artifact_name,
    v.package_version as artifact_version,
    v.fix_version as vulnerability_fix_versions,
    v.fix_status as vulnerability_fix_state,
    v.package_type as artifact_type,
    v.severity as vulnerability_severity,
    MAX(v.risk) as vulnerability_risk,
    MAX(v.known_exploited) as vulnerability_known_exploits,
    COUNT(DISTINCT n.id) as vulnerability_count`

	mainQuery := selectClause + baseQuery + groupBy

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
		mainQuery += severityCase + " " + sortOrder + ",\n    v.cve_id ASC"
	case sortBy == "vulnerability_id":
		mainQuery += "    v.cve_id " + sortOrder + ",\n" + severityCase + " ASC"
	case sortBy != "" && validSortColumns[sortBy]:
		mainQuery += fmt.Sprintf("    %s %s,\n", sortBy, sortOrder)
		mainQuery += severityCase + " ASC,\n    v.cve_id ASC"
	default:
		mainQuery += severityCase + " ASC,\n    v.cve_id ASC"
	}

	if limit > 0 {
		mainQuery += fmt.Sprintf("\nLIMIT %d OFFSET %d", limit, offset)
	}

	return mainQuery, countQuery
}

// NodeCVEAffectedHandler creates an HTTP handler for /api/node-cves/affected.
// Given a CVE finding (cve plus the package name/version/type), it returns the
// nodes where it is present. Backs the "affected nodes" section of the node CVE
// details modal.
func NodeCVEAffectedHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		params := r.URL.Query()
		cve := params.Get("cve")
		if cve == "" {
			http.Error(w, "cve required", http.StatusBadRequest)
			return
		}

		conditions := nodeCVEMatchConditions(params)

		query := fmt.Sprintf(`
SELECT
    n.name as node_name,
    n.os_release as os_release
FROM node_vulnerabilities v
JOIN nodes n ON v.node_id = n.id
WHERE %s
GROUP BY n.name, n.os_release
ORDER BY n.name`, strings.Join(conditions, " AND "))

		result, err := db.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Error("error executing node CVE affected query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		response := map[string]interface{}{
			"affected": result.Rows,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding node CVE affected response", "error", err)
		}
	}
}

// NodeCVEDetailVariantsHandler creates an HTTP handler for /api/node-cves/details.
// For a CVE finding it returns the distinct vulnerability-detail JSON records
// across all affected nodes, collapsing byte-identical records into a single
// variant and listing which nodes produce each one.
func NodeCVEDetailVariantsHandler(db *database.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		params := r.URL.Query()
		cve := params.Get("cve")
		if cve == "" {
			http.Error(w, "cve required", http.StatusBadRequest)
			return
		}

		conditions := nodeCVEMatchConditions(params)

		// UNIQUE(node_id, cve_id, package_name, package_version) guarantees at most
		// one node_vulnerabilities row per node per finding, so one detail per node.
		query := fmt.Sprintf(`
SELECT
    n.name as node_name,
    vd.details as details
FROM node_vulnerabilities v
JOIN node_vulnerability_details vd ON vd.node_vulnerability_id = v.id
JOIN nodes n ON v.node_id = n.id
WHERE %s
ORDER BY n.name`, strings.Join(conditions, " AND "))

		result, err := db.ExecuteReadOnlyQuery(query)
		if err != nil {
			log.Error("error executing node CVE detail variants query", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		variants := groupNodeDetailVariants(result.Rows)
		response := map[string]interface{}{
			"variants":      variants,
			"variant_count": len(variants),
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Error("error encoding node CVE detail variants response", "error", err)
		}
	}
}

// nodeDetailVariantRef identifies one node that produces a given detail variant.
type nodeDetailVariantRef struct {
	NodeName string `json:"node_name"`
}

// nodeDetailVariant is one distinct detail-JSON record plus the nodes sharing it.
type nodeDetailVariant struct {
	Details json.RawMessage        `json:"details"`
	Nodes   []nodeDetailVariantRef `json:"nodes"`
}

// groupNodeDetailVariants collapses (node_name, details) rows into distinct
// detail variants, preserving first-seen order and listing the nodes that share
// each. Rows are expected to be ordered so variant/node ordering is stable.
func groupNodeDetailVariants(rows []map[string]interface{}) []nodeDetailVariant {
	variants := []nodeDetailVariant{}
	indexByContent := map[string]int{} // detail JSON content -> index in variants
	for _, row := range rows {
		details, _ := row["details"].(string)
		if details == "" {
			continue
		}
		nodeName, _ := row["node_name"].(string)

		idx, ok := indexByContent[details]
		if !ok {
			idx = len(variants)
			indexByContent[details] = idx
			variants = append(variants, nodeDetailVariant{Details: json.RawMessage(details)})
		}
		variants[idx].Nodes = append(variants[idx].Nodes, nodeDetailVariantRef{NodeName: nodeName})
	}
	return variants
}

// nodeCVEMatchConditions builds the WHERE conditions that identify a single CVE
// finding (cve required; package name/version/type narrow it to the exact
// grouped row). Shared by the affected and detail-variants handlers.
func nodeCVEMatchConditions(params map[string][]string) []string {
	get := func(k string) string {
		if v, ok := params[k]; ok && len(v) > 0 {
			return v[0]
		}
		return ""
	}
	conditions := []string{fmt.Sprintf("v.cve_id = '%s'", escapeSQL(get("cve")))}
	if name := get("name"); name != "" {
		conditions = append(conditions, fmt.Sprintf("v.package_name = '%s'", escapeSQL(name)))
	}
	if version := get("version"); version != "" {
		conditions = append(conditions, fmt.Sprintf("v.package_version = '%s'", escapeSQL(version)))
	}
	if ptype := get("type"); ptype != "" {
		conditions = append(conditions, fmt.Sprintf("v.package_type = '%s'", escapeSQL(ptype)))
	}
	return conditions
}
