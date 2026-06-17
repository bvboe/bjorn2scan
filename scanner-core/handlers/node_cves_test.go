package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBuildNodeCVEsQuery(t *testing.T) {
	t.Run("groups and counts affected nodes", func(t *testing.T) {
		mainQuery, countQuery := buildNodeCVEsQuery(nil, nil, nil, nil, "", "ASC", 100, 0)

		for _, frag := range []string{
			"FROM node_vulnerabilities v",
			"JOIN nodes n ON v.node_id = n.id",
			"COUNT(DISTINCT n.id) as vulnerability_count",
			"v.fix_version as vulnerability_fix_versions",
			"GROUP BY v.cve_id, v.package_name, v.package_version, v.fix_version, v.fix_status, v.package_type, v.severity",
		} {
			if !strings.Contains(mainQuery, frag) {
				t.Errorf("main query missing %q\nquery: %s", frag, mainQuery)
			}
		}
		if !strings.Contains(countQuery, "SELECT COUNT(*) FROM (SELECT 1") || !strings.Contains(countQuery, "GROUP BY") {
			t.Errorf("count query should wrap the grouped subquery, got: %s", countQuery)
		}
		if !strings.Contains(mainQuery, "LIMIT 100 OFFSET 0") {
			t.Errorf("expected pagination clause, got: %s", mainQuery)
		}
	})

	t.Run("applies all filters (no namespace)", func(t *testing.T) {
		mainQuery, _ := buildNodeCVEsQuery(
			[]string{"wolfi"}, []string{"Critical"}, []string{"fixed"}, []string{"apk"}, "", "ASC", 100, 0)
		for _, frag := range []string{
			"n.os_release IN ('wolfi')",
			"v.severity IN ('Critical')",
			"v.fix_status IN ('fixed')",
			"v.package_type IN ('apk')",
		} {
			if !strings.Contains(mainQuery, frag) {
				t.Errorf("query missing filter %q\nquery: %s", frag, mainQuery)
			}
		}
		if strings.Contains(mainQuery, "namespace") {
			t.Errorf("node query should not reference namespace: %s", mainQuery)
		}
	})

	t.Run("export omits LIMIT", func(t *testing.T) {
		mainQuery, _ := buildNodeCVEsQuery(nil, nil, nil, nil, "", "ASC", -1, 0)
		if strings.Contains(mainQuery, "LIMIT") {
			t.Errorf("export query should not contain LIMIT: %s", mainQuery)
		}
	})

	t.Run("aggregate column sort uses alias", func(t *testing.T) {
		mainQuery, _ := buildNodeCVEsQuery(nil, nil, nil, nil, "vulnerability_count", "DESC", 100, 0)
		if !strings.Contains(mainQuery, "vulnerability_count DESC") {
			t.Errorf("expected order by vulnerability_count alias, got: %s", mainQuery)
		}
	})
}

func TestGroupNodeDetailVariants(t *testing.T) {
	rows := []map[string]interface{}{
		{"node_name": "node-a", "details": `{"loc":"/a"}`},
		{"node_name": "node-b", "details": `{"loc":"/a"}`}, // identical -> same variant
		{"node_name": "node-c", "details": `{"loc":"/b"}`}, // different -> new variant
		{"node_name": "node-d", "details": ""},             // skipped (no detail)
	}
	variants := groupNodeDetailVariants(rows)
	if len(variants) != 2 {
		t.Fatalf("expected 2 distinct variants, got %d", len(variants))
	}
	if len(variants[0].Nodes) != 2 {
		t.Errorf("expected first variant shared by 2 nodes, got %d", len(variants[0].Nodes))
	}
	if len(variants[1].Nodes) != 1 {
		t.Errorf("expected second variant to have 1 node, got %d", len(variants[1].Nodes))
	}
	if string(variants[0].Details) != `{"loc":"/a"}` {
		t.Errorf("unexpected variant 0 details: %s", variants[0].Details)
	}
}

// TestNodeCVEHandlersAgainstRealSchema runs the actual generated SQL (every
// sort variant) and all three handlers against a real, migrated (empty)
// database. This catches column/alias/syntax errors that the pure unit tests
// can't; populated dedup/affected-count correctness is asserted in the
// database-package migration test (which can insert rows).
func TestNodeCVEHandlersAgainstRealSchema(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	mainQuery, countQuery := buildNodeCVEsQuery(
		[]string{"wolfi"}, []string{"Critical"}, []string{"fixed"}, []string{"apk"}, "vulnerability_count", "DESC", 100, 0)
	if _, err := db.ExecuteReadOnlyQuery(countQuery); err != nil {
		t.Fatalf("count query failed against real schema: %v\n%s", err, countQuery)
	}
	if _, err := db.ExecuteReadOnlyQuery(mainQuery); err != nil {
		t.Fatalf("main query failed against real schema: %v\n%s", err, mainQuery)
	}
	for _, col := range []string{
		"vulnerability_severity", "vulnerability_id", "artifact_name", "artifact_version",
		"vulnerability_fix_versions", "vulnerability_fix_state", "artifact_type",
		"vulnerability_risk", "vulnerability_known_exploits", "vulnerability_count", "",
	} {
		q, _ := buildNodeCVEsQuery(nil, nil, nil, nil, col, "ASC", 50, 0)
		if _, err := db.ExecuteReadOnlyQuery(q); err != nil {
			t.Errorf("query with sortBy=%q failed against real schema: %v\n%s", col, err, q)
		}
	}

	rec := httptest.NewRecorder()
	NodeCVEsHandler(db)(rec, httptest.NewRequest(http.MethodGet, "/api/node-cves?page=1&pageSize=20", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("NodeCVEsHandler returned %d", rec.Code)
	}
	var listResp struct {
		CVEs       []map[string]interface{} `json:"cves"`
		TotalCount int64                    `json:"totalCount"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("list response not valid JSON: %v", err)
	}

	rec = httptest.NewRecorder()
	NodeCVEAffectedHandler(db)(rec, httptest.NewRequest(http.MethodGet, "/api/node-cves/affected?cve=CVE-2024-0001&name=openssl&version=1.1.1&type=apk", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("NodeCVEAffectedHandler returned %d (affected query likely invalid)", rec.Code)
	}

	rec = httptest.NewRecorder()
	NodeCVEDetailVariantsHandler(db)(rec, httptest.NewRequest(http.MethodGet, "/api/node-cves/details?cve=CVE-2024-0001&name=openssl&version=1.1.1&type=apk", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("NodeCVEDetailVariantsHandler returned %d (variants query likely invalid)", rec.Code)
	}

	rec = httptest.NewRecorder()
	NodeCVEAffectedHandler(db)(rec, httptest.NewRequest(http.MethodGet, "/api/node-cves/affected", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 without cve param, got %d", rec.Code)
	}
}
