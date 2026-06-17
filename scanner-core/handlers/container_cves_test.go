package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

func TestBuildContainerCVEsQuery(t *testing.T) {
	t.Run("groups and counts affected containers", func(t *testing.T) {
		mainQuery, countQuery := buildContainerCVEsQuery(nil, nil, nil, nil, nil, "", "ASC", 100, 0)

		for _, frag := range []string{
			"FROM image_vulnerabilities v",
			"JOIN images i ON v.image_id = i.id",
			"JOIN containers c ON c.image_id = i.id",
			"COUNT(DISTINCT c.id) as vulnerability_count",
			"GROUP BY v.cve_id, v.package_name, v.package_version, v.fixed_version, v.fix_status, v.package_type, v.severity",
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

	t.Run("applies all filters", func(t *testing.T) {
		mainQuery, _ := buildContainerCVEsQuery(
			[]string{"default"}, []string{"wolfi"}, []string{"Critical"},
			[]string{"fixed"}, []string{"apk"}, "", "ASC", 100, 0)

		for _, frag := range []string{
			"c.namespace IN ('default')",
			"i.os_name IN ('wolfi')",
			"v.severity IN ('Critical')",
			"v.fix_status IN ('fixed')",
			"v.package_type IN ('apk')",
		} {
			if !strings.Contains(mainQuery, frag) {
				t.Errorf("query missing filter %q\nquery: %s", frag, mainQuery)
			}
		}
	})

	t.Run("export omits LIMIT", func(t *testing.T) {
		mainQuery, _ := buildContainerCVEsQuery(nil, nil, nil, nil, nil, "", "ASC", -1, 0)
		if strings.Contains(mainQuery, "LIMIT") {
			t.Errorf("export query should not contain LIMIT: %s", mainQuery)
		}
	})

	t.Run("severity sort uses priority CASE", func(t *testing.T) {
		mainQuery, _ := buildContainerCVEsQuery(nil, nil, nil, nil, nil, "vulnerability_severity", "DESC", 100, 0)
		if !strings.Contains(mainQuery, "CASE v.severity") {
			t.Errorf("expected severity CASE ordering, got: %s", mainQuery)
		}
	})

	t.Run("aggregate column sort uses alias", func(t *testing.T) {
		mainQuery, _ := buildContainerCVEsQuery(nil, nil, nil, nil, nil, "vulnerability_count", "DESC", 100, 0)
		if !strings.Contains(mainQuery, "vulnerability_count DESC") {
			t.Errorf("expected order by vulnerability_count alias, got: %s", mainQuery)
		}
	})
}

func TestContainerCVEsHandler(t *testing.T) {
	tests := []struct {
		name           string
		queryParams    string
		expectedStatus int
	}{
		{"basic request", "page=1&pageSize=20", http.StatusOK},
		{"with filters", "namespaces=default&severity=Critical&vulnStatuses=fixed&packageTypes=apk&osNames=wolfi", http.StatusOK},
		{"csv export", "format=csv", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &mockQueryProvider{
				queryFunc: func(query string) (*database.QueryResult, error) {
					if strings.Contains(query, "COUNT(*) FROM") {
						return &database.QueryResult{
							Columns: []string{"COUNT(*)"},
							Rows:    []map[string]interface{}{{"COUNT(*)": int64(2)}},
						}, nil
					}
					return &database.QueryResult{
						Columns: []string{"id", "vulnerability_id", "vulnerability_severity", "vulnerability_count"},
						Rows: []map[string]interface{}{
							{"id": int64(1), "vulnerability_id": "CVE-2024-0001", "vulnerability_severity": "Critical", "vulnerability_count": int64(5)},
						},
					}, nil
				},
			}

			handler := ContainerCVEsHandler(provider)
			req := httptest.NewRequest(http.MethodGet, "/api/container-cves?"+tt.queryParams, nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, rec.Code)
			}
		})
	}
}

func TestContainerCVEAffectedHandler(t *testing.T) {
	t.Run("requires cve param", func(t *testing.T) {
		provider := &mockQueryProvider{queryFunc: func(string) (*database.QueryResult, error) {
			return &database.QueryResult{}, nil
		}}
		handler := ContainerCVEAffectedHandler(provider)
		req := httptest.NewRequest(http.MethodGet, "/api/container-cves/affected", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 without cve param, got %d", rec.Code)
		}
	})

	t.Run("builds query and returns affected rows", func(t *testing.T) {
		var captured string
		provider := &mockQueryProvider{
			queryFunc: func(query string) (*database.QueryResult, error) {
				captured = query
				return &database.QueryResult{
					Columns: []string{"reference", "digest", "namespace", "container_count"},
					Rows: []map[string]interface{}{
						{"reference": "nginx:1.25", "digest": "sha256:abc", "namespace": "default", "container_count": int64(3)},
					},
				}, nil
			},
		}
		handler := ContainerCVEAffectedHandler(provider)
		req := httptest.NewRequest(http.MethodGet, "/api/container-cves/affected?cve=CVE-2024-0001&name=openssl&version=1.1&type=apk", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		for _, frag := range []string{
			"v.cve_id = 'CVE-2024-0001'",
			"v.package_name = 'openssl'",
			"v.package_version = '1.1'",
			"v.package_type = 'apk'",
			"COUNT(DISTINCT c.id) as container_count",
		} {
			if !strings.Contains(captured, frag) {
				t.Errorf("affected query missing %q\nquery: %s", frag, captured)
			}
		}
	})
}

// TestContainerCVEQueriesExecuteAgainstRealSchema runs the actual generated SQL
// (every sort variant and filter combination) against a real, migrated database.
// Mock-based handler tests never execute the SQL and the DB-layer test uses
// hand-written SQL, so this is what catches a column/alias/syntax typo in
// buildContainerCVEsQuery or the affected query.
func TestContainerCVEQueriesExecuteAgainstRealSchema(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	// Fully filtered + aggregate-column sort.
	mainQuery, countQuery := buildContainerCVEsQuery(
		[]string{"default"}, []string{"wolfi"}, []string{"Critical"},
		[]string{"fixed"}, []string{"apk"}, "vulnerability_count", "DESC", 100, 0)
	if _, err := db.ExecuteReadOnlyQuery(countQuery); err != nil {
		t.Fatalf("count query failed against real schema: %v\n%s", err, countQuery)
	}
	if _, err := db.ExecuteReadOnlyQuery(mainQuery); err != nil {
		t.Fatalf("main query failed against real schema: %v\n%s", err, mainQuery)
	}

	// Every sortable column must produce valid SQL.
	for _, col := range []string{
		"vulnerability_severity", "vulnerability_id", "artifact_name", "artifact_version",
		"vulnerability_fix_versions", "vulnerability_fix_state", "artifact_type",
		"vulnerability_risk", "vulnerability_known_exploits", "vulnerability_count", "",
	} {
		q, _ := buildContainerCVEsQuery(nil, nil, nil, nil, nil, col, "ASC", 50, 0)
		if _, err := db.ExecuteReadOnlyQuery(q); err != nil {
			t.Errorf("query with sortBy=%q failed against real schema: %v\n%s", col, err, q)
		}
	}

	// HTTP handlers against the real (empty) schema return valid JSON envelopes.
	rec := httptest.NewRecorder()
	ContainerCVEsHandler(db)(rec, httptest.NewRequest(http.MethodGet, "/api/container-cves?page=1&pageSize=20", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ContainerCVEsHandler returned %d", rec.Code)
	}
	var listResp struct {
		CVEs       []map[string]interface{} `json:"cves"`
		TotalCount int64                    `json:"totalCount"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("list response not valid JSON: %v", err)
	}

	rec = httptest.NewRecorder()
	ContainerCVEAffectedHandler(db)(rec, httptest.NewRequest(http.MethodGet, "/api/container-cves/affected?cve=CVE-2024-0001&name=openssl&version=1.1&type=apk", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ContainerCVEAffectedHandler returned %d (affected query likely invalid)", rec.Code)
	}

	rec = httptest.NewRecorder()
	ContainerCVEDetailVariantsHandler(db)(rec, httptest.NewRequest(http.MethodGet, "/api/container-cves/details?cve=CVE-2024-0001&name=openssl&version=1.1&type=apk", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ContainerCVEDetailVariantsHandler returned %d (variants query likely invalid)", rec.Code)
	}
}

func TestContainerCVEDetailVariantsHandler(t *testing.T) {
	t.Run("requires cve param", func(t *testing.T) {
		provider := &mockQueryProvider{queryFunc: func(string) (*database.QueryResult, error) {
			return &database.QueryResult{}, nil
		}}
		rec := httptest.NewRecorder()
		ContainerCVEDetailVariantsHandler(provider)(rec, httptest.NewRequest(http.MethodGet, "/api/container-cves/details", nil))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected 400 without cve param, got %d", rec.Code)
		}
	})

	t.Run("collapses identical details and groups images", func(t *testing.T) {
		var captured string
		provider := &mockQueryProvider{
			queryFunc: func(query string) (*database.QueryResult, error) {
				captured = query
				return &database.QueryResult{
					Columns: []string{"digest", "reference", "details"},
					Rows: []map[string]interface{}{
						{"digest": "sha256:a", "reference": "nginx:1", "details": `{"loc":"/a"}`},
						{"digest": "sha256:b", "reference": "nginx:2", "details": `{"loc":"/a"}`}, // identical -> same variant
						{"digest": "sha256:c", "reference": "redis:7", "details": `{"loc":"/b"}`}, // different -> new variant
					},
				}, nil
			},
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/container-cves/details?cve=CVE-1&name=openssl&version=1.1&type=apk", nil)
		ContainerCVEDetailVariantsHandler(provider)(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
		for _, frag := range []string{
			"JOIN image_vulnerability_details vd ON vd.vulnerability_id = v.id",
			"EXISTS (SELECT 1 FROM containers c WHERE c.image_id = i.id)",
			"v.cve_id = 'CVE-1'",
			"v.package_name = 'openssl'",
		} {
			if !strings.Contains(captured, frag) {
				t.Errorf("query missing %q\nquery: %s", frag, captured)
			}
		}

		var resp struct {
			VariantCount int `json:"variant_count"`
			Variants     []struct {
				Details json.RawMessage `json:"details"`
				Images  []struct {
					Digest    string `json:"digest"`
					Reference string `json:"reference"`
				} `json:"images"`
			} `json:"variants"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("response not valid JSON: %v", err)
		}
		if resp.VariantCount != 2 || len(resp.Variants) != 2 {
			t.Fatalf("expected 2 distinct variants, got count=%d len=%d", resp.VariantCount, len(resp.Variants))
		}
		if len(resp.Variants[0].Images) != 2 {
			t.Errorf("expected first variant shared by 2 images, got %d", len(resp.Variants[0].Images))
		}
		if len(resp.Variants[1].Images) != 1 {
			t.Errorf("expected second variant to have 1 image, got %d", len(resp.Variants[1].Images))
		}
		if string(resp.Variants[0].Details) != `{"loc":"/a"}` {
			t.Errorf("unexpected variant 0 details: %s", resp.Variants[0].Details)
		}
	})
}
