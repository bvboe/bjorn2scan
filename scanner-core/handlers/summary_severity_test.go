package handlers

import (
	"strings"
	"testing"
)

// TestSummaryMetricsSeverityFilter verifies the deployment- and node-metrics
// summary queries honor the severity filter used by the CVE pages, and that the
// generated SQL still executes against the real schema.
func TestSummaryMetricsSeverityFilter(t *testing.T) {
	db, cleanup := createTestDBForHandlers(t)
	defer cleanup()

	t.Run("deployment metrics applies severity", func(t *testing.T) {
		q := buildDeploymentMetricsQuery(nil, nil, nil, nil, []string{"Critical", "High"})
		if !strings.Contains(q, "severity IN ('Critical','High')") {
			t.Errorf("expected severity filter in deployment metrics query:\n%s", q)
		}
		if _, err := db.ExecuteReadOnlyQuery(q); err != nil {
			t.Fatalf("severity-filtered deployment query failed against real schema: %v\n%s", err, q)
		}

		// No severity → no severity clause (unchanged behavior).
		if q := buildDeploymentMetricsQuery(nil, nil, nil, nil, nil); strings.Contains(q, "severity IN") {
			t.Errorf("did not expect a severity clause when none selected:\n%s", q)
		}
	})

	t.Run("node metrics applies severity", func(t *testing.T) {
		q := buildNodeMetricsQuery(nil, nil, nil, []string{"Critical"})
		if !strings.Contains(q, "nv.severity IN ('Critical')") {
			t.Errorf("expected nv.severity filter in node metrics query:\n%s", q)
		}
		if _, err := db.ExecuteReadOnlyQuery(q); err != nil {
			t.Fatalf("severity-filtered node query failed against real schema: %v\n%s", err, q)
		}

		if q := buildNodeMetricsQuery(nil, nil, nil, nil); strings.Contains(q, "severity IN") {
			t.Errorf("did not expect a severity clause when none selected:\n%s", q)
		}
	})
}
