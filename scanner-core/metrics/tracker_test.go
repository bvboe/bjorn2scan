package metrics

import (
	"sync"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/database"
)

// mockStalenessDB is an in-memory StalenessDB for testing. Shared across
// tracker_test.go, handler_test.go, and otel_test.go since they all live in
// the same package. mu protects all fields because DeleteExpired runs in a
// goroutine concurrently with QueryStale.
type mockStalenessDB struct {
	mu        sync.Mutex
	rows      map[uint64]*database.StalenessRow // keyed by KeyHash; value is the live row
	upserts   []database.StalenessRow           // history of upsert calls (one entry per row, in call order)
	staled    []uint64                          // history of stale-mark calls (one entry per hash)
	deleted   int64
	err       error
	hydrateOK map[uint64]int64 // initial state returned by HydrateStalenessState; empty if nil
}

func (m *mockStalenessDB) QueryStaleness(cycleStart int64) ([]database.StalenessRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	var stale []database.StalenessRow
	for _, r := range m.rows {
		if r.ExpiresAtUnix != nil && *r.ExpiresAtUnix > cycleStart {
			stale = append(stale, *r)
		}
	}
	return stale, nil
}

func (m *mockStalenessDB) HydrateStalenessState() (map[uint64]int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	state := make(map[uint64]int64, len(m.hydrateOK))
	for h, exp := range m.hydrateOK {
		state[h] = exp
	}
	// Mirror hydrate state into rows so QueryStaleness sees pre-existing data.
	if m.rows == nil {
		m.rows = make(map[uint64]*database.StalenessRow, len(m.hydrateOK))
	}
	return state, nil
}

func (m *mockStalenessDB) ApplyStalenessChanges(toUpsert []database.StalenessRow, toStale []uint64, expiresAtUnix int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	if m.rows == nil {
		m.rows = make(map[uint64]*database.StalenessRow, len(toUpsert))
	}
	for _, r := range toUpsert {
		row := r // copy
		row.ExpiresAtUnix = nil
		m.rows[r.KeyHash] = &row
		m.upserts = append(m.upserts, r)
	}
	for _, h := range toStale {
		if r, ok := m.rows[h]; ok {
			v := expiresAtUnix
			r.ExpiresAtUnix = &v
		}
		m.staled = append(m.staled, h)
	}
	return nil
}

func (m *mockStalenessDB) DeleteExpiredStaleness(expireBefore int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.deleted = expireBefore
	for h, r := range m.rows {
		if r.ExpiresAtUnix != nil && *r.ExpiresAtUnix < expireBefore {
			delete(m.rows, h)
		}
	}
	return nil
}

func ptr64(v int64) *int64 { return &v }

// hashOf is a test helper mirroring database.HashMetricKey to keep call sites readable.
func hashOf(key string) uint64 { return database.HashMetricKey(key) }

// withHydratedRow seeds the mock with a row already known at construction time.
func withHydratedRow(m *mockStalenessDB, key, family, labels string, expiresAt *int64) {
	if m.rows == nil {
		m.rows = make(map[uint64]*database.StalenessRow)
	}
	if m.hydrateOK == nil {
		m.hydrateOK = make(map[uint64]int64)
	}
	h := hashOf(key)
	r := database.StalenessRow{MetricKey: key, FamilyName: family, LabelsJSON: labels, KeyHash: h, ExpiresAtUnix: expiresAt}
	m.rows[h] = &r
	if expiresAt == nil {
		m.hydrateOK[h] = 0
	} else {
		m.hydrateOK[h] = *expiresAt
	}
}

// ── StalenessStore construction ──────────────────────────────────────────────

func TestNewStalenessStore_Defaults(t *testing.T) {
	db := &mockStalenessDB{}
	s := NewStalenessStore(db, 0) // zero → DefaultStalenessWindow

	if s.StalenessWindow() != DefaultStalenessWindow {
		t.Errorf("Expected default window %v, got %v", DefaultStalenessWindow, s.StalenessWindow())
	}
}

func TestNewStalenessStore_CustomWindow(t *testing.T) {
	db := &mockStalenessDB{}
	window := 30 * time.Minute
	s := NewStalenessStore(db, window)

	if s.StalenessWindow() != window {
		t.Errorf("Expected window %v, got %v", window, s.StalenessWindow())
	}
}

// ── QueryStale ───────────────────────────────────────────────────────────────

func TestStalenessStore_QueryStale(t *testing.T) {
	cycleStart := time.Unix(2000000, 0)
	futureExpiry := cycleStart.Unix() + 3600 // expires 1 hour after cycleStart
	pastExpiry := cycleStart.Unix() - 1      // already expired

	db := &mockStalenessDB{}
	withHydratedRow(db, "stale_metric", "f1", `{}`, ptr64(futureExpiry))
	withHydratedRow(db, "expired_metric", "f2", `{}`, ptr64(pastExpiry))
	withHydratedRow(db, "active_metric", "f3", `{}`, nil)

	s := NewStalenessStore(db, time.Hour)
	stale, err := s.QueryStale(cycleStart)
	if err != nil {
		t.Fatalf("QueryStale failed: %v", err)
	}

	if len(stale) != 1 {
		t.Fatalf("Expected 1 stale row, got %d", len(stale))
	}
	if stale[0].MetricKey != "stale_metric" {
		t.Errorf("Expected stale_metric, got %s", stale[0].MetricKey)
	}
}

func TestStalenessStore_QueryStale_Empty(t *testing.T) {
	db := &mockStalenessDB{}
	s := NewStalenessStore(db, time.Hour)

	stale, err := s.QueryStale(time.Now())
	if err != nil {
		t.Fatalf("Expected no error for empty DB, got: %v", err)
	}
	if len(stale) != 0 {
		t.Errorf("Expected 0 stale rows, got %d", len(stale))
	}
}

// ── ApplyDiff ────────────────────────────────────────────────────────────────

func TestApplyDiff_NewMetrics(t *testing.T) {
	db := &mockStalenessDB{} // empty DB
	s := NewStalenessStore(db, time.Hour)

	current := []database.StalenessRow{
		{MetricKey: "m1", FamilyName: "f1", LabelsJSON: `{}`},
		{MetricKey: "m2", FamilyName: "f1", LabelsJSON: `{}`},
	}

	if err := s.ApplyDiff(current, time.Now()); err != nil {
		t.Fatalf("ApplyDiff failed: %v", err)
	}

	db.mu.Lock()
	defer db.mu.Unlock()
	if len(db.upserts) != 2 {
		t.Errorf("Expected 2 upserts for new metrics, got %d", len(db.upserts))
	}
	if len(db.staled) != 0 {
		t.Errorf("Expected 0 stale marks, got %d", len(db.staled))
	}
}

func TestApplyDiff_StableCluster_NoWrites(t *testing.T) {
	// Active rows in DB that match current cycle exactly — zero writes.
	db := &mockStalenessDB{}
	withHydratedRow(db, "m1", "f1", `{}`, nil)
	withHydratedRow(db, "m2", "f1", `{}`, nil)

	s := NewStalenessStore(db, time.Hour)

	current := []database.StalenessRow{
		{MetricKey: "m1", FamilyName: "f1", LabelsJSON: `{}`},
		{MetricKey: "m2", FamilyName: "f1", LabelsJSON: `{}`},
	}

	if err := s.ApplyDiff(current, time.Now()); err != nil {
		t.Fatalf("ApplyDiff failed: %v", err)
	}

	db.mu.Lock()
	defer db.mu.Unlock()
	if len(db.upserts) != 0 {
		t.Errorf("Expected 0 upserts for stable cluster, got %d", len(db.upserts))
	}
	if len(db.staled) != 0 {
		t.Errorf("Expected 0 stale marks for stable cluster, got %d", len(db.staled))
	}
}

func TestApplyDiff_DisappearedMetric(t *testing.T) {
	// m1 was active, not seen this cycle → mark stale
	// m2 was active, still present → no write
	db := &mockStalenessDB{}
	withHydratedRow(db, "m1", "f1", `{}`, nil)
	withHydratedRow(db, "m2", "f1", `{}`, nil)

	s := NewStalenessStore(db, time.Hour)

	current := []database.StalenessRow{
		{MetricKey: "m2", FamilyName: "f1", LabelsJSON: `{}`},
	}

	cycleStart := time.Unix(2000000, 0)
	if err := s.ApplyDiff(current, cycleStart); err != nil {
		t.Fatalf("ApplyDiff failed: %v", err)
	}

	db.mu.Lock()
	defer db.mu.Unlock()
	if len(db.staled) != 1 || db.staled[0] != hashOf("m1") {
		t.Errorf("Expected m1 to be marked stale (hash %d), got %v", hashOf("m1"), db.staled)
	}
	// Verify expiry is set on the row
	if r, ok := db.rows[hashOf("m1")]; !ok || r.ExpiresAtUnix == nil {
		t.Error("Expected m1 to have expires_at_unix set")
	} else {
		expected := cycleStart.Unix() + int64(time.Hour.Seconds())
		if *r.ExpiresAtUnix != expected {
			t.Errorf("Expected expires_at_unix=%d, got %d", expected, *r.ExpiresAtUnix)
		}
	}
}

func TestApplyDiff_ReappearedMetric(t *testing.T) {
	// m1 was stale (has expires_at_unix), reappears this cycle → UPSERT clears expiry
	futureExpiry := time.Now().Add(30 * time.Minute).Unix()
	db := &mockStalenessDB{}
	withHydratedRow(db, "m1", "f1", `{}`, ptr64(futureExpiry))

	s := NewStalenessStore(db, time.Hour)

	current := []database.StalenessRow{
		{MetricKey: "m1", FamilyName: "f1", LabelsJSON: `{}`},
	}

	if err := s.ApplyDiff(current, time.Now()); err != nil {
		t.Fatalf("ApplyDiff failed: %v", err)
	}

	db.mu.Lock()
	defer db.mu.Unlock()
	if len(db.upserts) != 1 {
		t.Errorf("Expected 1 upsert for reactivation, got %d", len(db.upserts))
	}
	if r, ok := db.rows[hashOf("m1")]; !ok || r.ExpiresAtUnix != nil {
		t.Error("Expected m1 to have expires_at_unix=nil after reactivation")
	}
}

// ── DeleteExpired ─────────────────────────────────────────────────────────────

func TestStalenessStore_DeleteExpired(t *testing.T) {
	db := &mockStalenessDB{}
	// Pre-populate with one expired row so the in-memory state has work to do.
	pastExpiry := int64(1000000)
	withHydratedRow(db, "old_metric", "f1", `{}`, ptr64(pastExpiry))

	s := NewStalenessStore(db, time.Hour)

	cycleStart := time.Unix(2000000, 0)
	s.DeleteExpired(cycleStart)

	if db.deleted != cycleStart.Unix() {
		t.Errorf("Expected expireBefore=%d, got %d", cycleStart.Unix(), db.deleted)
	}
}

func TestStalenessStore_DeleteExpired_Skipped(t *testing.T) {
	// Empty state — DeleteExpired should not call the DB at all.
	db := &mockStalenessDB{}
	s := NewStalenessStore(db, time.Hour)

	s.DeleteExpired(time.Unix(2000000, 0))

	if db.deleted != 0 {
		t.Errorf("Expected DeleteExpiredStaleness to be skipped (deleted==0), got %d", db.deleted)
	}
}

// ── generateMetricKey ─────────────────────────────────────────────────────────

func TestGenerateMetricKey(t *testing.T) {
	tests := []struct {
		name       string
		familyName string
		labels     map[string]string
		expected   string
	}{
		{
			name:       "no labels",
			familyName: "my_metric",
			labels:     map[string]string{},
			expected:   "my_metric",
		},
		{
			name:       "single label",
			familyName: "my_metric",
			labels:     map[string]string{"key": "value"},
			expected:   "my_metric|key=value",
		},
		{
			name:       "multiple labels sorted",
			familyName: "my_metric",
			labels:     map[string]string{"z": "last", "a": "first", "m": "middle"},
			expected:   "my_metric|a=first|m=middle|z=last",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateMetricKey(tt.familyName, tt.labels)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}
