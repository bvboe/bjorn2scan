package metrics

import (
	"testing"
	"time"

	"github.com/bvboe/bjorn2scan/scanner-core/database"
)

// TestSteadyCycleMaterializesNothing is the point of the recorder.
//
// Collection used to build, for every series on every cycle, a metric-key
// string, a JSON encoding of its labels, a second copy of that JSON, and a row
// holding them — around 950 bytes per series, roughly half a gigabyte at
// production scale, discarded immediately. Since almost nothing changes between
// cycles in a steady cluster, nearly all of it was waste, and it dominated the
// footprint of a process whose binding constraint is memory.
//
// A second cycle over an unchanged series set must therefore materialize zero
// rows and write nothing to the database.
func TestSteadyCycleMaterializesNothing(t *testing.T) {
	db := &mockStalenessDB{}
	s := NewStalenessStore(db, time.Hour)

	rows := []database.StalenessRow{
		{MetricKey: "m1", FamilyName: "f", LabelsJSON: `{"a":"1"}`},
		{MetricKey: "m2", FamilyName: "f", LabelsJSON: `{"a":"2"}`},
		{MetricKey: "m3", FamilyName: "f", LabelsJSON: `{"a":"3"}`},
	}

	// First cycle: everything is new, so everything must be written.
	first := s.NewRecorder()
	for _, r := range rows {
		h := database.HashMetricKey(r.MetricKey)
		if !first.Observe(h) {
			t.Fatalf("%s should need persisting on a first sighting", r.MetricKey)
		}
		r.KeyHash = h
		first.Materialize(r)
	}
	if err := s.Apply(first, time.Now()); err != nil {
		t.Fatalf("first Apply failed: %v", err)
	}

	// Second cycle: same series, nothing changed.
	second := s.NewRecorder()
	for _, r := range rows {
		if second.Observe(database.HashMetricKey(r.MetricKey)) {
			t.Errorf("%s asked to be materialized on an unchanged cycle; the expensive "+
				"labels JSON would be built for every series again", r.MetricKey)
		}
	}
	if len(second.toWrite) != 0 {
		t.Errorf("steady cycle materialized %d rows, want 0", len(second.toWrite))
	}

	db.mu.Lock()
	upsertsAfterFirst := len(db.upserts)
	db.mu.Unlock()

	if err := s.Apply(second, time.Now()); err != nil {
		t.Fatalf("second Apply failed: %v", err)
	}

	db.mu.Lock()
	defer db.mu.Unlock()
	if len(db.upserts) != upsertsAfterFirst {
		t.Errorf("steady cycle wrote %d extra upserts, want 0",
			len(db.upserts)-upsertsAfterFirst)
	}
	if len(db.staled) != 0 {
		t.Errorf("steady cycle marked %d series stale, want 0", len(db.staled))
	}
}

// TestDisappearedSeriesGoStale checks the other half: a series that stops being
// reported must still be marked stale, which is what produces the NaN marker
// downstream. Streaming must not lose that.
func TestDisappearedSeriesGoStale(t *testing.T) {
	db := &mockStalenessDB{}
	s := NewStalenessStore(db, time.Hour)

	all := []string{"m1", "m2", "m3"}
	first := s.NewRecorder()
	for _, k := range all {
		h := database.HashMetricKey(k)
		first.Observe(h)
		first.Materialize(database.StalenessRow{MetricKey: k, FamilyName: "f", LabelsJSON: `{}`, KeyHash: h})
	}
	if err := s.Apply(first, time.Now()); err != nil {
		t.Fatalf("first Apply failed: %v", err)
	}

	// m2 disappears.
	second := s.NewRecorder()
	for _, k := range []string{"m1", "m3"} {
		second.Observe(database.HashMetricKey(k))
	}
	if err := s.Apply(second, time.Now()); err != nil {
		t.Fatalf("second Apply failed: %v", err)
	}

	db.mu.Lock()
	defer db.mu.Unlock()
	if len(db.staled) != 1 {
		t.Fatalf("expected exactly 1 series marked stale, got %d", len(db.staled))
	}
	if db.staled[0] != database.HashMetricKey("m2") {
		t.Errorf("wrong series marked stale")
	}
}

// TestReturningSeriesIsMaterialized covers the case that makes Observe more than
// a set-membership check: a series that went stale and came back must be written
// again to clear its expiry, so it needs its full row even though it is already
// tracked.
func TestReturningSeriesIsMaterialized(t *testing.T) {
	db := &mockStalenessDB{}
	s := NewStalenessStore(db, time.Hour)

	h := database.HashMetricKey("m1")

	first := s.NewRecorder()
	first.Observe(h)
	first.Materialize(database.StalenessRow{MetricKey: "m1", FamilyName: "f", LabelsJSON: `{}`, KeyHash: h})
	if err := s.Apply(first, time.Now()); err != nil {
		t.Fatalf("first Apply failed: %v", err)
	}

	// Cycle with no series at all: m1 goes stale.
	if err := s.Apply(s.NewRecorder(), time.Now()); err != nil {
		t.Fatalf("staling Apply failed: %v", err)
	}

	// m1 returns.
	third := s.NewRecorder()
	if !third.Observe(h) {
		t.Error("a series returning from stale must be materialized so its expiry is cleared")
	}
}

// TestIsLiveSuppressesNaN guards the NaN-suppression path, which switched from
// comparing metric-key strings to comparing hashes. Getting that wrong would
// emit NaN over a live value — the metric would read as absent while the series
// is actually being reported.
func TestIsLiveSuppressesNaN(t *testing.T) {
	db := &mockStalenessDB{}
	s := NewStalenessStore(db, time.Hour)

	rec := s.NewRecorder()
	rec.Observe(database.HashMetricKey("live-one"))

	if !rec.IsLive(database.HashMetricKey("live-one")) {
		t.Error("a series observed this cycle must report as live, or NaN will overwrite it")
	}
	if rec.IsLive(database.HashMetricKey("never-seen")) {
		t.Error("an unobserved series must not report as live, or its NaN marker is suppressed")
	}
}
