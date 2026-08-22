package metrics

import (
	"github.com/bvboe/bjorn2scan/scanner-core/database"
)

// StalenessRecorder receives every live series seen during one collection pass.
//
// It exists to keep the per-cycle allocation proportional to what *changed*
// rather than to the total number of series. Collection previously built, for
// every series on every cycle, a metric-key string, a JSON encoding of its
// labels, a second copy of that JSON as a string, and a StalenessRow holding
// them — then retained the key strings in a map and the rows in a slice until
// the cycle finished. At 508,657 series that is on the order of half a gigabyte
// of live allocation per export, and Go's default GOGC=100 reserves roughly as
// much again as headroom, so each transient byte cost two.
//
// That mattered because memory, not latency, is this exporter's binding
// constraint: a large deployment sits near 2.6 GiB against a 4 GiB limit while
// using 2.4% of its push interval.
//
// The observation that makes it avoidable: in a steady cluster almost no series
// change between cycles. The staleness store already knows which hashes are
// active, so it can answer "do you need the full row for this one?" before the
// caller pays to build it. Observe is called for every series and is cheap;
// Materialize is called only for the few that are new or returning from stale.
type StalenessRecorder interface {
	// Observe records that keyHash was emitted live this cycle and reports
	// whether the caller must follow up with Materialize. Returning false means
	// the series is already tracked as active and nothing needs to be written.
	Observe(keyHash uint64) bool

	// Materialize supplies the full row for a series where Observe returned true.
	Materialize(row database.StalenessRow)

	// IsLive reports whether keyHash was seen live this cycle. Used to suppress
	// NaN for series that appear in the stale query only because it ran before
	// this cycle's live values were recorded.
	IsLive(keyHash uint64) bool
}

// diffRecorder is the StalenessRecorder used in production. It holds the set of
// hashes seen this cycle plus the rows that actually need persisting.
//
// Memory is one map entry per series (~16 bytes) instead of a retained key
// string and JSON row (~950 bytes), and the rows slice stays empty in a steady
// cluster.
//
// State is read through the store under its read lock rather than snapshotted.
// A snapshot would be another map of every series — ~8 MB — allocated per cycle,
// which is the kind of cost this change exists to remove. A read lock per series
// is ~20 ns, so ~10 ms across 500k series, and it is correct even though the
// scrape path applies its diff on a background goroutine that can overlap the
// next collection.
type diffRecorder struct {
	store   *StalenessStore
	live    map[uint64]struct{}
	toWrite []database.StalenessRow
}

func newDiffRecorder(store *StalenessStore, sizeHint int) *diffRecorder {
	return &diffRecorder{
		store: store,
		live:  make(map[uint64]struct{}, sizeHint),
	}
}

func (r *diffRecorder) Observe(keyHash uint64) bool {
	r.live[keyHash] = struct{}{}
	return r.store.needsPersist(keyHash)
}

func (r *diffRecorder) Materialize(row database.StalenessRow) {
	r.toWrite = append(r.toWrite, row)
}

func (r *diffRecorder) IsLive(keyHash uint64) bool {
	_, ok := r.live[keyHash]
	return ok
}
