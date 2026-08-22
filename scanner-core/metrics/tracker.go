package metrics

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/bvboe/bjorn2scan/scanner-core/database"
)

// DefaultStalenessWindow is the default duration after which metrics are considered stale
const DefaultStalenessWindow = 60 * time.Minute

// StalenessDB is the subset of StreamingProvider needed for staleness operations.
// This is a separate interface so StalenessStore can be unit-tested with a mock.
type StalenessDB interface {
	QueryStaleness(cycleStart int64) ([]database.StalenessRow, error)
	HydrateStalenessState() (map[uint64]int64, error)
	ApplyStalenessChanges(toUpsert []database.StalenessRow, toStale []uint64, expiresAtUnix int64) error
	DeleteExpiredStaleness(expireBefore int64) error
}

// StalenessStore tracks per-metric-point staleness using the metric_staleness DB table
// plus an in-memory hash → expires_at_unix map for diff computation.
//
// Staleness behavior:
//  1. New metric this cycle → UPSERT (active, NULL expiry); add to in-memory state.
//  2. Metric that disappeared → UPDATE expires_at_unix; in-memory state records the expiry.
//  3. During the stale grace period the metric emits NaN; after expiry the row is deleted.
//  4. Stale metric reappears → same UPSERT path clears expires_at_unix.
//  5. Active metrics that remain active → zero DB I/O per cycle.
//
// Memory cost: ~24 B per entry × N metric series. At 371k series (kubeadm scale)
// the map is ~9 MB. Hash collisions (FNV-1a 64-bit) at this scale are ~7×10⁻⁶
// expected over the whole table; the consequence of a collision is at most one
// cycle of incorrect staleness signaling for the colliding pair.
type StalenessStore struct {
	db              StalenessDB
	stalenessWindow time.Duration

	mu    sync.RWMutex
	state map[uint64]int64 // key_hash → expires_at_unix (0 sentinel = active)
}

// NewStalenessStore creates a StalenessStore backed by the given database. The
// in-memory state is hydrated from the metric_staleness table once during
// construction; if hydration fails the store starts empty and the next ApplyDiff
// will treat every metric as new (one cycle of redundant UPSERTs, then steady
// state). This is acceptable because the table is non-critical metadata and the
// alternative — failing startup — would block scans.
func NewStalenessStore(db StalenessDB, stalenessWindow time.Duration) *StalenessStore {
	if stalenessWindow == 0 {
		stalenessWindow = DefaultStalenessWindow
	}
	state, err := db.HydrateStalenessState()
	if err != nil {
		log.Warn("failed to hydrate staleness state; starting empty", "error", err)
		state = make(map[uint64]int64)
	} else {
		log.Info("staleness state hydrated", "rows", len(state))
	}
	return &StalenessStore{
		db:              db,
		stalenessWindow: stalenessWindow,
		state:           state,
	}
}

// QueryStale returns metric rows in the stale grace period (disappeared but not yet expired).
// These are emitted as NaN in the current collection cycle. Reads from the DB so
// that labels_json is available for NaN line reconstruction; the in-memory state
// only tracks expiry timestamps, not full labels.
func (s *StalenessStore) QueryStale(cycleStart time.Time) ([]database.StalenessRow, error) {
	return s.db.QueryStaleness(cycleStart.Unix())
}

// NewRecorder returns a StalenessRecorder for one collection pass, sized against
// the current tracked series count so the live set rarely has to grow.
func (s *StalenessStore) NewRecorder() *diffRecorder {
	s.mu.RLock()
	sizeHint := len(s.state)
	s.mu.RUnlock()
	return newDiffRecorder(s, sizeHint)
}

// needsPersist reports whether a series must be written to the staleness table:
// true when it has never been seen, or when it was marked stale and has now
// reappeared. Series already tracked as active need no write, which in a steady
// cluster is all of them.
func (s *StalenessStore) needsPersist(keyHash uint64) bool {
	s.mu.RLock()
	expiry, tracked := s.state[keyHash]
	s.mu.RUnlock()
	return !tracked || expiry != 0
}

// Apply commits the diff gathered by a recorder: the rows it materialized are
// upserted, and anything tracked as active but not seen this cycle is marked
// stale.
//
// This replaces the older ApplyDiff, which took every series as a fully
// materialized row. The work is identical; the difference is that the caller no
// longer has to build half a gigabyte of rows to describe a cycle in which
// nothing changed.
func (s *StalenessStore) Apply(rec *diffRecorder, cycleStart time.Time) error {
	if rec == nil {
		return nil
	}
	expiresAt := cycleStart.Unix() + int64(s.stalenessWindow.Seconds())

	s.mu.RLock()
	var toStale []uint64
	for h, exp := range s.state {
		if exp == 0 {
			if _, seen := rec.live[h]; !seen {
				toStale = append(toStale, h)
			}
		}
	}
	s.mu.RUnlock()

	if len(rec.toWrite) == 0 && len(toStale) == 0 {
		return nil // steady state — no DB I/O at all
	}

	if err := s.db.ApplyStalenessChanges(rec.toWrite, toStale, expiresAt); err != nil {
		return fmt.Errorf("failed to apply staleness changes: %w", err)
	}

	s.mu.Lock()
	for _, r := range rec.toWrite {
		s.state[r.KeyHash] = 0 // active
	}
	for _, h := range toStale {
		s.state[h] = expiresAt
	}
	s.mu.Unlock()

	return nil
}

// DeleteExpired removes staleness rows whose expiry has passed. Skipped entirely
// when no in-memory entry has an expiry ≤ cycleStart, which avoids the per-cycle
// DELETE statement against NFS in the steady state.
func (s *StalenessStore) DeleteExpired(cycleStart time.Time) {
	now := cycleStart.Unix()

	s.mu.RLock()
	var expired []uint64
	for h, exp := range s.state {
		if exp != 0 && exp < now {
			expired = append(expired, h)
		}
	}
	s.mu.RUnlock()

	if len(expired) == 0 {
		return
	}

	if err := s.db.DeleteExpiredStaleness(now); err != nil {
		log.Warn("failed to delete expired staleness entries", "error", err)
		return
	}

	s.mu.Lock()
	for _, h := range expired {
		// Re-check inside the write lock in case the entry was reactivated
		// between snapshot and now.
		if exp, ok := s.state[h]; ok && exp != 0 && exp < now {
			delete(s.state, h)
		}
	}
	s.mu.Unlock()
}

// StalenessWindow returns the configured staleness window.
func (s *StalenessStore) StalenessWindow() time.Duration {
	return s.stalenessWindow
}

// generateMetricKey creates a unique key for a metric based on its family name and labels.
// Key format: "familyName|label1=value1|label2=value2|..." (labels sorted alphabetically).
// HashMetricKey then hashes this string into the 64-bit PRIMARY KEY of metric_staleness.
func generateMetricKey(familyName string, labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	key := familyName
	for _, k := range keys {
		key += "|" + k + "=" + labels[k]
	}
	return key
}
