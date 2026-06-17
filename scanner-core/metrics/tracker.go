package metrics

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/database"
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

// ApplyDiff compares currentRows (all metric series seen this cycle) against the
// in-memory state and writes only what changed:
//   - New series (not previously tracked) → UPSERT with NULL expiry.
//   - Disappeared series (in state as active, not seen this cycle) → mark stale.
//   - Reappeared series (in state as stale, seen this cycle) → UPSERT clears expiry.
//   - Stable series (in state as active, seen this cycle) → no DB I/O.
//
// In a stable cluster this is zero DB writes. The in-memory state is updated
// only after the transaction commits successfully; if the commit fails the
// state is unchanged and the next cycle will retry the same diff.
func (s *StalenessStore) ApplyDiff(currentRows []database.StalenessRow, cycleStart time.Time) error {
	expiresAt := cycleStart.Unix() + int64(s.stalenessWindow.Seconds())

	// Hash currentRows up-front so we can index by hash for the diff.
	for i := range currentRows {
		currentRows[i].KeyHash = database.HashMetricKey(currentRows[i].MetricKey)
	}

	// Compute the diff under a read lock; defer all writes until after.
	s.mu.RLock()
	seenHashes := make(map[uint64]struct{}, len(currentRows))
	var toUpsert []database.StalenessRow
	for i := range currentRows {
		h := currentRows[i].KeyHash
		seenHashes[h] = struct{}{}
		if exp, ok := s.state[h]; !ok {
			// Never seen — UPSERT inserts a new row.
			toUpsert = append(toUpsert, currentRows[i])
		} else if exp != 0 {
			// Was stale — UPSERT clears expiry.
			toUpsert = append(toUpsert, currentRows[i])
		}
		// else: already active in memory, no DB write needed.
	}

	var toStale []uint64
	for h, exp := range s.state {
		if exp == 0 {
			if _, seen := seenHashes[h]; !seen {
				toStale = append(toStale, h)
			}
		}
	}
	s.mu.RUnlock()

	if len(toUpsert) == 0 && len(toStale) == 0 {
		return nil // steady state — no DB I/O at all
	}

	if err := s.db.ApplyStalenessChanges(toUpsert, toStale, expiresAt); err != nil {
		return fmt.Errorf("failed to apply staleness changes: %w", err)
	}

	// Commit succeeded — mirror the changes into the in-memory state.
	s.mu.Lock()
	for _, r := range toUpsert {
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
