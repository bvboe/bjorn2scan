package jobs

import (
	"errors"
	"testing"
	"time"

	"github.com/bvboe/bjorn2scan/scanner-core/nodes"
)

// mockNodeDatabase implements NodeDatabaseInterface for testing.
type mockNodeDatabase struct {
	needingRescan []nodes.NodeWithStatus
	err           error
	calledWith    time.Time
	callCount     int
}

func (m *mockNodeDatabase) GetNodesNeedingRescan(currentGrypeDBBuilt time.Time) ([]nodes.NodeWithStatus, error) {
	m.callCount++
	m.calledWith = currentGrypeDBBuilt
	if m.err != nil {
		return nil, m.err
	}
	return m.needingRescan, nil
}

// mockNodeScanQueue implements NodeScanQueueInterface for testing.
type mockNodeScanQueue struct {
	enqueued []string
}

func (m *mockNodeScanQueue) EnqueueHostForceScan(nodeName string) {
	m.enqueued = append(m.enqueued, nodeName)
}

// TestRescanNodesOnDBUpdate_EnqueuesStaleNodes covers the path that actually runs
// in production. It fires whenever the grype database updates, which measurement
// of the tracked history shows is daily (29 intervals, median 24.0h, max 24.3h),
// and it is the only thing that refreshes node SBOMs.
//
// It previously had no direct test at all — the tests in this file covered a
// sibling job that was never scheduled and has since been deleted.
func TestRescanNodesOnDBUpdate_EnqueuesStaleNodes(t *testing.T) {
	dbBuilt := time.Date(2026, 8, 24, 6, 22, 13, 0, time.UTC)
	db := &mockNodeDatabase{needingRescan: []nodes.NodeWithStatus{
		{Node: nodes.Node{Name: "worker-1"}},
		{Node: nodes.Node{Name: "worker-2"}},
		{Node: nodes.Node{Name: "controlplane"}},
	}}
	q := &mockNodeScanQueue{}

	if err := RescanNodesOnDBUpdate(db, q, dbBuilt); err != nil {
		t.Fatalf("RescanNodesOnDBUpdate failed: %v", err)
	}

	if len(q.enqueued) != 3 {
		t.Errorf("enqueued %d nodes, want 3 — a node missed here keeps reporting "+
			"vulnerabilities against a stale database", len(q.enqueued))
	}
	if !db.calledWith.Equal(dbBuilt) {
		t.Errorf("queried with %v, want the current database build time %v; passing the "+
			"wrong timestamp would select the wrong set of nodes", db.calledWith, dbBuilt)
	}
}

// TestRescanNodesOnDBUpdate_NoStaleNodes is the common case: the job runs, every
// node is already current, and nothing should be queued. Enqueuing here would
// mean a full SBOM regeneration of every node on every check — roughly 59s per
// node on a large cluster — for no reason.
func TestRescanNodesOnDBUpdate_NoStaleNodes(t *testing.T) {
	db := &mockNodeDatabase{needingRescan: nil}
	q := &mockNodeScanQueue{}

	if err := RescanNodesOnDBUpdate(db, q, time.Now()); err != nil {
		t.Fatalf("RescanNodesOnDBUpdate failed: %v", err)
	}
	if len(q.enqueued) != 0 {
		t.Errorf("enqueued %v with no stale nodes; every check would trigger a full "+
			"rescan of the fleet", q.enqueued)
	}
}

// TestRescanNodesOnDBUpdate_DatabaseError checks the error is returned rather
// than swallowed. This runs inside the rescan-database job; silently returning
// nil would make a broken node query look like "nothing to do", and nodes would
// quietly stop being rescanned.
func TestRescanNodesOnDBUpdate_DatabaseError(t *testing.T) {
	db := &mockNodeDatabase{err: errors.New("database is locked")}
	q := &mockNodeScanQueue{}

	err := RescanNodesOnDBUpdate(db, q, time.Now())
	if err == nil {
		t.Fatal("expected an error when the node query fails, got nil")
	}
	if len(q.enqueued) != 0 {
		t.Errorf("enqueued %v despite the query failing", q.enqueued)
	}
}

// TestRescanNodesOnDBUpdate_HostScanningNotConfigured covers agents and clusters
// with host scanning disabled, where both dependencies are nil. It must be a
// no-op rather than a nil-pointer panic, because it is called unconditionally
// from the rescan-database job.
func TestRescanNodesOnDBUpdate_HostScanningNotConfigured(t *testing.T) {
	if err := RescanNodesOnDBUpdate(nil, nil, time.Now()); err != nil {
		t.Errorf("expected a no-op with no host scanning configured, got %v", err)
	}
	// Also each half individually — a partially wired setup must not panic.
	if err := RescanNodesOnDBUpdate(&mockNodeDatabase{}, nil, time.Now()); err != nil {
		t.Errorf("nil queue should be a no-op, got %v", err)
	}
	if err := RescanNodesOnDBUpdate(nil, &mockNodeScanQueue{}, time.Now()); err != nil {
		t.Errorf("nil database should be a no-op, got %v", err)
	}
}
