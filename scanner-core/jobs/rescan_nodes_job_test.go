package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/nodes"
)

// mockNodeDatabase implements NodeDatabaseInterface for testing
type mockNodeDatabase struct {
	nodes []nodes.NodeWithStatus
	err   error
}

func (m *mockNodeDatabase) GetAllNodes() ([]nodes.NodeWithStatus, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.nodes, nil
}

func (m *mockNodeDatabase) GetNodesNeedingRescan(currentGrypeDBBuilt time.Time) ([]nodes.NodeWithStatus, error) {
	return nil, nil // Not used by RescanNodesJob
}

// mockFullRescanQueue implements NodeFullRescanQueueInterface for testing
type mockFullRescanQueue struct {
	enqueuedNodes []string
}

func (m *mockFullRescanQueue) EnqueueHostFullRescan(nodeName string) {
	m.enqueuedNodes = append(m.enqueuedNodes, nodeName)
}

func TestRescanNodesJob_Name(t *testing.T) {
	db := &mockNodeDatabase{}
	queue := &mockFullRescanQueue{}
	job := NewRescanNodesJob(db, queue)

	if job.Name() != "rescan-nodes" {
		t.Errorf("expected job name 'rescan-nodes', got '%s'", job.Name())
	}
}

func TestRescanNodesJob_Run_EnqueuesCompletedNodes(t *testing.T) {
	db := &mockNodeDatabase{
		nodes: []nodes.NodeWithStatus{
			{Node: nodes.Node{Name: "node1"}, NodeScanStatus: nodes.NodeScanStatus{Status: "completed"}},
			{Node: nodes.Node{Name: "node2"}, NodeScanStatus: nodes.NodeScanStatus{Status: "scanned"}},
			{Node: nodes.Node{Name: "node3"}, NodeScanStatus: nodes.NodeScanStatus{Status: "pending"}},
			{Node: nodes.Node{Name: "node4"}, NodeScanStatus: nodes.NodeScanStatus{Status: "failed"}},
		},
	}
	queue := &mockFullRescanQueue{}
	job := NewRescanNodesJob(db, queue)

	err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only enqueue completed and scanned nodes
	if len(queue.enqueuedNodes) != 2 {
		t.Errorf("expected 2 nodes enqueued, got %d", len(queue.enqueuedNodes))
	}

	// Verify correct nodes were enqueued
	expectedNodes := map[string]bool{"node1": true, "node2": true}
	for _, name := range queue.enqueuedNodes {
		if !expectedNodes[name] {
			t.Errorf("unexpected node enqueued: %s", name)
		}
	}
}

func TestRescanNodesJob_Run_NoNodes(t *testing.T) {
	db := &mockNodeDatabase{nodes: []nodes.NodeWithStatus{}}
	queue := &mockFullRescanQueue{}
	job := NewRescanNodesJob(db, queue)

	err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(queue.enqueuedNodes) != 0 {
		t.Errorf("expected no nodes enqueued, got %d", len(queue.enqueuedNodes))
	}
}

func TestRescanNodesJob_Run_NoCompletedNodes(t *testing.T) {
	db := &mockNodeDatabase{
		nodes: []nodes.NodeWithStatus{
			{Node: nodes.Node{Name: "node1"}, NodeScanStatus: nodes.NodeScanStatus{Status: "pending"}},
			{Node: nodes.Node{Name: "node2"}, NodeScanStatus: nodes.NodeScanStatus{Status: "generating_sbom"}},
		},
	}
	queue := &mockFullRescanQueue{}
	job := NewRescanNodesJob(db, queue)

	err := job.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(queue.enqueuedNodes) != 0 {
		t.Errorf("expected no nodes enqueued, got %d", len(queue.enqueuedNodes))
	}
}

func TestRescanNodesJob_Run_DatabaseError(t *testing.T) {
	db := &mockNodeDatabase{err: errors.New("database error")}
	queue := &mockFullRescanQueue{}
	job := NewRescanNodesJob(db, queue)

	err := job.Run(context.Background())
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if len(queue.enqueuedNodes) != 0 {
		t.Errorf("expected no nodes enqueued on error, got %d", len(queue.enqueuedNodes))
	}
}

func TestNewRescanNodesJob_NilDependencies(t *testing.T) {
	tests := []struct {
		name      string
		db        NodeDatabaseInterface
		scanQueue NodeFullRescanQueueInterface
	}{
		{"nil database", nil, &mockFullRescanQueue{}},
		{"nil scan queue", &mockNodeDatabase{}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Error("expected panic for nil dependency")
				}
			}()
			NewRescanNodesJob(tt.db, tt.scanQueue)
		})
	}
}
