package jobs

import (
	"context"
	"errors"
	"testing"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
)

// mockDatabaseCleanup implements DatabaseCleanup for testing
type mockDatabaseCleanup struct {
	called      bool
	shouldFail  bool
	cleanupFunc func() (*database.CleanupStats, error)
	stats       *database.CleanupStats
}

func (m *mockDatabaseCleanup) CleanupStaleContainers(_ []containers.ContainerID) (int, error) {
	return 0, nil
}

func (m *mockDatabaseCleanup) CleanupOrphanedImages() (*database.CleanupStats, error) {
	m.called = true
	if m.cleanupFunc != nil {
		return m.cleanupFunc()
	}
	if m.shouldFail {
		return nil, errors.New("mock cleanup error")
	}
	return m.stats, nil
}

func TestCleanupOrphanedImagesJob(t *testing.T) {
	t.Run("successful cleanup", func(t *testing.T) {
		db := &mockDatabaseCleanup{
			stats: &database.CleanupStats{
				ImagesRemoved:          5,
				PackagesRemoved:        123,
				VulnerabilitiesRemoved: 456,
			},
		}
		job := NewCleanupOrphanedImagesJob(db)

		if job.Name() != "cleanup-orphaned-images" {
			t.Errorf("Expected name 'cleanup-orphaned-images', got %s", job.Name())
		}

		err := job.Run(context.Background())
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		if !db.called {
			t.Error("Expected cleanup to be called")
		}
	})

	t.Run("no orphaned images", func(t *testing.T) {
		db := &mockDatabaseCleanup{
			stats: &database.CleanupStats{
				ImagesRemoved:          0,
				PackagesRemoved:        0,
				VulnerabilitiesRemoved: 0,
			},
		}
		job := NewCleanupOrphanedImagesJob(db)

		err := job.Run(context.Background())
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		if !db.called {
			t.Error("Expected cleanup to be called even with no orphans")
		}
	})

	t.Run("cleanup failure", func(t *testing.T) {
		db := &mockDatabaseCleanup{shouldFail: true}
		job := NewCleanupOrphanedImagesJob(db)

		err := job.Run(context.Background())
		if err == nil {
			t.Error("Expected error, got nil")
		}

		if !db.called {
			t.Error("Expected cleanup to be called")
		}
	})

	t.Run("nil database panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic with nil database")
			}
		}()

		NewCleanupOrphanedImagesJob(nil)
	})

	t.Run("context is passed but not used", func(t *testing.T) {
		db := &mockDatabaseCleanup{}
		job := NewCleanupOrphanedImagesJob(db)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Job doesn't check context, so it should still run
		_ = job.Run(ctx)

		if !db.called {
			t.Error("Expected cleanup to be called despite cancelled context")
		}
	})

	t.Run("large cleanup", func(t *testing.T) {
		db := &mockDatabaseCleanup{
			stats: &database.CleanupStats{
				ImagesRemoved:          1000,
				PackagesRemoved:        50000,
				VulnerabilitiesRemoved: 100000,
			},
		}
		job := NewCleanupOrphanedImagesJob(db)

		err := job.Run(context.Background())
		if err != nil {
			t.Errorf("Expected no error with large cleanup, got %v", err)
		}
	})
}
