package jobs

import (
	"context"
	"errors"
	"testing"
)

// mockRefreshTrigger implements containers.RefreshTrigger for testing
type mockRefreshTrigger struct {
	called      bool
	shouldFail  bool
	triggerFunc func() error
}

func (m *mockRefreshTrigger) TriggerRefresh() error {
	m.called = true
	if m.triggerFunc != nil {
		return m.triggerFunc()
	}
	if m.shouldFail {
		return errors.New("mock trigger error")
	}
	return nil
}

func TestRefreshImagesJob(t *testing.T) {
	t.Run("successful refresh", func(t *testing.T) {
		trigger := &mockRefreshTrigger{}
		job := NewRefreshImagesJob(trigger)

		if job.Name() != "refresh-images" {
			t.Errorf("Expected name 'refresh-images', got %s", job.Name())
		}

		err := job.Run(context.Background())
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}

		if !trigger.called {
			t.Error("Expected trigger to be called")
		}
	})

	t.Run("failed refresh", func(t *testing.T) {
		trigger := &mockRefreshTrigger{shouldFail: true}
		job := NewRefreshImagesJob(trigger)

		err := job.Run(context.Background())
		if err == nil {
			t.Error("Expected error, got nil")
		}

		if !trigger.called {
			t.Error("Expected trigger to be called even on failure")
		}
	})

	t.Run("nil trigger panics", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Error("Expected panic with nil trigger")
			}
		}()

		NewRefreshImagesJob(nil)
	})

	t.Run("context cancellation", func(t *testing.T) {
		trigger := &mockRefreshTrigger{
			triggerFunc: func() error {
				// Simulate long-running operation
				return nil
			},
		}
		job := NewRefreshImagesJob(trigger)

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		// Job should still complete (it doesn't check context internally)
		// But in a real scenario, the trigger implementation would check context
		_ = job.Run(ctx)

		if !trigger.called {
			t.Error("Expected trigger to be called")
		}
	})
}
