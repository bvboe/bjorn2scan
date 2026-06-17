package debug

import (
	"testing"
	"time"
)

func TestNewDebugConfig(t *testing.T) {
	// Test enabled
	cfg := NewDebugConfig(true)
	if !cfg.IsEnabled() {
		t.Error("Expected debug to be enabled")
	}

	// Test disabled
	cfg = NewDebugConfig(false)
	if cfg.IsEnabled() {
		t.Error("Expected debug to be disabled")
	}
}

func TestRecordRequest(t *testing.T) {
	cfg := NewDebugConfig(true)

	// Record a request
	cfg.RecordRequest("/api/test", 100*time.Millisecond)

	metrics := cfg.GetMetrics()

	if metrics.RequestCount != 1 {
		t.Errorf("Expected request count 1, got %d", metrics.RequestCount)
	}

	if metrics.TotalDuration != 100*time.Millisecond {
		t.Errorf("Expected total duration 100ms, got %v", metrics.TotalDuration)
	}

	if metrics.EndpointMetrics["/api/test"] == nil {
		t.Fatal("Expected endpoint metrics for /api/test")
	}

	em := metrics.EndpointMetrics["/api/test"]
	if em.Count != 1 {
		t.Errorf("Expected endpoint count 1, got %d", em.Count)
	}

	if em.TotalDuration != 100*time.Millisecond {
		t.Errorf("Expected endpoint duration 100ms, got %v", em.TotalDuration)
	}
}

func TestRecordMultipleRequests(t *testing.T) {
	cfg := NewDebugConfig(true)

	// Record multiple requests to different endpoints
	cfg.RecordRequest("/api/test1", 50*time.Millisecond)
	cfg.RecordRequest("/api/test2", 75*time.Millisecond)
	cfg.RecordRequest("/api/test1", 25*time.Millisecond)

	metrics := cfg.GetMetrics()

	if metrics.RequestCount != 3 {
		t.Errorf("Expected request count 3, got %d", metrics.RequestCount)
	}

	expected := 50*time.Millisecond + 75*time.Millisecond + 25*time.Millisecond
	if metrics.TotalDuration != expected {
		t.Errorf("Expected total duration %v, got %v", expected, metrics.TotalDuration)
	}

	// Check /api/test1 endpoint
	if metrics.EndpointMetrics["/api/test1"].Count != 2 {
		t.Errorf("Expected /api/test1 count 2, got %d", metrics.EndpointMetrics["/api/test1"].Count)
	}

	// Check /api/test2 endpoint
	if metrics.EndpointMetrics["/api/test2"].Count != 1 {
		t.Errorf("Expected /api/test2 count 1, got %d", metrics.EndpointMetrics["/api/test2"].Count)
	}
}

func TestRecordRequestWhenDisabled(t *testing.T) {
	cfg := NewDebugConfig(false)

	// Record a request when disabled
	cfg.RecordRequest("/api/test", 100*time.Millisecond)

	metrics := cfg.GetMetrics()

	// Metrics should not be recorded when disabled
	if metrics.RequestCount != 0 {
		t.Errorf("Expected request count 0 when disabled, got %d", metrics.RequestCount)
	}
}

func TestSetQueueDepth(t *testing.T) {
	cfg := NewDebugConfig(true)

	cfg.SetQueueDepth(42)

	metrics := cfg.GetMetrics()

	if metrics.QueueDepth != 42 {
		t.Errorf("Expected queue depth 42, got %d", metrics.QueueDepth)
	}
}

func TestSetQueueDepthWhenDisabled(t *testing.T) {
	cfg := NewDebugConfig(false)

	cfg.SetQueueDepth(42)

	metrics := cfg.GetMetrics()

	// Queue depth should not be set when disabled
	if metrics.QueueDepth != 0 {
		t.Errorf("Expected queue depth 0 when disabled, got %d", metrics.QueueDepth)
	}
}

func TestResetMetrics(t *testing.T) {
	cfg := NewDebugConfig(true)

	// Record some metrics
	cfg.RecordRequest("/api/test", 100*time.Millisecond)
	cfg.SetQueueDepth(10)

	// Reset
	cfg.ResetMetrics()

	metrics := cfg.GetMetrics()

	if metrics.RequestCount != 0 {
		t.Errorf("Expected request count 0 after reset, got %d", metrics.RequestCount)
	}

	if metrics.TotalDuration != 0 {
		t.Errorf("Expected total duration 0 after reset, got %v", metrics.TotalDuration)
	}

	if metrics.QueueDepth != 0 {
		t.Errorf("Expected queue depth 0 after reset, got %d", metrics.QueueDepth)
	}

	if len(metrics.EndpointMetrics) != 0 {
		t.Errorf("Expected no endpoint metrics after reset, got %d", len(metrics.EndpointMetrics))
	}
}

func TestConcurrentRecordRequest(t *testing.T) {
	cfg := NewDebugConfig(true)

	// Record requests concurrently
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			cfg.RecordRequest("/api/test", 1*time.Millisecond)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	metrics := cfg.GetMetrics()

	if metrics.RequestCount != 100 {
		t.Errorf("Expected request count 100, got %d", metrics.RequestCount)
	}
}

func TestGetMetricsReturnsCopy(t *testing.T) {
	cfg := NewDebugConfig(true)

	cfg.RecordRequest("/api/test", 100*time.Millisecond)

	// Get metrics
	metrics1 := cfg.GetMetrics()

	// Modify the returned metrics
	metrics1.RequestCount = 999

	// Get metrics again
	metrics2 := cfg.GetMetrics()

	// Original metrics should not be affected
	if metrics2.RequestCount == 999 {
		t.Error("GetMetrics should return a copy, not the original")
	}

	if metrics2.RequestCount != 1 {
		t.Errorf("Expected request count 1, got %d", metrics2.RequestCount)
	}
}
