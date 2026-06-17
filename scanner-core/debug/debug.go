// Package debug provides debug mode functionality including metrics collection,
// SQL query debugging, and verbose logging.
package debug

import (
	"sync"
	"time"
)

// DebugConfig holds debug mode configuration and metrics.
type DebugConfig struct {
	enabled bool
	mu      sync.RWMutex
	metrics *Metrics
}

// Metrics holds performance and request statistics.
type Metrics struct {
	RequestCount    int64
	TotalDuration   time.Duration
	QueueDepth      int
	LastUpdated     time.Time
	EndpointMetrics map[string]*EndpointMetrics
}

// EndpointMetrics holds per-endpoint statistics.
type EndpointMetrics struct {
	Count         int64
	TotalDuration time.Duration
	LastAccess    time.Time
}

// NewDebugConfig creates a new DebugConfig with the specified enabled state.
func NewDebugConfig(enabled bool) *DebugConfig {
	return &DebugConfig{
		enabled: enabled,
		metrics: &Metrics{
			EndpointMetrics: make(map[string]*EndpointMetrics),
		},
	}
}

// IsEnabled returns whether debug mode is enabled.
// This method is thread-safe.
func (d *DebugConfig) IsEnabled() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.enabled
}

// RecordRequest records a request's metrics.
// This method is thread-safe.
func (d *DebugConfig) RecordRequest(endpoint string, duration time.Duration) {
	if !d.IsEnabled() {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Update global metrics
	d.metrics.RequestCount++
	d.metrics.TotalDuration += duration
	d.metrics.LastUpdated = time.Now()

	// Update endpoint-specific metrics
	if d.metrics.EndpointMetrics[endpoint] == nil {
		d.metrics.EndpointMetrics[endpoint] = &EndpointMetrics{}
	}
	d.metrics.EndpointMetrics[endpoint].Count++
	d.metrics.EndpointMetrics[endpoint].TotalDuration += duration
	d.metrics.EndpointMetrics[endpoint].LastAccess = time.Now()
}

// GetMetrics returns a snapshot of current metrics.
// This method is thread-safe.
func (d *DebugConfig) GetMetrics() *Metrics {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Create a deep copy to avoid concurrent modification
	metricsCopy := &Metrics{
		RequestCount:    d.metrics.RequestCount,
		TotalDuration:   d.metrics.TotalDuration,
		QueueDepth:      d.metrics.QueueDepth,
		LastUpdated:     d.metrics.LastUpdated,
		EndpointMetrics: make(map[string]*EndpointMetrics),
	}

	for endpoint, em := range d.metrics.EndpointMetrics {
		metricsCopy.EndpointMetrics[endpoint] = &EndpointMetrics{
			Count:         em.Count,
			TotalDuration: em.TotalDuration,
			LastAccess:    em.LastAccess,
		}
	}

	return metricsCopy
}

// SetQueueDepth updates the queue depth metric.
// This method is thread-safe.
func (d *DebugConfig) SetQueueDepth(depth int) {
	if !d.IsEnabled() {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.metrics.QueueDepth = depth
}

// ResetMetrics clears all collected metrics.
// This method is thread-safe.
func (d *DebugConfig) ResetMetrics() {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.metrics = &Metrics{
		EndpointMetrics: make(map[string]*EndpointMetrics),
	}
}
