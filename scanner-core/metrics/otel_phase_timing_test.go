package metrics

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
)

// phaseTimingMetrics builds a payload big enough that marshalling and gzip take
// measurable time. A single tiny metric can complete inside the clock's
// resolution and make the timers look broken when they are fine.
func phaseTimingMetrics(n int) []*metricsv1.Metric {
	out := make([]*metricsv1.Metric, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, &metricsv1.Metric{
			Name: "bjorn2scan_phase_timing_test",
			Data: &metricsv1.Metric_Gauge{Gauge: &metricsv1.Gauge{
				DataPoints: []*metricsv1.NumberDataPoint{{
					TimeUnixNano: uint64(i),
					Value:        &metricsv1.NumberDataPoint_AsDouble{AsDouble: float64(i)},
					Attributes: []*commonv1.KeyValue{
						stringKV("vulnerability", "CVE-2024-00000"),
						stringKV("package_name", "some-reasonably-long-package-name"),
						stringKV("package_version", "1.2.3-4ubuntu5.6"),
					},
				}},
			}},
		})
	}
	return out
}

// TestSendPhaseTimingsAreAttributed covers the split of send_ms into marshal,
// compress and http.
//
// The whole point of the split is to tell a CPU problem from a network one: a
// 30-second export where 18 seconds sat in "send" gave no basis for choosing
// between optimising serialisation, dropping compression, or blaming the
// receiver. A timer that silently stays at zero would be worse than no timer, so
// this asserts each phase is actually populated.
func TestSendPhaseTimingsAreAttributed(t *testing.T) {
	serverDelay := 150 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(serverDelay)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender, err := NewDirectOTLPSender(DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		Compression:    CompressionGzip,
		Timeout:        30 * time.Second,
		MaxRetries:     1,
		Insecure:       true,
		ServiceName:    "test",
		ServiceVersion: "1.0.0",
	})
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	if err := sender.Send(context.Background(), phaseTimingMetrics(2000)); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	stats := sender.Stats()

	if stats.MarshalNanos == 0 {
		t.Error("MarshalNanos = 0; protobuf marshalling is not being timed")
	}
	if stats.CompressNanos == 0 {
		t.Error("CompressNanos = 0; gzip is enabled but not being timed")
	}
	if stats.HTTPNanos == 0 {
		t.Error("HTTPNanos = 0; the round-trip is not being timed")
	}

	// The handler sleeps, so the HTTP phase must reflect that. This is what
	// distinguishes a genuine attribution from three timers wired to the same
	// clock — it pins the slow phase to the one that is actually slow.
	if stats.HTTPNanos < uint64(serverDelay) {
		t.Errorf("HTTPNanos = %v, want at least the server's %v delay — the round-trip "+
			"is being undercounted", time.Duration(stats.HTTPNanos), serverDelay)
	}
	if stats.MarshalNanos > uint64(serverDelay) {
		t.Errorf("MarshalNanos = %v exceeds the deliberately slow HTTP phase (%v); the "+
			"timers are probably measuring overlapping spans",
			time.Duration(stats.MarshalNanos), serverDelay)
	}
}

// TestCompressTimingZeroWhenDisabled guards against the compress timer picking up
// work that is not compression. With METRICS_COMPRESSION=none there is no gzip
// call at all, so a non-zero reading would mean the timer is wrapping something
// else and the attribution cannot be trusted.
func TestCompressTimingZeroWhenDisabled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if enc := r.Header.Get("Content-Encoding"); enc != "" {
			t.Errorf("Content-Encoding = %q, want empty with compression disabled", enc)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender, err := NewDirectOTLPSender(DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		Compression:    CompressionNone,
		Timeout:        30 * time.Second,
		MaxRetries:     1,
		Insecure:       true,
		ServiceName:    "test",
		ServiceVersion: "1.0.0",
	})
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	if err := sender.Send(context.Background(), phaseTimingMetrics(500)); err != nil {
		t.Fatalf("Send failed: %v", err)
	}

	stats := sender.Stats()
	if stats.CompressNanos != 0 {
		t.Errorf("CompressNanos = %d with compression disabled; the timer is measuring "+
			"something other than gzip", stats.CompressNanos)
	}
	if stats.MarshalNanos == 0 || stats.HTTPNanos == 0 {
		t.Error("marshal and http must still be timed when compression is off")
	}
}

// TestPhaseTimingsAccumulateAcrossSends confirms the counters are cumulative.
// The exporter logs per-cycle deltas against its own saved values, so a counter
// that reset per call would make every log line report a full total instead.
func TestPhaseTimingsAccumulateAcrossSends(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sender, err := NewDirectOTLPSender(DirectOTLPConfig{
		Endpoint:       server.URL,
		Protocol:       "http",
		Compression:    CompressionGzip,
		Timeout:        30 * time.Second,
		MaxRetries:     1,
		Insecure:       true,
		ServiceName:    "test",
		ServiceVersion: "1.0.0",
	})
	if err != nil {
		t.Fatalf("Failed to create sender: %v", err)
	}
	defer func() { _ = sender.Close() }()

	batch := phaseTimingMetrics(200)
	if err := sender.Send(context.Background(), batch); err != nil {
		t.Fatalf("first Send failed: %v", err)
	}
	first := sender.Stats()

	if err := sender.Send(context.Background(), batch); err != nil {
		t.Fatalf("second Send failed: %v", err)
	}
	second := sender.Stats()

	if second.HTTPNanos <= first.HTTPNanos {
		t.Errorf("HTTPNanos did not accumulate: %d then %d", first.HTTPNanos, second.HTTPNanos)
	}
	if second.MarshalNanos <= first.MarshalNanos {
		t.Errorf("MarshalNanos did not accumulate: %d then %d", first.MarshalNanos, second.MarshalNanos)
	}
}
