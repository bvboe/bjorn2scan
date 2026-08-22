package metrics

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
)

// parseExposition pulls metric name -> value out of Prometheus text output,
// ignoring HELP and TYPE lines.
func parseExposition(t *testing.T, s string) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for _, line := range strings.Split(s, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			t.Fatalf("malformed exposition line: %q", line)
		}
		v, err := strconv.ParseFloat(parts[1], 64)
		if err != nil {
			t.Fatalf("unparseable value in %q: %v", line, err)
		}
		out[parts[0]] = v
	}
	return out
}

// TestWriteRuntimeMetricsEmitsWhatMemoryWorkNeeds pins the specific series this
// was added for. Memory is the binding constraint on this exporter (~2.6 GiB
// against a 4 GiB limit) and there was previously no visibility beyond container
// RSS, which cannot separate a persistent working set from transient garbage.
func TestWriteRuntimeMetricsEmitsWhatMemoryWorkNeeds(t *testing.T) {
	var buf bytes.Buffer
	WriteRuntimeMetrics(&buf)
	got := parseExposition(t, buf.String())

	required := []string{
		// live heap and what the runtime holds from the OS
		"go_memstats_heap_alloc_bytes",
		"go_memstats_heap_inuse_bytes",
		"go_memstats_heap_sys_bytes",
		"go_memstats_heap_released_bytes",
		"go_memstats_heap_objects",
		// GC target: at GOGC=100 this is ~2x the live set, which is why transient
		// garbage costs double
		"go_memstats_next_gc_bytes",
		// cumulative allocation — its rate is the garbage rate, the number the
		// staleness-batch work is meant to move
		"go_memstats_alloc_bytes_total",
		"go_memstats_mallocs_total",
		"go_memstats_frees_total",
		// non-heap, so RSS can be reconciled against the heap
		"go_memstats_stack_inuse_bytes",
		"go_memstats_sys_bytes",
		"go_gc_cycles_total",
		"go_gc_pause_seconds_total",
		"go_goroutines",
	}

	for _, name := range required {
		if _, ok := got[name]; !ok {
			t.Errorf("%s missing; memory work depends on it", name)
		}
	}

	// Sanity: a running Go process always has a non-zero heap and at least one
	// goroutine. Zeroes here would mean ReadMemStats was not actually consulted.
	for _, name := range []string{"go_memstats_heap_alloc_bytes", "go_memstats_sys_bytes", "go_goroutines"} {
		if got[name] <= 0 {
			t.Errorf("%s = %v, want > 0", name, got[name])
		}
	}
}

// TestRuntimeMetricsCardinalityIsBounded matters because this project's central
// problem is series count. Diagnostics must not become part of it: the standard
// client_golang collector emits ~80 series, this emits a deliberate handful, and
// none of them carry labels.
func TestRuntimeMetricsCardinalityIsBounded(t *testing.T) {
	var buf bytes.Buffer
	WriteRuntimeMetrics(&buf)
	got := parseExposition(t, buf.String())

	const maxSeries = 20
	if len(got) > maxSeries {
		t.Errorf("emitted %d series, want at most %d — runtime diagnostics should not "+
			"add meaningfully to cardinality", len(got), maxSeries)
	}
	for name := range got {
		if strings.Contains(name, "{") {
			t.Errorf("%s carries labels; runtime metrics must stay label-free", name)
		}
	}
}

// TestAllocBytesTotalIsCumulative is the guard on the single most useful series
// here. If it were ever wired to a gauge that resets, rate() would silently
// return nonsense and the garbage-rate measurements would be wrong rather than
// obviously broken.
func TestAllocBytesTotalIsCumulative(t *testing.T) {
	var first bytes.Buffer
	WriteRuntimeMetrics(&first)
	before := parseExposition(t, first.String())["go_memstats_alloc_bytes_total"]

	// Allocate something the compiler cannot elide.
	sink := make([][]byte, 0, 256)
	for i := 0; i < 256; i++ {
		b := make([]byte, 4096)
		b[0] = byte(i)
		sink = append(sink, b)
	}
	if len(sink) != 256 {
		t.Fatal("allocation elided")
	}

	var second bytes.Buffer
	WriteRuntimeMetrics(&second)
	after := parseExposition(t, second.String())["go_memstats_alloc_bytes_total"]

	if after <= before {
		t.Errorf("go_memstats_alloc_bytes_total did not increase after ~1 MiB of "+
			"allocation: %v then %v", before, after)
	}
}

// TestRuntimeMetricsExpositionIsWellFormed checks every series has HELP and TYPE.
// A missing TYPE makes Prometheus guess, and an untyped counter silently loses
// rate() semantics.
func TestRuntimeMetricsExpositionIsWellFormed(t *testing.T) {
	var buf bytes.Buffer
	WriteRuntimeMetrics(&buf)
	text := buf.String()

	for name := range parseExposition(t, text) {
		if !strings.Contains(text, "# HELP "+name+" ") {
			t.Errorf("%s has no HELP line", name)
		}
		if !strings.Contains(text, "# TYPE "+name+" ") {
			t.Errorf("%s has no TYPE line", name)
		}
	}

	// The cumulative ones must be declared counters, not gauges.
	for _, name := range []string{
		"go_memstats_alloc_bytes_total", "go_memstats_mallocs_total",
		"go_memstats_frees_total", "go_gc_cycles_total", "go_gc_pause_seconds_total",
	} {
		if !strings.Contains(text, "# TYPE "+name+" counter") {
			t.Errorf("%s should be declared a counter", name)
		}
	}
}
