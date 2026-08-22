package metrics

import (
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

// WriteRuntimeMetrics writes Go runtime memory and GC counters in Prometheus
// text format.
//
// These exist because memory, not latency, is the binding constraint on this
// exporter: a large deployment sits at ~2.6 GiB against a 4 GiB limit (1.58x
// headroom) while using only 2.4% of its push interval. Tuning that was
// guesswork — there was no pprof endpoint and no runtime metrics, so the only
// visibility was container RSS from `kubectl top`, which cannot distinguish a
// persistent working set from transient garbage awaiting collection.
//
// alloc_bytes_total is the important one for this workload. It is cumulative
// bytes allocated, so its rate is the garbage rate, and the dominant term is
// expected to be the per-cycle staleness batch — one row per series carrying a
// JSON copy of its labels, built and discarded every export.
//
// Written to /metrics only, like the bjorn2scan_db_* histograms: these are
// diagnostics for the process, not vulnerability data, and there is no reason to
// carry them over OTLP to every backend. Names follow the client_golang
// convention so existing dashboards and alerts work unchanged, but the exposition
// is hand-rolled to match the rest of this package and to keep the series count
// deliberate — 13 series, not the ~80 the standard collector emits.
func WriteRuntimeMetrics(w io.Writer) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	gauge := func(name, help, typ string, value uint64) {
		_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", name, help, name, typ, name, value)
	}

	// Live heap and what the runtime holds from the OS. heap_inuse minus
	// heap_alloc is fragmentation; sys minus released is what the container is
	// actually charged for.
	gauge("go_memstats_heap_alloc_bytes",
		"Bytes of allocated heap objects currently reachable", "gauge", m.HeapAlloc)
	gauge("go_memstats_heap_inuse_bytes",
		"Bytes in in-use heap spans", "gauge", m.HeapInuse)
	gauge("go_memstats_heap_sys_bytes",
		"Heap bytes obtained from the OS", "gauge", m.HeapSys)
	gauge("go_memstats_heap_released_bytes",
		"Heap bytes released back to the OS", "gauge", m.HeapReleased)
	gauge("go_memstats_heap_objects",
		"Number of allocated heap objects", "gauge", m.HeapObjects)

	// The GC target. Go's default GOGC=100 sets this to roughly twice the live
	// set, so every transient megabyte costs a second megabyte of headroom —
	// which is why per-cycle garbage dominates this process's footprint.
	gauge("go_memstats_next_gc_bytes",
		"Heap size target for the next GC cycle", "gauge", m.NextGC)

	// Cumulative. The rate of this is the garbage rate.
	gauge("go_memstats_alloc_bytes_total",
		"Cumulative bytes allocated for heap objects", "counter", m.TotalAlloc)
	gauge("go_memstats_mallocs_total",
		"Cumulative count of heap objects allocated", "counter", m.Mallocs)
	gauge("go_memstats_frees_total",
		"Cumulative count of heap objects freed", "counter", m.Frees)

	// Non-heap runtime overhead, so RSS can be reconciled against the heap.
	gauge("go_memstats_stack_inuse_bytes",
		"Bytes in stack spans", "gauge", m.StackInuse)
	gauge("go_memstats_sys_bytes",
		"Total bytes obtained from the OS", "gauge", m.Sys)

	gauge("go_gc_cycles_total",
		"Number of completed GC cycles", "counter", uint64(m.NumGC))
	_, _ = fmt.Fprintf(w,
		"# HELP go_gc_pause_seconds_total Cumulative time spent in GC stop-the-world pauses\n"+
			"# TYPE go_gc_pause_seconds_total counter\ngo_gc_pause_seconds_total %g\n",
		float64(m.PauseTotalNs)/1e9)

	_, _ = fmt.Fprintf(w,
		"# HELP go_goroutines Number of goroutines that currently exist\n"+
			"# TYPE go_goroutines gauge\ngo_goroutines %d\n", runtime.NumGoroutine())

	if limit := debug.SetMemoryLimit(-1); limit > 0 && limit < (1<<62) {
		gauge("go_memlimit_bytes",
			"Soft memory limit configured via GOMEMLIMIT", "gauge", uint64(limit))
	}
}
