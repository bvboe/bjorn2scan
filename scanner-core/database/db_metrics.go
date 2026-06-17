package database

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

// histBounds are the upper bounds (seconds) for histogram buckets.
var histBounds = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

// fpf writes formatted output to w, ignoring errors (best-effort metrics output).
func fpf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

type dbHistogram struct {
	mu      sync.Mutex
	count   uint64
	sum     float64
	buckets [13]uint64 // one per histBounds entry
}

func (h *dbHistogram) observe(v float64) {
	h.mu.Lock()
	h.count++
	h.sum += v
	for i, b := range histBounds {
		if v <= b {
			h.buckets[i]++
		}
	}
	h.mu.Unlock()
}

// snapshot returns a consistent copy under lock.
func (h *dbHistogram) snapshot() (count uint64, sum float64, buckets [13]uint64) {
	h.mu.Lock()
	count, sum, buckets = h.count, h.sum, h.buckets
	h.mu.Unlock()
	return
}

type dbHistogramVec struct {
	mu    sync.RWMutex
	hists map[string]*dbHistogram
}

func newDBHistogramVec() *dbHistogramVec {
	return &dbHistogramVec{hists: make(map[string]*dbHistogram)}
}

func (v *dbHistogramVec) observe(op string, val float64) {
	v.mu.RLock()
	h := v.hists[op]
	v.mu.RUnlock()
	if h == nil {
		v.mu.Lock()
		if h = v.hists[op]; h == nil {
			h = &dbHistogram{}
			v.hists[op] = h
		}
		v.mu.Unlock()
	}
	h.observe(val)
}

func (v *dbHistogramVec) isEmpty() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.hists) == 0
}

func (v *dbHistogramVec) write(w io.Writer, metricName, labelKey string) {
	v.mu.RLock()
	ops := make([]string, 0, len(v.hists))
	for op := range v.hists {
		ops = append(ops, op)
	}
	v.mu.RUnlock()
	sort.Strings(ops)
	for _, op := range ops {
		v.mu.RLock()
		h := v.hists[op]
		v.mu.RUnlock()
		count, sum, buckets := h.snapshot()
		labels := fmt.Sprintf("%s=%q", labelKey, op)
		for i, b := range histBounds {
			fpf(w, "%s_bucket{%s,le=\"%g\"} %d\n", metricName, labels, b, buckets[i])
		}
		fpf(w, "%s_bucket{%s,le=\"+Inf\"} %d\n", metricName, labels, count)
		fpf(w, "%s_sum{%s} %g\n", metricName, labels, sum)
		fpf(w, "%s_count{%s} %d\n", metricName, labels, count)
	}
}

// Package-level histogram vecs — zero-allocation on the read path after warm-up.
var (
	dbWriteWait = newDBHistogramVec() // time waiting to acquire writeMu
	dbWriteExec = newDBHistogramVec() // time holding writeMu (transaction execution)
	dbReadDur   = newDBHistogramVec() // time for read operations
)

// beginWrite acquires the write lock, records wait time, and returns a done
// function that records execution time and releases the lock.
//
// Usage (defer pattern):
//
//	done := db.beginWrite("operation_name")
//	defer done()
//
// Usage (explicit, no defer, e.g. lock released before function return):
//
//	done := db.beginWrite("operation_name")
//	// ... do work ...
//	done()
func (db *DB) beginWrite(op string) func() {
	waitStart := time.Now()
	db.writeMu.Lock()
	dbWriteWait.observe(op, time.Since(waitStart).Seconds())
	execStart := time.Now()
	return func() {
		dbWriteExec.observe(op, time.Since(execStart).Seconds())
		db.writeMu.Unlock()
	}
}

// trackRead measures the duration of a read operation.
func trackRead(op string, fn func() error) error {
	start := time.Now()
	err := fn()
	dbReadDur.observe(op, time.Since(start).Seconds())
	return err
}

// WriteOpMetrics writes database operation timing histograms in Prometheus text
// format to w. Called from StreamMetrics to include these at /metrics.
// Nothing is written if no operations have been observed yet.
func WriteOpMetrics(w io.Writer) {
	if !dbWriteWait.isEmpty() {
		fpf(w, "# HELP bjorn2scan_db_write_wait_seconds Time waiting to acquire the database write lock, by operation\n")
		fpf(w, "# TYPE bjorn2scan_db_write_wait_seconds histogram\n")
		dbWriteWait.write(w, "bjorn2scan_db_write_wait_seconds", "operation")
	}

	if !dbWriteExec.isEmpty() {
		fpf(w, "# HELP bjorn2scan_db_write_exec_seconds Time executing a write transaction (lock held), by operation\n")
		fpf(w, "# TYPE bjorn2scan_db_write_exec_seconds histogram\n")
		dbWriteExec.write(w, "bjorn2scan_db_write_exec_seconds", "operation")
	}

	if !dbReadDur.isEmpty() {
		fpf(w, "# HELP bjorn2scan_db_read_seconds Time executing a read operation, by operation\n")
		fpf(w, "# TYPE bjorn2scan_db_read_seconds histogram\n")
		dbReadDur.write(w, "bjorn2scan_db_read_seconds", "operation")
	}
}
