package grype

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"
)

// TestScanDoesNotLeakGoroutines guards the vulnerability-provider lifecycle.
//
// ScanVulnerabilitiesWithConfig opens the Grype database via curator.Reader()
// and wraps it in a vulnerability.Provider. That provider owns a *sql.DB, and
// database/sql starts one connectionOpener goroutine per *sql.DB which parks
// forever unless the handle is closed. Before the fix, every scan leaked one:
// kubeadm reached 808 of 843 goroutines in connectionOpener over 15 days, with
// container RSS at 685Mi against a stable ~350MB Go heap.
//
// The leak was invisible to every guard we had. It compiles, no test failed,
// the scan results were correct, and the Go heap looked healthy because the
// leaked memory is on the SQLite/CGO side. Only a goroutine count catches it,
// which is what this test asserts.
func TestScanDoesNotLeakGoroutines(t *testing.T) {
	// Integration test: runs real Grype scans, which need the vulnerability DB.
	if testing.Short() {
		t.Skip("skipping in -short: requires the Grype vulnerability database")
	}

	sbomJSON, err := os.ReadFile("testdata/nginx-1.15-sbom.json")
	if err != nil {
		t.Fatalf("failed to read SBOM: %v", err)
	}

	ctx := context.Background()

	// One warm-up scan first. The first call through this path initialises
	// package-level state in Grype and Syft (loggers, caches, the arch-alias
	// table) that legitimately starts goroutines and never releases them.
	// Counting from a cold process would attribute that one-time cost to the
	// per-scan path and make the threshold meaningless.
	if _, err := ScanVulnerabilitiesWithConfig(ctx, sbomJSON, Config{}); err != nil {
		t.Fatalf("warm-up scan failed: %v", err)
	}

	before := stableGoroutineCount()

	const scans = 5
	for i := 0; i < scans; i++ {
		if _, err := ScanVulnerabilitiesWithConfig(ctx, sbomJSON, Config{}); err != nil {
			t.Fatalf("scan %d failed: %v", i+1, err)
		}
	}

	after := stableGoroutineCount()
	growth := after - before

	// The leak was exactly one goroutine per scan, so the signal is
	// unmistakable: 5 scans meant +5. Allow a small margin for unrelated
	// background goroutines (HTTP keep-alives from the distribution client,
	// finalisers) that can settle either way between samples.
	const tolerance = 2
	if growth > tolerance {
		t.Errorf("goroutines grew by %d across %d scans (%d -> %d); the vulnerability "+
			"provider is not being closed, so each scan leaks a *sql.DB and its "+
			"connectionOpener goroutine",
			growth, scans, before, after)
	}
	t.Logf("goroutines %d -> %d across %d scans (growth %d, tolerance %d)",
		before, after, scans, growth, tolerance)
}

// stableGoroutineCount waits for the goroutine count to stop moving before
// reporting it. Scans leave transient goroutines behind for a short while
// (idle-connection reapers, HTTP transports winding down); sampling
// immediately makes the measurement flap and would produce a flaky test in
// both directions.
func stableGoroutineCount() int {
	prev := -1
	for i := 0; i < 40; i++ {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
		n := runtime.NumGoroutine()
		if n == prev {
			return n
		}
		prev = n
	}
	return prev
}
