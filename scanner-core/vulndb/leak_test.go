package vulndb

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
)

// TestDefaultDatabaseLoaderDoesNotLeakGoroutines guards the provider lifecycle
// on the database-updater path.
//
// grype.LoadVulnerabilityDB returns a provider that owns a SQLite handle
// alongside the status this function actually wants. Discarding it leaks the
// handle and database/sql's per-*sql.DB connectionOpener goroutine, which parks
// forever once the handle is unreachable.
//
// This path leaked for a release after the equivalent bug was fixed in the scan
// path (a7e8c15). It was missed because the search covered curator.Reader() and
// sql.Open call sites in scanner-core/grype but not LoadVulnerabilityDB callers
// in other packages — and because the existing regression test exercises
// ScanVulnerabilitiesWithConfig, which cannot reach this code. Production
// showed 31 leaked goroutines after 15h of uptime, matching the ~30 runs of the
// rescan-database job on its 30m interval.
//
// The leak here is driven by a timer rather than by scan volume, so it
// accumulated at the same rate on every deployment regardless of size.
func TestDefaultDatabaseLoaderDoesNotLeakGoroutines(t *testing.T) {
	// Integration test: needs a real Grype database on disk.
	if testing.Short() {
		t.Skip("skipping in -short: requires the Grype vulnerability database")
	}

	identification := clio.Identification{Name: "bjorn2scan-grype", Version: "1.0.0"}
	distCfg := distribution.DefaultConfig()
	distCfg.ID = identification
	installCfg := installation.DefaultConfig(identification)

	// Seed a private DB root from whatever database is already on the machine,
	// rather than using the default root for this identification. Two reasons:
	// the test must not mutate a real cache, and installation.DefaultConfig
	// derives its path from the identification Name, so it points somewhere
	// unrelated to the `grype` CLI's own cache and is usually empty.
	installCfg.DBRootDir = seedDBRoot(t)

	// update=false keeps this offline: load whatever is on disk, never fetch.
	// A test that reached the network would be measuring HTTP connection reuse
	// as much as the provider lifecycle.
	const update = false

	// Warm-up, and a guard against passing vacuously. LoadVulnerabilityDB
	// returns a nil provider on every error path — including the validateAge
	// rejection for a database older than 5 days — so a failed load means there
	// is nothing to leak and the assertion below would hold for the wrong
	// reason. Skip loudly instead of reporting a false pass.
	if _, err := defaultDatabaseLoader(distCfg, installCfg, update); err != nil {
		t.Skipf("no usable Grype DB (%v); run `grype db update` to refresh it. "+
			"Cannot verify the provider lifecycle without one.", err)
	}

	before := stableGoroutineCount()

	const loads = 5
	for i := 0; i < loads; i++ {
		if _, err := defaultDatabaseLoader(distCfg, installCfg, update); err != nil {
			t.Fatalf("load %d failed: %v", i+1, err)
		}
	}

	after := stableGoroutineCount()
	growth := after - before

	// The leak was exactly one goroutine per load, so 5 loads meant +5. The
	// tolerance covers unrelated background goroutines settling between samples.
	const tolerance = 2
	if growth > tolerance {
		t.Errorf("goroutines grew by %d across %d loads (%d -> %d); the provider "+
			"returned by LoadVulnerabilityDB is not being closed, so every "+
			"rescan-database run leaks a *sql.DB and its connectionOpener goroutine",
			growth, loads, before, after)
	}
	t.Logf("goroutines %d -> %d across %d loads (growth %d, tolerance %d)",
		before, after, loads, growth, tolerance)
}

// seedDBRoot copies an existing Grype v6 database into a temp directory and
// returns a DBRootDir pointing at it. Returns an empty root if no database is
// found, which the caller's warm-up load then reports as a skip.
func seedDBRoot(t *testing.T) string {
	t.Helper()

	root := filepath.Join(t.TempDir(), "db")
	if err := os.MkdirAll(filepath.Join(root, "6"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return root
	}
	// Both plausible locations for the grype CLI's cache across platforms.
	candidates := []string{
		filepath.Join(home, "Library", "Caches", "grype", "db", "6"),
		filepath.Join(home, ".cache", "grype", "db", "6"),
	}

	for _, src := range candidates {
		entries, err := os.ReadDir(src)
		if err != nil {
			continue
		}
		copied := false
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			b, err := os.ReadFile(filepath.Join(src, e.Name()))
			if err != nil {
				continue
			}
			if err := os.WriteFile(filepath.Join(root, "6", e.Name()), b, 0o644); err != nil {
				t.Fatalf("copy %s: %v", e.Name(), err)
			}
			copied = true
		}
		if copied {
			return root
		}
	}
	return root
}

// stableGoroutineCount waits for the goroutine count to settle before reporting
// it. Loading the database leaves transient goroutines behind briefly, so
// sampling immediately would make this flaky in both directions.
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
