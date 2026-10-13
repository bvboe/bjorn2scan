package grype

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anchore/clio"
	v6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"
	"github.com/anchore/grype/grype/db/v6/installation"
)

// TestDBLoadCostBreakdown decomposes what ScanVulnerabilitiesWithConfig pays
// before it matches a single package.
//
// Motivation: an EKS deployment logged "loaded vulnerability database
// successfully duration=23.7s" on every scan — seven times in thirteen
// minutes. Reading the grype source suggests curator.Reader() -> Status() ->
// validateIntegrity() streams the entire database through a hash on every
// call, unconditionally (the ValidateChecksum config gates whether the
// resulting error is acted on, not whether the hash runs). But that is
// inference from code, and Reader() does several other things — opens SQLite,
// reads metadata, checks whether rehydration is needed, and can rehydrate.
// This measures which part actually costs, rather than assuming.
//
// The key separation is disk versus CPU. A plain io.Copy to io.Discard reads
// the same bytes with no hashing, so:
//
//	readOnly              = pure I/O cost
//	Status() - readOnly   = hashing + description read
//	Reader() - Status()   = SQLite open + metadata + rehydration check
//
// That matters because the remedy differs: if it is I/O bound, provisioning
// storage throughput fixes it with no code change; if it is CPU bound, only
// avoiding the work helps.
func TestDBLoadCostBreakdown(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short: requires the Grype vulnerability database")
	}

	dbRoot := findDBRoot(t)
	dbFile := filepath.Join(dbRoot, "6", "vulnerability.db")

	fi, err := os.Stat(dbFile)
	if err != nil {
		t.Skipf("no database at %s (%v); run `grype db update`", dbFile, err)
	}
	sizeGB := float64(fi.Size()) / (1 << 30)
	t.Logf("database: %s (%.2f GiB)", dbFile, sizeGB)

	identification := clio.Identification{Name: "bjorn2scan-grype", Version: "1.0.0"}
	distCfg := distribution.DefaultConfig()
	distCfg.ID = identification
	installCfg := installation.DefaultConfig(identification)
	installCfg.DBRootDir = dbRoot

	sbomJSON, err := os.ReadFile("testdata/nginx-1.15-sbom.json")
	if err != nil {
		t.Fatalf("read SBOM fixture: %v", err)
	}

	// Three passes. The first may read cold; later ones show the warm-cache
	// floor. On a developer machine with enough RAM the file stays cached, so
	// these numbers are the CPU-bound lower bound — the EKS figures are the
	// same work against storage that cannot serve it from memory.
	const passes = 3
	for i := 1; i <= passes; i++ {
		readOnly := timeIt(func() {
			f, err := os.Open(dbFile)
			if err != nil {
				t.Fatalf("open db: %v", err)
			}
			defer func() { _ = f.Close() }()
			if _, err := io.Copy(io.Discard, f); err != nil {
				t.Fatalf("read db: %v", err)
			}
		})

		distClient, err := distribution.NewClient(distCfg)
		if err != nil {
			t.Fatalf("distribution client: %v", err)
		}
		curator, err := installation.NewCurator(installCfg, distClient)
		if err != nil {
			t.Fatalf("curator: %v", err)
		}

		statusDur := timeIt(func() { _ = curator.Status() })

		var rdr v6.Reader
		readerDur := timeIt(func() {
			var rerr error
			rdr, rerr = curator.Reader()
			if rerr != nil {
				t.Fatalf("reader: %v", rerr)
			}
		})

		providerDur := timeIt(func() { _ = v6.NewVulnerabilityProvider(rdr) })

		// Close what we opened; the provider wraps the reader and owns it.
		if c, ok := any(rdr).(io.Closer); ok {
			_ = c.Close()
		}

		scanDur := timeIt(func() {
			if _, err := ScanVulnerabilitiesWithConfig(t.Context(), sbomJSON, Config{DBRootDir: ""}); err != nil {
				t.Fatalf("scan: %v", err)
			}
		})

		t.Logf("pass %d: read-only=%-8s status=%-8s reader=%-8s provider=%-8s fullscan=%-8s  | read throughput=%s",
			i,
			round(readOnly), round(statusDur), round(readerDur), round(providerDur), round(scanDur),
			throughput(fi.Size(), readOnly))
		t.Logf("         hash+desc (status-read)=%-8s  open+meta+rehydrate-check (reader-status)=%s",
			round(statusDur-readOnly), round(readerDur-statusDur))
	}

	t.Log("note: ScanVulnerabilitiesWithConfig uses the DEFAULT db root, not the " +
		"one measured above, so fullscan is only comparable if they are the same path")
}

// TestReaderConstructionAlternatives compares the two ways to obtain a
// vulnerability.Provider, which is the whole question for optimising the scan
// path:
//
//	curator.Reader()  — what we call today. Runs Status() first, which hashes
//	                    the entire database, then opens SQLite, reads metadata
//	                    and checks whether rehydration is needed.
//	v6.NewReader()    — what curator.Reader() calls internally after Status().
//	                    Opens SQLite and validates the schema model version
//	                    (newStore errors with "not a v6 database"), but never
//	                    touches the bulk of the file.
//
// Both yield a Reader that v6.NewVulnerabilityProvider accepts, so the
// substitution is mechanical. What it gives up is the per-call integrity hash
// and the rehydration check — neither of which this code path uses the result
// of, and both of which the rescan-database job still performs on its own
// schedule.
func TestReaderConstructionAlternatives(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short: requires the Grype vulnerability database")
	}

	dbRoot := findDBRoot(t)
	dbDir := filepath.Join(dbRoot, "6")
	if _, err := os.Stat(filepath.Join(dbDir, "vulnerability.db")); err != nil {
		t.Skipf("no database at %s: %v", dbDir, err)
	}

	identification := clio.Identification{Name: "bjorn2scan-grype", Version: "1.0.0"}
	distCfg := distribution.DefaultConfig()
	distCfg.ID = identification
	installCfg := installation.DefaultConfig(identification)
	installCfg.DBRootDir = dbRoot

	const passes = 3
	for i := 1; i <= passes; i++ {
		// Current path.
		var viaCurator time.Duration
		{
			distClient, err := distribution.NewClient(distCfg)
			if err != nil {
				t.Fatalf("distribution client: %v", err)
			}
			cur, err := installation.NewCurator(installCfg, distClient)
			if err != nil {
				t.Fatalf("curator: %v", err)
			}
			viaCurator = timeIt(func() {
				rdr, rerr := cur.Reader()
				if rerr != nil {
					t.Fatalf("curator.Reader: %v", rerr)
				}
				p := v6.NewVulnerabilityProvider(rdr)
				if cerr := p.Close(); cerr != nil {
					t.Fatalf("close: %v", cerr)
				}
			})
		}

		// Proposed path.
		viaNewReader := timeIt(func() {
			rdr, rerr := v6.NewReader(v6.Config{DBDirPath: dbDir})
			if rerr != nil {
				t.Fatalf("v6.NewReader: %v", rerr)
			}
			p := v6.NewVulnerabilityProvider(rdr)
			if cerr := p.Close(); cerr != nil {
				t.Fatalf("close: %v", cerr)
			}
		})

		speedup := float64(viaCurator) / float64(max(viaNewReader, 1))
		t.Logf("pass %d: curator.Reader()=%-9s v6.NewReader()=%-9s  saving=%-9s (%.0fx)",
			i, round(viaCurator), round(viaNewReader),
			round(viaCurator-viaNewReader), speedup)
	}
}

// findDBRoot returns a directory containing a 6/vulnerability.db, preferring
// the root this project configures and falling back to the grype CLI's own
// cache. Nothing is copied — a 3 GiB copy per run would dominate the very
// measurement being taken.
func findDBRoot(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("cannot determine home directory: %v", err)
	}
	candidates := []string{
		filepath.Join(home, "Library", "Caches", "bjorn2scan-grype", "db"),
		filepath.Join(home, ".cache", "bjorn2scan-grype", "db"),
		filepath.Join(home, "Library", "Caches", "grype", "db"),
		filepath.Join(home, ".cache", "grype", "db"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "6", "vulnerability.db")); err == nil {
			return c
		}
	}
	t.Skip("no grype database found; run `grype db update`")
	return ""
}

func timeIt(fn func()) time.Duration {
	start := time.Now()
	fn()
	return time.Since(start)
}

func round(d time.Duration) string { return d.Round(time.Millisecond).String() }

func throughput(bytes int64, d time.Duration) string {
	if d <= 0 {
		return "n/a"
	}
	mbps := (float64(bytes) / (1 << 20)) / d.Seconds()
	return fmt.Sprintf("%.0f MB/s", mbps)
}
