package vulndb

import (
	"errors"
	"testing"
	"time"

	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

// fakeProvider is a vulnerability.Provider that records whether it was closed.
// The interface is only four methods, so a hand-written fake is cheaper than a
// generated mock and keeps the assertion obvious.
type fakeProvider struct {
	closes   int
	closeErr error
}

func (f *fakeProvider) Close() error {
	f.closes++
	return f.closeErr
}

func (f *fakeProvider) PackageSearchNames(grypePkg.Package) []string { return nil }

func (f *fakeProvider) FindVulnerabilities(...vulnerability.Criteria) ([]vulnerability.Vulnerability, error) {
	return nil, nil
}

func (f *fakeProvider) VulnerabilityMetadata(vulnerability.Reference) (*vulnerability.Metadata, error) {
	return nil, nil
}

// TestStatusFromLoadClosesProvider is the CI-visible guard for the defect that
// leaked twice: a resource-owning return value from LoadVulnerabilityDB being
// dropped instead of closed.
//
// The goroutine-counting tests in this package and in scanner-core/grype prove
// the runtime consequence, but both need a real Grype database and are skipped
// by -short — which is how CI runs scanner-core, so neither protects a pull
// request. This one needs no database and no network, so it actually runs.
//
// It asserts the contract rather than the symptom: whatever provider comes back
// gets closed exactly once. That is the thing that was violated, and it is
// cheap to keep honest.
func TestStatusFromLoadClosesProvider(t *testing.T) {
	built := time.Date(2026, 9, 22, 6, 30, 41, 0, time.UTC)
	status := &vulnerability.ProviderStatus{
		Built:         built,
		SchemaVersion: "6",
		Path:          "/var/lib/bjorn2scan/grype/6/vulnerability.db",
	}

	provider := &fakeProvider{}
	got, err := statusFromLoad(provider, status, nil)
	if err != nil {
		t.Fatalf("statusFromLoad returned %v", err)
	}

	if provider.closes != 1 {
		t.Errorf("provider closed %d times, want exactly 1; it owns a SQLite handle and "+
			"database/sql parks a connectionOpener goroutine per unclosed *sql.DB",
			provider.closes)
	}

	// The projection still has to be right — closing the handle must not cost us
	// the status the caller asked for.
	if !got.Built.Equal(built) {
		t.Errorf("Built = %v, want %v", got.Built, built)
	}
	if got.SchemaVersion != status.SchemaVersion || got.Path != status.Path {
		t.Errorf("got (%q, %q), want (%q, %q)",
			got.SchemaVersion, got.Path, status.SchemaVersion, status.Path)
	}
}

// TestStatusFromLoadClosesProviderOnError covers the case where a load both
// returns a provider and fails. Ownership does not depend on success, so the
// handle must still be released — and the error must still reach the caller,
// because the rescan-database job's trust-the-disk fallback depends on seeing
// it.
func TestStatusFromLoadClosesProviderOnError(t *testing.T) {
	loadErr := errors.New("the vulnerability database was built 2 weeks ago")
	provider := &fakeProvider{}

	got, err := statusFromLoad(provider, nil, loadErr)

	if !errors.Is(err, loadErr) {
		t.Errorf("err = %v, want the load error passed through", err)
	}
	if got != nil {
		t.Errorf("got %+v, want nil status alongside an error", got)
	}
	if provider.closes != 1 {
		t.Errorf("provider closed %d times on the error path, want 1", provider.closes)
	}
}

// TestStatusFromLoadNilProvider is the shape LoadVulnerabilityDB actually
// returns on failure — nil provider, nil status, non-nil error. It must not
// panic, which is why the nil check in statusFromLoad is required rather than
// defensive padding.
func TestStatusFromLoadNilProvider(t *testing.T) {
	loadErr := errors.New("unable to create db reader")

	got, err := statusFromLoad(nil, nil, loadErr)
	if !errors.Is(err, loadErr) {
		t.Errorf("err = %v, want the load error passed through", err)
	}
	if got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

// TestStatusFromLoadCloseErrorIsNotFatal pins that a failing Close is logged
// and swallowed rather than surfaced. A close error means the handle is already
// in a bad state; failing the database check over it would stop rescans
// entirely for a condition the caller cannot act on.
func TestStatusFromLoadCloseErrorIsNotFatal(t *testing.T) {
	provider := &fakeProvider{closeErr: errors.New("close failed")}
	status := &vulnerability.ProviderStatus{Built: time.Now(), SchemaVersion: "6"}

	got, err := statusFromLoad(provider, status, nil)
	if err != nil {
		t.Errorf("err = %v, want nil: a Close failure must not fail the load", err)
	}
	if got == nil {
		t.Fatal("got nil status despite a successful load")
	}
}

// TestStatusFromLoadMissingStatus guards the one combination the library should
// never produce: success with no status. Returning it unchecked would
// nil-dereference, so this pins the error instead.
func TestStatusFromLoadMissingStatus(t *testing.T) {
	provider := &fakeProvider{}

	got, err := statusFromLoad(provider, nil, nil)
	if err == nil {
		t.Error("expected an error when the load reports success with no status")
	}
	if got != nil {
		t.Errorf("got %+v, want nil", got)
	}
	if provider.closes != 1 {
		t.Errorf("provider closed %d times, want 1 even on this path", provider.closes)
	}
}
