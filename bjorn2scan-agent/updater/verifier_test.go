package updater

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/tuf"
)

func TestNewVerifier(t *testing.T) {
	tests := []struct {
		name           string
		identityRegexp string
		oidcIssuer     string
	}{
		{
			name:           "valid configuration",
			identityRegexp: "https://github.com/bvboe/b2s-go/*",
			oidcIssuer:     "https://token.actions.githubusercontent.com",
		},
		{
			name:           "empty configuration",
			identityRegexp: "",
			oidcIssuer:     "",
		},
		{
			name:           "custom configuration",
			identityRegexp: "https://gitlab.com/custom/*",
			oidcIssuer:     "https://custom.issuer.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := NewVerifier(tt.identityRegexp, tt.oidcIssuer)
			if v == nil {
				t.Fatal("NewVerifier returned nil")
			}
			if v.identityRegexp != tt.identityRegexp {
				t.Errorf("identityRegexp = %q, want %q", v.identityRegexp, tt.identityRegexp)
			}
			if v.oidcIssuer != tt.oidcIssuer {
				t.Errorf("oidcIssuer = %q, want %q", v.oidcIssuer, tt.oidcIssuer)
			}
		})
	}
}

func TestVerifySignature_MissingBundleFile(t *testing.T) {
	v := NewVerifier("https://github.com/*", "https://token.actions.githubusercontent.com")

	tmpDir := t.TempDir()
	blobPath := filepath.Join(tmpDir, "blob.tar.gz")
	if err := os.WriteFile(blobPath, []byte("blob content"), 0600); err != nil {
		t.Fatal(err)
	}

	err := v.VerifySignature(blobPath, filepath.Join(tmpDir, "nonexistent.sigstore"))
	if err == nil {
		t.Error("expected error for missing bundle file, got nil")
	}
}

func TestVerifySignature_MissingBlobFile(t *testing.T) {
	v := NewVerifier("https://github.com/*", "https://token.actions.githubusercontent.com")

	tmpDir := t.TempDir()
	bundlePath := filepath.Join(tmpDir, "bundle.sigstore")
	// Write a syntactically valid but semantically invalid JSON bundle
	if err := os.WriteFile(bundlePath, []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.1"}`), 0600); err != nil {
		t.Fatal(err)
	}

	// Blob does not exist — should fail when trying to read it
	err := v.VerifySignature(filepath.Join(tmpDir, "nonexistent.tar.gz"), bundlePath)
	if err == nil {
		t.Error("expected error for missing blob file, got nil")
	}
}

func TestVerifySignature_MalformedBundle(t *testing.T) {
	v := NewVerifier("https://github.com/*", "https://token.actions.githubusercontent.com")

	tmpDir := t.TempDir()
	blobPath := filepath.Join(tmpDir, "blob.tar.gz")
	bundlePath := filepath.Join(tmpDir, "bundle.sigstore")

	if err := os.WriteFile(blobPath, []byte("blob content"), 0600); err != nil {
		t.Fatal(err)
	}
	// Write malformed JSON — bundle loading should fail
	if err := os.WriteFile(bundlePath, []byte(`not valid json`), 0600); err != nil {
		t.Fatal(err)
	}

	err := v.VerifySignature(blobPath, bundlePath)
	if err == nil {
		t.Error("expected error for malformed bundle, got nil")
	}
}

// TestTUFClient_DisableLocalCache_NoFilesystemWrite is a regression test for the
// ubuntu-server auto-update failure: when systemd ran the agent with a read-only
// filesystem, tuf.New() tried to mkdir $HOME/.sigstore and failed.
// WithDisableLocalCache() must prevent that mkdir.
func TestTUFClient_DisableLocalCache_NoFilesystemWrite(t *testing.T) {
	readOnlyDir := t.TempDir()
	if err := os.Chmod(readOnlyDir, 0o500); err != nil {
		t.Skip("cannot set read-only permissions on temp dir")
	}
	t.Setenv("HOME", readOnlyDir)

	// tuf.New() is the call that triggers mkdir — no network needed for this.
	_, err := tuf.New(tuf.DefaultOptions().WithDisableLocalCache())
	if err != nil && (strings.Contains(err.Error(), "read-only") || strings.Contains(err.Error(), "mkdir")) {
		t.Errorf("TUF client creation wrote to filesystem (regression): %v", err)
	}
}

func TestVerifySignature_EmptyBundle(t *testing.T) {
	v := NewVerifier("https://github.com/*", "https://token.actions.githubusercontent.com")

	tmpDir := t.TempDir()
	blobPath := filepath.Join(tmpDir, "blob.tar.gz")
	bundlePath := filepath.Join(tmpDir, "bundle.sigstore")

	if err := os.WriteFile(blobPath, []byte("blob content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundlePath, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}

	err := v.VerifySignature(blobPath, bundlePath)
	if err == nil {
		t.Error("expected error for empty bundle JSON, got nil")
	}
}
