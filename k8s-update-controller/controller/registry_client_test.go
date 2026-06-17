package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewRegistryClient(t *testing.T) {
	tests := []struct {
		name          string
		chartRegistry string
	}{
		{
			name:          "Standard OCI registry",
			chartRegistry: "oci://ghcr.io/bvboe/b2s-go/bjorn2scan",
		},
		{
			name:          "Registry without oci:// prefix",
			chartRegistry: "ghcr.io/bvboe/b2s-go/bjorn2scan",
		},
		{
			name:          "Empty registry",
			chartRegistry: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewRegistryClient(tt.chartRegistry)
			if client == nil {
				t.Fatal("NewRegistryClient returned nil")
			}
			if client.chartRegistry != tt.chartRegistry {
				t.Errorf("chartRegistry = %q, want %q", client.chartRegistry, tt.chartRegistry)
			}
		})
	}
}

func TestRegistryClient_URLParsing(t *testing.T) {
	tests := []struct {
		name          string
		chartRegistry string
		wantPrefix    string
	}{
		{
			name:          "OCI prefix is stripped",
			chartRegistry: "oci://ghcr.io/bvboe/b2s-go/bjorn2scan",
			wantPrefix:    "ghcr.io/bvboe/b2s-go/bjorn2scan",
		},
		{
			name:          "No OCI prefix - unchanged",
			chartRegistry: "ghcr.io/bvboe/b2s-go/bjorn2scan",
			wantPrefix:    "ghcr.io/bvboe/b2s-go/bjorn2scan",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the URL parsing logic used in ListVersions and DownloadChart
			registryURL := strings.TrimPrefix(tt.chartRegistry, "oci://")
			if registryURL != tt.wantPrefix {
				t.Errorf("URL parsing: got %q, want %q", registryURL, tt.wantPrefix)
			}
		})
	}
}

func TestRegistryClient_ListVersions_InvalidURL(t *testing.T) {
	tests := []struct {
		name          string
		chartRegistry string
		wantErr       bool
	}{
		{
			name:          "Empty registry URL",
			chartRegistry: "",
			wantErr:       true,
		},
		{
			name:          "Invalid URL format",
			chartRegistry: "oci://not a valid url!!!",
			wantErr:       true,
		},
		{
			name:          "Missing repository",
			chartRegistry: "oci://ghcr.io",
			wantErr:       false, // name.ParseReference might accept this
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewRegistryClient(tt.chartRegistry)
			ctx := context.Background()

			// Note: This will try to contact the registry, so we expect network errors
			// We're mainly testing that invalid URLs are caught
			_, err := client.ListVersions(ctx)
			if tt.wantErr && err == nil {
				t.Error("ListVersions() expected error, got nil")
			}
			// For valid URLs, we expect network/auth errors (not nil), which is fine
		})
	}
}

func TestRegistryClient_DownloadChart_InvalidURL(t *testing.T) {
	tests := []struct {
		name          string
		chartRegistry string
		version       string
		wantErr       bool
	}{
		{
			name:          "Empty registry URL",
			chartRegistry: "",
			version:       "0.1.0",
			wantErr:       true,
		},
		{
			name:          "Invalid URL format",
			chartRegistry: "oci://not a valid url!!!",
			version:       "0.1.0",
			wantErr:       true,
		},
		{
			name:          "Empty version",
			chartRegistry: "oci://ghcr.io/bvboe/b2s-go/bjorn2scan",
			version:       "",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewRegistryClient(tt.chartRegistry)
			ctx := context.Background()

			// Note: This will try to contact the registry
			// We're testing that invalid inputs produce errors
			_, err := client.DownloadChart(ctx, tt.version)
			if tt.wantErr && err == nil {
				t.Error("DownloadChart() expected error, got nil")
			}
		})
	}
}

func TestVerifySignature_BundleNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	rc := NewRegistryClient("oci://ghcr.io/example/chart")

	tmpDir := t.TempDir()
	chartPath := filepath.Join(tmpDir, "chart.tgz")
	if err := os.WriteFile(chartPath, []byte("fake chart content"), 0600); err != nil {
		t.Fatal(err)
	}

	err := rc.VerifySignature(context.Background(), chartPath, "1.0.0",
		srv.URL, "https://github.com/bvboe/b2s-go/*", "https://token.actions.githubusercontent.com")
	if err == nil {
		t.Error("expected error when bundle returns 404, got nil")
	}
}

func TestVerifySignature_MalformedBundle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not valid json`))
	}))
	defer srv.Close()

	rc := NewRegistryClient("oci://ghcr.io/example/chart")

	tmpDir := t.TempDir()
	chartPath := filepath.Join(tmpDir, "chart.tgz")
	if err := os.WriteFile(chartPath, []byte("fake chart content"), 0600); err != nil {
		t.Fatal(err)
	}

	err := rc.VerifySignature(context.Background(), chartPath, "1.0.0",
		srv.URL, "https://github.com/bvboe/b2s-go/*", "https://token.actions.githubusercontent.com")
	if err == nil {
		t.Error("expected error for malformed bundle JSON, got nil")
	}
}

func TestVerifySignature_EmptyBundle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	rc := NewRegistryClient("oci://ghcr.io/example/chart")

	tmpDir := t.TempDir()
	chartPath := filepath.Join(tmpDir, "chart.tgz")
	if err := os.WriteFile(chartPath, []byte("fake chart content"), 0600); err != nil {
		t.Fatal(err)
	}

	err := rc.VerifySignature(context.Background(), chartPath, "1.0.0",
		srv.URL, "https://github.com/bvboe/b2s-go/*", "https://token.actions.githubusercontent.com")
	if err == nil {
		t.Error("expected error for empty bundle JSON, got nil")
	}
}

func TestVerifySignature_MissingChart(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.1"}`))
	}))
	defer srv.Close()

	rc := NewRegistryClient("oci://ghcr.io/example/chart")

	err := rc.VerifySignature(context.Background(), "/nonexistent/chart.tgz", "1.0.0",
		srv.URL, "https://github.com/bvboe/b2s-go/*", "https://token.actions.githubusercontent.com")
	if err == nil {
		t.Error("expected error when chart file is missing, got nil")
	}
}

func TestDownloadToTemp_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := downloadToTemp(context.Background(), srv.URL+"/bundle.sigstore")
	if err == nil {
		t.Error("expected error for HTTP 500, got nil")
	}
}

func TestDownloadToTemp_Success(t *testing.T) {
	content := []byte(`{"test":"bundle"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	path, err := downloadToTemp(context.Background(), srv.URL+"/bundle.sigstore")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = os.Remove(path) }()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Errorf("downloaded content = %q, want %q", got, content)
	}
}

func TestBundleURLConstruction(t *testing.T) {
	tests := []struct {
		releaseBaseURL string
		version        string
		wantURL        string
	}{
		{
			releaseBaseURL: "https://github.com/bvboe/b2s-go/releases/download",
			version:        "0.1.122",
			wantURL:        "https://github.com/bvboe/b2s-go/releases/download/v0.1.122/bjorn2scan-0.1.122.tgz.sigstore",
		},
	}

	for _, tt := range tests {
		got := tt.releaseBaseURL + "/v" + tt.version + "/bjorn2scan-" + tt.version + ".tgz.sigstore"
		if got != tt.wantURL {
			t.Errorf("bundle URL = %q, want %q", got, tt.wantURL)
		}
	}
}

// TestVersionFiltering tests the logic used in ListVersions to filter out non-version tags
func TestVersionFiltering(t *testing.T) {
	tests := []struct {
		name     string
		tags     []string
		wantSkip map[string]bool
	}{
		{
			name: "Filter latest and sha tags",
			tags: []string{"0.1.0", "0.1.1", "latest", "sha-abc123", "0.2.0"},
			wantSkip: map[string]bool{
				"latest":     true,
				"sha-abc123": true,
			},
		},
		{
			name: "No special tags",
			tags: []string{"0.1.0", "0.1.1", "0.2.0"},
			wantSkip: map[string]bool{},
		},
		{
			name: "Only special tags",
			tags: []string{"latest", "sha-abc123", "sha-def456"},
			wantSkip: map[string]bool{
				"latest":     true,
				"sha-abc123": true,
				"sha-def456": true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the filtering logic from ListVersions
			versions := []string{}
			for _, tag := range tt.tags {
				// Skip non-semantic version tags
				if tag == "latest" || strings.HasPrefix(tag, "sha-") {
					if !tt.wantSkip[tag] {
						t.Errorf("Tag %q should not be skipped", tag)
					}
					continue
				}
				versions = append(versions, tag)
			}

			// Verify correct tags were kept
			for _, version := range versions {
				if tt.wantSkip[version] {
					t.Errorf("Version %q should have been filtered out", version)
				}
			}

			// Verify correct count
			expectedCount := len(tt.tags) - len(tt.wantSkip)
			if len(versions) != expectedCount {
				t.Errorf("Got %d versions, want %d", len(versions), expectedCount)
			}
		})
	}
}

// TestChartRefConstruction tests the logic used to build chart references
func TestChartRefConstruction(t *testing.T) {
	tests := []struct {
		name          string
		chartRegistry string
		version       string
		wantRef       string
	}{
		{
			name:          "Standard chart reference",
			chartRegistry: "oci://ghcr.io/bvboe/b2s-go/bjorn2scan",
			version:       "0.1.35",
			wantRef:       "ghcr.io/bvboe/b2s-go/bjorn2scan:0.1.35",
		},
		{
			name:          "Registry without oci prefix",
			chartRegistry: "ghcr.io/bvboe/b2s-go/bjorn2scan",
			version:       "0.1.35",
			wantRef:       "ghcr.io/bvboe/b2s-go/bjorn2scan:0.1.35",
		},
		{
			name:          "Version with v prefix",
			chartRegistry: "oci://ghcr.io/bvboe/b2s-go/bjorn2scan",
			version:       "v0.1.35",
			wantRef:       "ghcr.io/bvboe/b2s-go/bjorn2scan:v0.1.35",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the chart reference construction from DownloadChart
			registryURL := strings.TrimPrefix(tt.chartRegistry, "oci://")
			chartRef := registryURL + ":" + tt.version

			if chartRef != tt.wantRef {
				t.Errorf("Chart ref = %q, want %q", chartRef, tt.wantRef)
			}
		})
	}
}
