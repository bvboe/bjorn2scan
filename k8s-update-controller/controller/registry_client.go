package controller

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// RegistryClient handles OCI registry operations
type RegistryClient struct {
	chartRegistry string
}

// NewRegistryClient creates a new registry client
func NewRegistryClient(chartRegistry string) *RegistryClient {
	return &RegistryClient{
		chartRegistry: chartRegistry,
	}
}

// ListVersions lists all available chart versions from the OCI registry
func (rc *RegistryClient) ListVersions(ctx context.Context) ([]string, error) {
	// Parse OCI registry URL (e.g., "oci://ghcr.io/bvboe/b2s-go/bjorn2scan")
	registryURL := strings.TrimPrefix(rc.chartRegistry, "oci://")

	// Parse as OCI reference
	ref, err := name.ParseReference(registryURL)
	if err != nil {
		return nil, fmt.Errorf("invalid registry URL: %w", err)
	}

	// List tags
	tags, err := remote.List(ref.Context())
	if err != nil {
		return nil, fmt.Errorf("failed to list tags: %w", err)
	}

	// Filter out non-version tags (like 'latest', 'sha-*')
	versions := []string{}
	for _, tag := range tags {
		// Skip non-semantic version tags
		if tag == "latest" || strings.HasPrefix(tag, "sha-") {
			continue
		}
		versions = append(versions, tag)
	}

	return versions, nil
}

// DownloadChart downloads a specific chart version to a temporary directory
func (rc *RegistryClient) DownloadChart(ctx context.Context, version string) (string, error) {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "helm-chart-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Build chart reference
	registryURL := strings.TrimPrefix(rc.chartRegistry, "oci://")
	chartRef := fmt.Sprintf("%s:%s", registryURL, version)

	// Parse reference
	ref, err := name.ParseReference(chartRef)
	if err != nil {
		_ = os.RemoveAll(tmpDir) // Best effort cleanup
		return "", fmt.Errorf("invalid chart reference: %w", err)
	}

	// Pull OCI artifact (Helm chart)
	img, err := remote.Image(ref)
	if err != nil {
		_ = os.RemoveAll(tmpDir) // Best effort cleanup
		return "", fmt.Errorf("failed to pull chart: %w", err)
	}

	// Get the layers - Helm charts are stored as a single layer
	layers, err := img.Layers()
	if err != nil {
		_ = os.RemoveAll(tmpDir) // Best effort cleanup
		return "", fmt.Errorf("failed to get image layers: %w", err)
	}

	if len(layers) == 0 {
		_ = os.RemoveAll(tmpDir)
		return "", fmt.Errorf("chart image has no layers")
	}

	// Extract the first layer (contains the chart.tgz)
	layer := layers[0]
	layerReader, err := layer.Compressed()
	if err != nil {
		_ = os.RemoveAll(tmpDir) // Best effort cleanup
		return "", fmt.Errorf("failed to read layer: %w", err)
	}
	defer func() { _ = layerReader.Close() }()

	// Write layer content to file
	chartPath := filepath.Join(tmpDir, "chart.tgz")
	chartFile, err := os.Create(chartPath)
	if err != nil {
		_ = os.RemoveAll(tmpDir) // Best effort cleanup
		return "", fmt.Errorf("failed to create chart file: %w", err)
	}
	defer func() { _ = chartFile.Close() }()

	// Copy layer content to file
	if _, err := chartFile.ReadFrom(layerReader); err != nil {
		_ = os.RemoveAll(tmpDir) // Best effort cleanup
		return "", fmt.Errorf("failed to write chart file: %w", err)
	}

	return chartPath, nil
}

// VerifySignature verifies the Sigstore bundle for a downloaded Helm chart.
//
// The bundle is fetched from GitHub releases at:
//
//	<releaseBaseURL>/v<version>/bjorn2scan-<version>.tgz.sigstore
//
// It was produced by cosign sign-blob --bundle on the packaged chart. The
// chart content is identical regardless of whether it came from OCI or a
// GitHub release asset, so the digest in the bundle matches chartPath.
func (rc *RegistryClient) VerifySignature(ctx context.Context, chartPath, version, releaseBaseURL, identityRegexp, oidcIssuer string) error {
	// Build and download the bundle file
	bundleURL := fmt.Sprintf("%s/v%s/bjorn2scan-%s.tgz.sigstore", releaseBaseURL, version, version)
	bundlePath, err := downloadToTemp(ctx, bundleURL)
	if err != nil {
		return fmt.Errorf("failed to download signature bundle from %s: %w", bundleURL, err)
	}
	defer func() { _ = os.Remove(bundlePath) }()

	// Load the Sigstore bundle
	b, err := bundle.LoadJSONFromPath(bundlePath)
	if err != nil {
		return fmt.Errorf("failed to load signature bundle: %w", err)
	}

	// Fetch the Sigstore public-good trust root from TUF
	trustedRoot, err := root.FetchTrustedRoot()
	if err != nil {
		return fmt.Errorf("failed to fetch trusted root: %w", err)
	}

	// Require at least one transparency-log entry and one observer timestamp
	verifier, err := verify.NewVerifier(trustedRoot,
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return fmt.Errorf("failed to create verifier: %w", err)
	}

	// Read the chart content for artifact digest verification
	chartBytes, err := os.ReadFile(chartPath)
	if err != nil {
		return fmt.Errorf("failed to read chart: %w", err)
	}

	// Build the certificate identity policy
	certID, err := verify.NewShortCertificateIdentity(oidcIssuer, "", "", identityRegexp)
	if err != nil {
		return fmt.Errorf("invalid certificate identity: %w", err)
	}

	policy := verify.NewPolicy(
		verify.WithArtifact(bytes.NewReader(chartBytes)),
		verify.WithCertificateIdentity(certID),
	)

	if _, err := verifier.Verify(b, policy); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// downloadToTemp downloads a URL to a temporary file and returns its path.
// The caller is responsible for removing the file when done.
func downloadToTemp(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d downloading %s", resp.StatusCode, url)
	}

	f, err := os.CreateTemp("", "sigstore-bundle-*.sigstore")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := io.Copy(f, resp.Body); err != nil {
		_ = os.Remove(f.Name())
		return "", fmt.Errorf("failed to write bundle: %w", err)
	}

	return f.Name(), nil
}
