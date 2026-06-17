package updater

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

)


// Downloader handles downloading and verifying release assets
type Downloader struct {
	httpDownloader *HTTPDownloader
	workDir        string
}

// DownloaderConfig contains configuration for the downloader
type DownloaderConfig struct {
	AssetBaseURL     string
	MaxRetries       int
	EnableValidation bool
}

// NewDownloader creates a new downloader
func NewDownloader(assetBaseURL string) (*Downloader, error) {
	return NewDownloaderWithConfig(&DownloaderConfig{
		AssetBaseURL:     assetBaseURL,
		MaxRetries:       3,
		EnableValidation: true,
	})
}

// NewDownloaderWithConfig creates a new downloader with custom configuration
func NewDownloaderWithConfig(config *DownloaderConfig) (*Downloader, error) {
	// Create temporary work directory
	workDir, err := os.MkdirTemp("", "bjorn2scan-update-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create work directory: %w", err)
	}

	httpDownloader := NewHTTPDownloader(config.AssetBaseURL)
	httpDownloader.SetMaxRetries(config.MaxRetries)
	httpDownloader.SetValidation(config.EnableValidation)

	return &Downloader{
		httpDownloader: httpDownloader,
		workDir:        workDir,
	}, nil
}

// DownloadRelease downloads the binary, checksum, signature, and certificate for a release
func (d *Downloader) DownloadRelease(ctx context.Context, version string) (string, error) {
	// Download all assets using HTTP downloader
	binaryPath, err := d.httpDownloader.DownloadReleaseAssets(ctx, version, d.workDir)
	if err != nil {
		return "", err
	}

	// Verify checksum
	log := log
	arch := runtime.GOARCH
	checksumName := fmt.Sprintf("bjorn2scan-agent-linux-%s.tar.gz.sha256", arch)
	checksumPath := filepath.Join(d.workDir, checksumName)

	log.Info("verifying checksum")
	if err := d.VerifyChecksum(binaryPath, checksumPath); err != nil {
		return "", fmt.Errorf("checksum verification failed: %w", err)
	}
	log.Info("checksum verified")

	return binaryPath, nil
}

// VerifyChecksum verifies the SHA256 checksum of a file
func (d *Downloader) VerifyChecksum(filePath, checksumPath string) error {
	// Read expected checksum
	checksumData, err := os.ReadFile(checksumPath)
	if err != nil {
		return fmt.Errorf("failed to read checksum file: %w", err)
	}

	// Parse checksum (format: "hash  filename")
	parts := strings.Fields(string(checksumData))
	if len(parts) < 1 {
		return fmt.Errorf("invalid checksum file format")
	}
	expectedChecksum := parts[0]

	// Calculate actual checksum
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return fmt.Errorf("failed to calculate checksum: %w", err)
	}

	actualChecksum := hex.EncodeToString(hash.Sum(nil))

	// Compare checksums
	if actualChecksum != expectedChecksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}

	return nil
}

// ExtractBinary extracts the binary from the tarball
func (d *Downloader) ExtractBinary(tarballPath string) (string, error) {
	file, err := os.Open(tarballPath)
	if err != nil {
		return "", fmt.Errorf("failed to open tarball: %w", err)
	}
	defer func() { _ = file.Close() }()

	gzr, err := gzip.NewReader(file)
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() { _ = gzr.Close() }()

	tr := tar.NewReader(gzr)

	// Find and extract the binary
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to read tar: %w", err)
		}

		// Look for the binary (should be named bjorn2scan-agent)
		if filepath.Base(header.Name) == "bjorn2scan-agent" {
			extractPath := filepath.Join(d.workDir, "bjorn2scan-agent")
			out, err := os.OpenFile(extractPath, os.O_CREATE|os.O_WRONLY, 0755)
			if err != nil {
				return "", fmt.Errorf("failed to create extracted file: %w", err)
			}
			defer func() { _ = out.Close() }()

			if _, err := io.Copy(out, tr); err != nil {
				return "", fmt.Errorf("failed to extract binary: %w", err)
			}

			return extractPath, nil
		}
	}

	return "", fmt.Errorf("binary not found in tarball")
}

// Cleanup removes the work directory
func (d *Downloader) Cleanup() error {
	if d.workDir != "" {
		return os.RemoveAll(d.workDir)
	}
	return nil
}

// GetWorkDir returns the work directory path
func (d *Downloader) GetWorkDir() string {
	return d.workDir
}
