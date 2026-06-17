package updater

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewDownloader(t *testing.T) {
	assetBaseURL := "http://localhost:8080/download"

	downloader, err := NewDownloader(assetBaseURL)
	if err != nil {
		t.Fatalf("NewDownloader() error = %v", err)
	}
	defer func() { _ = downloader.Cleanup() }()

	if downloader.httpDownloader == nil {
		t.Error("HTTPDownloader not set correctly")
	}

	if downloader.workDir == "" {
		t.Error("Work directory not created")
	}

	// Verify work directory exists
	if _, err := os.Stat(downloader.workDir); os.IsNotExist(err) {
		t.Error("Work directory does not exist")
	}
}

func TestDownloader_GetWorkDir(t *testing.T) {
	downloader, err := NewDownloader("http://localhost:8080/download")
	if err != nil {
		t.Fatalf("NewDownloader() error = %v", err)
	}
	defer func() { _ = downloader.Cleanup() }()

	workDir := downloader.GetWorkDir()
	if workDir == "" {
		t.Error("GetWorkDir() returned empty string")
	}

	if workDir != downloader.workDir {
		t.Errorf("GetWorkDir() = %q, want %q", workDir, downloader.workDir)
	}
}

func TestDownloader_Cleanup(t *testing.T) {
	downloader, err := NewDownloader("http://localhost:8080/download")
	if err != nil {
		t.Fatalf("NewDownloader() error = %v", err)
	}

	workDir := downloader.workDir

	// Verify directory exists before cleanup
	if _, err := os.Stat(workDir); os.IsNotExist(err) {
		t.Fatal("Work directory should exist before cleanup")
	}

	// Cleanup
	if err := downloader.Cleanup(); err != nil {
		t.Errorf("Cleanup() error = %v", err)
	}

	// Verify directory is removed
	if _, err := os.Stat(workDir); !os.IsNotExist(err) {
		t.Error("Work directory should be removed after cleanup")
	}
}

// Helper function to create a test tarball
func createTestTarball(t *testing.T, binaryName string, content []byte) string {
	t.Helper()

	tmpDir := t.TempDir()
	tarballPath := filepath.Join(tmpDir, "test.tar.gz")

	// Create tarball
	file, err := os.Create(tarballPath)
	if err != nil {
		t.Fatalf("Failed to create tarball file: %v", err)
	}
	defer func() { _ = file.Close() }()

	gzw := gzip.NewWriter(file)
	defer func() { _ = gzw.Close() }()

	tw := tar.NewWriter(gzw)
	defer func() { _ = tw.Close() }()

	// Add binary to tarball
	header := &tar.Header{
		Name: binaryName,
		Mode: 0755,
		Size: int64(len(content)),
	}

	if err := tw.WriteHeader(header); err != nil {
		t.Fatalf("Failed to write tar header: %v", err)
	}

	if _, err := tw.Write(content); err != nil {
		t.Fatalf("Failed to write tar content: %v", err)
	}

	return tarballPath
}

func TestDownloader_ExtractBinary_Success(t *testing.T) {
	downloader, err := NewDownloader("http://localhost:8080/download")
	if err != nil {
		t.Fatalf("NewDownloader() error = %v", err)
	}
	defer func() { _ = downloader.Cleanup() }()

	// Create test tarball with correct binary name
	testContent := []byte("fake binary content")
	tarballPath := createTestTarball(t, "bjorn2scan-agent", testContent)

	extractedPath, err := downloader.ExtractBinary(tarballPath)
	if err != nil {
		t.Fatalf("ExtractBinary() error = %v", err)
	}

	// Verify extracted file exists
	if _, err := os.Stat(extractedPath); os.IsNotExist(err) {
		t.Error("Extracted binary does not exist")
	}

	// Verify content
	content, err := os.ReadFile(extractedPath)
	if err != nil {
		t.Fatalf("Failed to read extracted binary: %v", err)
	}

	if string(content) != string(testContent) {
		t.Errorf("Extracted content = %q, want %q", string(content), string(testContent))
	}

	// Verify file is in work directory
	if !strings.HasPrefix(extractedPath, downloader.workDir) {
		t.Errorf("Extracted path %q is not in work directory %q", extractedPath, downloader.workDir)
	}
}

func TestDownloader_ExtractBinary_PlatformSpecificName(t *testing.T) {
	// This test catches the bug where tarball contains "bjorn2scan-agent-linux-amd64"
	// but downloader expects "bjorn2scan-agent"
	downloader, err := NewDownloader("http://localhost:8080/download")
	if err != nil {
		t.Fatalf("NewDownloader() error = %v", err)
	}
	defer func() { _ = downloader.Cleanup() }()

	testContent := []byte("fake binary content")
	tarballPath := createTestTarball(t, "bjorn2scan-agent-linux-amd64", testContent)

	_, err = downloader.ExtractBinary(tarballPath)
	if err == nil {
		t.Fatal("ExtractBinary() expected error for platform-specific binary name, got nil")
	}

	if !strings.Contains(err.Error(), "binary not found") {
		t.Errorf("ExtractBinary() error = %v, want error containing 'binary not found'", err)
	}
}

func TestDownloader_ExtractBinary_EmptyTarball(t *testing.T) {
	downloader, err := NewDownloader("http://localhost:8080/download")
	if err != nil {
		t.Fatalf("NewDownloader() error = %v", err)
	}
	defer func() { _ = downloader.Cleanup() }()

	// Create empty tarball
	tmpDir := t.TempDir()
	tarballPath := filepath.Join(tmpDir, "empty.tar.gz")

	file, err := os.Create(tarballPath)
	if err != nil {
		t.Fatalf("Failed to create tarball: %v", err)
	}

	gzw := gzip.NewWriter(file)
	tw := tar.NewWriter(gzw)
	_ = tw.Close()
	_ = gzw.Close()
	_ = file.Close()

	_, err = downloader.ExtractBinary(tarballPath)
	if err == nil {
		t.Fatal("ExtractBinary() expected error for empty tarball, got nil")
	}

	if !strings.Contains(err.Error(), "binary not found") {
		t.Errorf("ExtractBinary() error = %v, want error containing 'binary not found'", err)
	}
}

func TestDownloader_ExtractBinary_WrongFileName(t *testing.T) {
	downloader, err := NewDownloader("http://localhost:8080/download")
	if err != nil {
		t.Fatalf("NewDownloader() error = %v", err)
	}
	defer func() { _ = downloader.Cleanup() }()

	testContent := []byte("fake binary content")
	tarballPath := createTestTarball(t, "wrong-name", testContent)

	_, err = downloader.ExtractBinary(tarballPath)
	if err == nil {
		t.Fatal("ExtractBinary() expected error for wrong filename, got nil")
	}

	if !strings.Contains(err.Error(), "binary not found") {
		t.Errorf("ExtractBinary() error = %v, want error containing 'binary not found'", err)
	}
}

func TestDownloader_ExtractBinary_InvalidTarball(t *testing.T) {
	downloader, err := NewDownloader("http://localhost:8080/download")
	if err != nil {
		t.Fatalf("NewDownloader() error = %v", err)
	}
	defer func() { _ = downloader.Cleanup() }()

	// Create invalid tarball (not a tar.gz file)
	tmpDir := t.TempDir()
	tarballPath := filepath.Join(tmpDir, "invalid.tar.gz")
	if err := os.WriteFile(tarballPath, []byte("not a tarball"), 0644); err != nil {
		t.Fatalf("Failed to create invalid tarball: %v", err)
	}

	_, err = downloader.ExtractBinary(tarballPath)
	if err == nil {
		t.Fatal("ExtractBinary() expected error for invalid tarball, got nil")
	}
}

func TestDownloader_ExtractBinary_NonexistentFile(t *testing.T) {
	downloader, err := NewDownloader("http://localhost:8080/download")
	if err != nil {
		t.Fatalf("NewDownloader() error = %v", err)
	}
	defer func() { _ = downloader.Cleanup() }()

	_, err = downloader.ExtractBinary("/nonexistent/path/file.tar.gz")
	if err == nil {
		t.Fatal("ExtractBinary() expected error for nonexistent file, got nil")
	}

	if !strings.Contains(err.Error(), "failed to open tarball") {
		t.Errorf("ExtractBinary() error = %v, want error containing 'failed to open tarball'", err)
	}
}

func TestDownloader_ExtractBinary_PathInTarball(t *testing.T) {
	// Test that we can extract binary even if it has a path prefix
	downloader, err := NewDownloader("http://localhost:8080/download")
	if err != nil {
		t.Fatalf("NewDownloader() error = %v", err)
	}
	defer func() { _ = downloader.Cleanup() }()

	testContent := []byte("fake binary content")
	// Binary with path prefix should still be extracted (we use filepath.Base)
	tarballPath := createTestTarball(t, "some/path/bjorn2scan-agent", testContent)

	extractedPath, err := downloader.ExtractBinary(tarballPath)
	if err != nil {
		t.Fatalf("ExtractBinary() error = %v", err)
	}

	// Verify content
	content, err := os.ReadFile(extractedPath)
	if err != nil {
		t.Fatalf("Failed to read extracted binary: %v", err)
	}

	if string(content) != string(testContent) {
		t.Errorf("Extracted content = %q, want %q", string(content), string(testContent))
	}
}

func TestDownloader_VerifyChecksum_Success(t *testing.T) {
	downloader, err := NewDownloader("http://localhost:8080/download")
	if err != nil {
		t.Fatalf("NewDownloader() error = %v", err)
	}
	defer func() { _ = downloader.Cleanup() }()

	// Create test file
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "testfile")
	testContent := []byte("test content for checksum")
	if err := os.WriteFile(filePath, testContent, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Calculate checksum
	hash := sha256.Sum256(testContent)
	checksum := hex.EncodeToString(hash[:])

	// Create checksum file
	checksumPath := filepath.Join(tmpDir, "testfile.sha256")
	checksumContent := checksum + "  testfile\n"
	if err := os.WriteFile(checksumPath, []byte(checksumContent), 0644); err != nil {
		t.Fatalf("Failed to create checksum file: %v", err)
	}

	// Verify
	if err := downloader.VerifyChecksum(filePath, checksumPath); err != nil {
		t.Errorf("VerifyChecksum() error = %v", err)
	}
}

func TestDownloader_VerifyChecksum_Mismatch(t *testing.T) {
	downloader, err := NewDownloader("http://localhost:8080/download")
	if err != nil {
		t.Fatalf("NewDownloader() error = %v", err)
	}
	defer func() { _ = downloader.Cleanup() }()

	// Create test file
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "testfile")
	if err := os.WriteFile(filePath, []byte("content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create checksum file with wrong checksum
	checksumPath := filepath.Join(tmpDir, "testfile.sha256")
	checksumContent := "wrongchecksumhex1234567890abcdef  testfile\n"
	if err := os.WriteFile(checksumPath, []byte(checksumContent), 0644); err != nil {
		t.Fatalf("Failed to create checksum file: %v", err)
	}

	// Verify should fail
	err = downloader.VerifyChecksum(filePath, checksumPath)
	if err == nil {
		t.Fatal("VerifyChecksum() expected error for checksum mismatch, got nil")
	}

	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("VerifyChecksum() error = %v, want error containing 'checksum mismatch'", err)
	}
}

func TestDownloader_VerifyChecksum_InvalidFormat(t *testing.T) {
	downloader, err := NewDownloader("http://localhost:8080/download")
	if err != nil {
		t.Fatalf("NewDownloader() error = %v", err)
	}
	defer func() { _ = downloader.Cleanup() }()

	// Create test file
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "testfile")
	if err := os.WriteFile(filePath, []byte("content"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create checksum file with invalid format (empty)
	checksumPath := filepath.Join(tmpDir, "testfile.sha256")
	if err := os.WriteFile(checksumPath, []byte(""), 0644); err != nil {
		t.Fatalf("Failed to create checksum file: %v", err)
	}

	// Verify should fail
	err = downloader.VerifyChecksum(filePath, checksumPath)
	if err == nil {
		t.Fatal("VerifyChecksum() expected error for invalid format, got nil")
	}

	if !strings.Contains(err.Error(), "invalid checksum file format") {
		t.Errorf("VerifyChecksum() error = %v, want error containing 'invalid checksum file format'", err)
	}
}

func TestDownloader_VerifyChecksum_NonexistentFile(t *testing.T) {
	downloader, err := NewDownloader("http://localhost:8080/download")
	if err != nil {
		t.Fatalf("NewDownloader() error = %v", err)
	}
	defer func() { _ = downloader.Cleanup() }()

	err = downloader.VerifyChecksum("/nonexistent/file", "/nonexistent/checksum")
	if err == nil {
		t.Fatal("VerifyChecksum() expected error for nonexistent file, got nil")
	}
}

func TestDownloader_VerifyChecksum_OnlyHashInFile(t *testing.T) {
	// Test checksum file with only the hash (no filename)
	downloader, err := NewDownloader("http://localhost:8080/download")
	if err != nil {
		t.Fatalf("NewDownloader() error = %v", err)
	}
	defer func() { _ = downloader.Cleanup() }()

	// Create test file
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "testfile")
	testContent := []byte("test content")
	if err := os.WriteFile(filePath, testContent, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Calculate checksum
	hash := sha256.Sum256(testContent)
	checksum := hex.EncodeToString(hash[:])

	// Create checksum file with only hash (no filename)
	checksumPath := filepath.Join(tmpDir, "testfile.sha256")
	if err := os.WriteFile(checksumPath, []byte(checksum), 0644); err != nil {
		t.Fatalf("Failed to create checksum file: %v", err)
	}

	// Verify should succeed (we only care about the first field)
	if err := downloader.VerifyChecksum(filePath, checksumPath); err != nil {
		t.Errorf("VerifyChecksum() error = %v", err)
	}
}
