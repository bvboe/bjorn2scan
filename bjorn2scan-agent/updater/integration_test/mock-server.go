//go:build integration
// +build integration

package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const atomFeedTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xml:lang="en-US">
  <id>tag:localhost,2024:test/releases</id>
  <link type="text/html" rel="alternate" href="http://localhost:8080/releases"/>
  <link type="application/atom+xml" rel="self" href="http://localhost:8080/releases.atom"/>
  <title>Release notes from test</title>
  <updated>%s</updated>
  %s
</feed>`

const atomEntryTemplate = `  <entry>
    <id>tag:localhost,2024:Release/%s</id>
    <updated>%s</updated>
    <link rel="alternate" type="text/html" href="http://localhost:8080/releases/tag/%s"/>
    <title>%s</title>
    <content type="html">
      &lt;p&gt;Test release %s&lt;/p&gt;
    </content>
    <author>
      <name>test</name>
    </author>
  </entry>`

// MockServer serves both Atom feed and assets
type MockServer struct {
	releases    []string // List of release versions (e.g., ["v0.1.1", "v0.1.0"])
	assetsDir   string   // Directory containing release assets
	failVersion string   // Version that should cause health check failure (empty = none)
}

// NewMockServer creates a new mock server
func NewMockServer(releases []string, assetsDir string) *MockServer {
	return &MockServer{
		releases:  releases,
		assetsDir: assetsDir,
	}
}

// ServeHTTP handles all HTTP requests
func (ms *MockServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.Path)

	// Atom feed endpoint
	if r.URL.Path == "/releases.atom" {
		ms.serveFeed(w, r)
		return
	}

	// Asset download endpoint: /download/{version}/{filename}
	if len(r.URL.Path) > 10 && r.URL.Path[:10] == "/download/" {
		ms.serveAsset(w, r)
		return
	}

	http.NotFound(w, r)
}

// serveFeed serves the Atom feed
func (ms *MockServer) serveFeed(w http.ResponseWriter, r *http.Request) {
	// Build entries for all releases
	entries := ""
	now := time.Now().Format(time.RFC3339)

	for _, version := range ms.releases {
		entry := fmt.Sprintf(atomEntryTemplate, version, now, version, version, version)
		entries += entry + "\n"
	}

	// Build complete feed
	feed := fmt.Sprintf(atomFeedTemplate, now, entries)

	w.Header().Set("Content-Type", "application/atom+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(feed))
}

// serveAsset serves release assets (tarballs, checksums, etc.)
func (ms *MockServer) serveAsset(w http.ResponseWriter, r *http.Request) {
	// Parse URL: /download/{version}/{filename}
	path := r.URL.Path[10:] // Remove "/download/"

	// Construct file path
	filePath := filepath.Join(ms.assetsDir, path)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Printf("Asset not found: %s", filePath)
		http.NotFound(w, r)
		return
	}

	// Serve file
	log.Printf("Serving asset: %s", filePath)
	http.ServeFile(w, r, filePath)
}

// CreateMockAsset creates a real tar.gz with a binary inside for testing
func CreateMockAsset(assetsDir, version, arch string, failHealthCheck bool) error {
	// Create version directory
	versionDir := filepath.Join(assetsDir, version)
	if err := os.MkdirAll(versionDir, 0755); err != nil {
		return fmt.Errorf("failed to create version dir: %w", err)
	}

	// Create fake binary content
	binaryContent := []byte(fmt.Sprintf("#!/bin/sh\necho 'Mock agent %s'\nexit 0\n", version))
	if failHealthCheck {
		// Binary that will fail health check by exiting with error
		binaryContent = []byte(fmt.Sprintf("#!/bin/sh\necho 'Mock agent %s (will fail)'\nexit 1\n", version))
	}

	// Create tarball filename
	tarballName := fmt.Sprintf("bjorn2scan-agent-linux-%s.tar.gz", arch)
	tarballPath := filepath.Join(versionDir, tarballName)

	// Create a real tar.gz file with the binary inside
	tarFile, err := os.Create(tarballPath)
	if err != nil {
		return fmt.Errorf("failed to create tarball file: %w", err)
	}
	defer tarFile.Close()

	// Create gzip writer
	gzWriter := gzip.NewWriter(tarFile)
	defer gzWriter.Close()

	// Create tar writer
	tarWriter := tar.NewWriter(gzWriter)
	defer tarWriter.Close()

	// Add binary to tarball with correct name (no platform suffix)
	header := &tar.Header{
		Name: "bjorn2scan-agent",
		Mode: 0755,
		Size: int64(len(binaryContent)),
	}
	if err := tarWriter.WriteHeader(header); err != nil {
		return fmt.Errorf("failed to write tar header: %w", err)
	}
	if _, err := tarWriter.Write(binaryContent); err != nil {
		return fmt.Errorf("failed to write tar content: %w", err)
	}

	// Close tar and gzip writers to finalize the tarball
	tarWriter.Close()
	gzWriter.Close()
	tarFile.Close()

	// Read the tarball to calculate checksum
	tarballData, err := os.ReadFile(tarballPath)
	if err != nil {
		return fmt.Errorf("failed to read tarball: %w", err)
	}

	// Calculate checksum
	hash := sha256.Sum256(tarballData)
	checksum := hex.EncodeToString(hash[:])

	// Write checksum file
	checksumName := fmt.Sprintf("%s.sha256", tarballName)
	checksumPath := filepath.Join(versionDir, checksumName)
	checksumContent := fmt.Sprintf("%s  %s\n", checksum, tarballName)
	if err := os.WriteFile(checksumPath, []byte(checksumContent), 0644); err != nil {
		return fmt.Errorf("failed to write checksum: %w", err)
	}

	log.Printf("Created mock asset: %s (fail=%v)", tarballPath, failHealthCheck)
	return nil
}

func main() {
	// Get configuration from environment
	port := os.Getenv("MOCK_PORT")
	if port == "" {
		port = "8080"
	}

	assetsDir := os.Getenv("MOCK_ASSETS_DIR")
	if assetsDir == "" {
		assetsDir = "/tmp/mock-assets"
	}

	// Create assets directory
	if err := os.MkdirAll(assetsDir, 0755); err != nil {
		log.Fatalf("Failed to create assets directory: %v", err)
	}

	// Create mock assets for testing
	log.Println("Creating mock assets...")

	// Use current architecture
	arch := runtime.GOARCH
	log.Printf("Creating assets for architecture: %s", arch)

	// Create v0.1.0 (baseline version)
	if err := CreateMockAsset(assetsDir, "v0.1.0", arch, false); err != nil {
		log.Fatalf("Failed to create v0.1.0 asset: %v", err)
	}

	// Create v0.1.1 (successful upgrade)
	if err := CreateMockAsset(assetsDir, "v0.1.1", arch, false); err != nil {
		log.Fatalf("Failed to create v0.1.1 asset: %v", err)
	}

	// Create v0.1.2 (will fail health check)
	if err := CreateMockAsset(assetsDir, "v0.1.2", arch, true); err != nil {
		log.Fatalf("Failed to create v0.1.2 asset: %v", err)
	}

	// Define available releases (newest first)
	// Can be overridden by MOCK_RELEASES env var (comma-separated)
	releasesStr := os.Getenv("MOCK_RELEASES")
	var releases []string
	if releasesStr != "" {
		releases = strings.Split(releasesStr, ",")
		log.Printf("Using custom releases: %v", releases)
	} else {
		releases = []string{"v0.1.2", "v0.1.1", "v0.1.0"}
		log.Printf("Using default releases: %v", releases)
	}

	// Create and start server
	server := NewMockServer(releases, assetsDir)

	log.Printf("Mock server starting on port %s", port)
	log.Printf("Feed URL: http://localhost:%s/releases.atom", port)
	log.Printf("Assets dir: %s", assetsDir)

	if err := http.ListenAndServe(":"+port, server); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
