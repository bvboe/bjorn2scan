package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bvboe/b2s-go/pod-scanner/runtime"
)

var log = slog.Default().With("component", "pod-scanner")

// SBOMHandler creates an HTTP handler for /sbom/{digest} endpoint
// Generates SBOM on-demand using the runtime manager
func SBOMHandler(runtimeMgr *runtime.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract digest from URL path: /sbom/sha256:abc123...
		path := r.URL.Path
		if len(path) <= 6 { // "/sbom/" is 6 characters
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}
		digest := path[6:] // Remove "/sbom/" prefix

		// Validate digest format (should start with sha256: or be a hex string)
		if digest == "" {
			http.Error(w, "Digest required", http.StatusBadRequest)
			return
		}

		// Normalize digest format (ensure it has sha256: prefix)
		if !strings.HasPrefix(digest, "sha256:") && len(digest) == 64 {
			// Looks like a hex digest without prefix
			digest = "sha256:" + digest
		}

		if !isValidDigest(digest) {
			http.Error(w, "Invalid digest format", http.StatusBadRequest)
			return
		}

		log.Info("SBOM request received", "digest", digest)

		// Set timeout for SBOM generation (5 minutes)
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
		defer cancel()

		// Generate SBOM using runtime manager
		sbomData, err := runtimeMgr.GenerateSBOM(ctx, digest)
		if err != nil {
			log.Error("error generating SBOM", "digest", digest, "error", err)

			// Check if it's a timeout
			if ctx.Err() == context.DeadlineExceeded {
				http.Error(w, "SBOM generation timed out", http.StatusGatewayTimeout)
				return
			}

			// Check if image not found
			if strings.Contains(err.Error(), "not found") {
				http.Error(w, "Image not found", http.StatusNotFound)
				return
			}

			http.Error(w, "Failed to generate SBOM", http.StatusInternalServerError)
			return
		}

		// Create a safe filename from digest
		filename := digestToFilename(digest)

		// Set headers for JSON download
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"sbom_%s.json\"", filename))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(sbomData)))

		// Write SBOM data
		if _, err := w.Write(sbomData); err != nil {
			log.Error("error writing SBOM response", "error", err)
		} else {
			log.Info("successfully served SBOM", "digest", digest, "size", len(sbomData))
		}
	}
}

// isValidDigest checks if the digest has a valid format
func isValidDigest(digest string) bool {
	// Should be in format: sha256:abc123... or sha512:...
	parts := strings.Split(digest, ":")
	if len(parts) != 2 {
		return false
	}

	// Check algorithm (sha256, sha512, etc.)
	algorithm := parts[0]
	if algorithm != "sha256" && algorithm != "sha512" {
		return false
	}

	// Check hex string length (sha256 = 64 chars, sha512 = 128 chars)
	hexStr := parts[1]
	if algorithm == "sha256" && len(hexStr) != 64 {
		return false
	}
	if algorithm == "sha512" && len(hexStr) != 128 {
		return false
	}

	// Check if it's valid hex
	for _, c := range hexStr {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}

	return true
}

// digestToFilename creates a safe filename from a digest
func digestToFilename(digest string) string {
	// Remove sha256: prefix and truncate to reasonable length
	filename := strings.ReplaceAll(digest, ":", "_")
	if len(filename) > 20 {
		// Use shortened version: sha256_abc123
		filename = filename[:7] + "_" + filename[7:19]
	}
	return filename
}
