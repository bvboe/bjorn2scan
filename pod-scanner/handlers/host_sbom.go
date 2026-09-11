package handlers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/source"
	"github.com/bvboe/bjorn2scan/sbom-generator-shared/exclusions"
)


// HostSBOMConfig configures the host SBOM handler
type HostSBOMConfig struct {
	// HostPath is the path to the host filesystem (typically /host)
	HostPath string
	// Timeout is the maximum duration for SBOM generation
	Timeout time.Duration
	// ExtraExclusions are additional exclusion patterns to add to defaults
	ExtraExclusions []string
	// AutoDetectNFS enables auto-detection of network filesystem mounts
	AutoDetectNFS bool
	// ExtraNetworkFSTypes are additional network FS types to detect
	ExtraNetworkFSTypes []string
}

// DefaultHostSBOMConfig returns a default configuration for host scanning
func DefaultHostSBOMConfig() HostSBOMConfig {
	return HostSBOMConfig{
		HostPath:            "/host",
		Timeout:             10 * time.Minute, // Host scans take longer than container scans
		ExtraExclusions:     nil,
		AutoDetectNFS:       true,
		ExtraNetworkFSTypes: nil,
	}
}

// BuildExclusions builds the complete list of exclusions based on config.
func (cfg *HostSBOMConfig) BuildExclusions() []string {
	excCfg := exclusions.HostExclusionConfig{
		ExtraExclusions:     cfg.ExtraExclusions,
		AutoDetectNFS:       cfg.AutoDetectNFS,
		ExtraNetworkFSTypes: cfg.ExtraNetworkFSTypes,
		HostPrefix:          cfg.HostPath,
	}
	result, err := exclusions.BuildExclusions(excCfg)
	if err != nil {
		log.Warn("failed to detect network mounts", "error", err)
	}
	return result
}

// HostSBOMHandler creates an HTTP handler for /host-sbom endpoint
// Generates SBOM for the host filesystem (mounted at /host)
func HostSBOMHandler(cfg HostSBOMConfig) http.HandlerFunc {
	// Build exclusions once at handler creation time
	exclusionPatterns := cfg.BuildExclusions()

	// Log the exclusion configuration including the fully resolved pattern list.
	// The list is logged at INFO (once, at startup) because the effective set is
	// otherwise impossible to determine from outside the process: the defaults are
	// compiled in and the network-mount patterns are auto-detected at runtime.
	log.Info("host SBOM exclusion config",
		"autoDetectNFS", cfg.AutoDetectNFS,
		"extraExclusions", len(cfg.ExtraExclusions),
		"extraNetworkFSTypes", len(cfg.ExtraNetworkFSTypes),
		"totalPatterns", len(exclusionPatterns),
		"patterns", strings.Join(exclusionPatterns, ","))

	return func(w http.ResponseWriter, r *http.Request) {
		log.Info("host SBOM request received")

		// Set timeout for SBOM generation
		ctx, cancel := context.WithTimeout(r.Context(), cfg.Timeout)
		defer cancel()

		// Copy exclusion patterns to avoid syft modifying the shared slice
		// (syft prepends the scan path to patterns, corrupting them for reuse)
		patternsCopy := make([]string, len(exclusionPatterns))
		copy(patternsCopy, exclusionPatterns)

		// Configure source with exclusions for container filesystems
		sourceCfg := syft.DefaultGetSourceConfig().
			WithExcludeConfig(source.ExcludeConfig{
				Paths: patternsCopy,
			})

		// Get source for the host filesystem
		log.Info("scanning host filesystem", "path", cfg.HostPath, "excludePatterns", len(exclusionPatterns))
		src, err := syft.GetSource(ctx, cfg.HostPath, sourceCfg)
		if err != nil {
			log.Error("error getting source for host filesystem", "error", err)
			http.Error(w, "Failed to access host filesystem", http.StatusInternalServerError)
			return
		}

		// Ensure cleanup of source
		defer func() {
			if cleanupErr := src.Close(); cleanupErr != nil {
				log.Warn("failed to cleanup source", "error", cleanupErr)
			}
		}()

		// Create SBOM from the source
		sbomCfg := syft.DefaultCreateSBOMConfig()
		sbomCfg.Search.Scope = source.AllLayersScope

		s, err := syft.CreateSBOM(ctx, src, sbomCfg)
		if err != nil {
			log.Error("error creating SBOM for host filesystem", "error", err)

			// Check if it's a timeout
			if ctx.Err() == context.DeadlineExceeded {
				http.Error(w, "Host SBOM generation timed out", http.StatusGatewayTimeout)
				return
			}

			http.Error(w, "Failed to generate host SBOM", http.StatusInternalServerError)
			return
		}

		// Get node name for logging
		nodeName := r.Header.Get("X-Node-Name")
		if nodeName == "" {
			nodeName = "unknown"
		}

		// Create filename for download
		filename := fmt.Sprintf("host-sbom_%s.json", nodeName)

		// Set headers for JSON download. Content-Length is deliberately absent:
		// the body is streamed, so its size is not known until the encode
		// finishes, and Go falls back to chunked transfer encoding. The only
		// consumer is k8s-scan-server, which reads with io.ReadAll and does not
		// look at Content-Length.
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))

		// Encode straight to the response rather than via format.Encode, which
		// collects the whole document into a bytes.Buffer and returns it as a
		// []byte. On this path that buffer reached 80MB — on top of the ~80MB
		// that json.Encoder already builds internally before writing — and it
		// landed at the point where memory is tightest, right after cataloguing
		// the host filesystem. Writing through the ResponseWriter removes one
		// of those two copies and avoids a single large contiguous allocation
		// that can force heap growth on its own.
		//
		// The trade-off is that status is committed on the first write: an
		// encode failure part-way through cannot become a clean 500, and the
		// client sees a truncated body instead. That is acceptable because the
		// encode is marshalling an in-memory struct, so failure is close to
		// impossible, and the log line below records it unambiguously.
		counter := &countingWriter{w: w}
		encoder := syftjson.NewFormatEncoder()
		if err := encoder.Encode(counter, *s); err != nil {
			log.Error("error encoding host SBOM to JSON; response is truncated",
				"error", err, "node", nodeName, "bytes_written", counter.n)
			return
		}

		log.Info("successfully served host SBOM",
			"node", nodeName,
			"size", counter.n,
			"packages", s.Artifacts.Packages.PackageCount())
	}
}

// countingWriter tracks how many bytes reached the wire. The streaming encode
// gives up format.Encode's []byte, and with it the length that the success and
// truncation log lines both report.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
