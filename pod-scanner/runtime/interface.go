package runtime

import (
	"context"
)

// RuntimeClient defines the interface for container runtime interactions
type RuntimeClient interface {
	// GenerateSBOM generates an SBOM for the given image digest
	// digest should be in the format "sha256:abc123..."
	GenerateSBOM(ctx context.Context, digest string) ([]byte, error)

	// IsAvailable checks if this runtime is accessible
	IsAvailable() bool

	// Name returns the runtime name ("docker" or "containerd")
	Name() string
}
