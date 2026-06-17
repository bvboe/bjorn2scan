package runtime

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
)


// DockerClient implements RuntimeClient for Docker daemon
type DockerClient struct {
	cli *client.Client
}

// NewDockerClient creates a new Docker runtime client
func NewDockerClient() *DockerClient {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Warn("failed to create Docker client", "error", err)
		return &DockerClient{cli: nil}
	}
	return &DockerClient{cli: cli}
}

// IsAvailable checks if Docker daemon is accessible
func (d *DockerClient) IsAvailable() bool {
	if d.cli == nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := d.cli.Ping(ctx)
	return err == nil
}

// Name returns the runtime name
func (d *DockerClient) Name() string {
	return "docker"
}

// GenerateSBOM generates an SBOM for the given image digest
func (d *DockerClient) GenerateSBOM(ctx context.Context, digest string) ([]byte, error) {
	if d.cli == nil {
		return nil, fmt.Errorf("docker client not initialized")
	}

	// List all images to find one with matching digest
	images, err := d.cli.ImageList(ctx, image.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("failed to list Docker images: %w", err)
	}

	// Find image with matching digest
	var imageRef string
	for _, img := range images {
		// Check if this image's ID matches the digest
		if img.ID == digest || img.ID == "sha256:"+digest {
			// Found the image, use first RepoTag if available
			if len(img.RepoTags) > 0 {
				imageRef = img.RepoTags[0]
			} else if len(img.RepoDigests) > 0 {
				imageRef = img.RepoDigests[0]
			} else {
				// No tags, use the image ID directly
				imageRef = img.ID
			}
			break
		}

		// Also check RepoDigests
		for _, repoDigest := range img.RepoDigests {
			if repoDigest == digest || repoDigest[strings.LastIndex(repoDigest, "@")+1:] == digest {
				imageRef = repoDigest
				break
			}
		}
		if imageRef != "" {
			break
		}
	}

	if imageRef == "" {
		return nil, fmt.Errorf("image with digest %s not found in Docker", digest)
	}

	log.Info("generating SBOM for Docker image", "image", imageRef, "digest", digest)

	// Use syft to generate SBOM from Docker daemon
	src, err := syft.GetSource(ctx, imageRef, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get source for image %s: %w", imageRef, err)
	}

	// Ensure cleanup of source
	defer func() {
		if cleanupErr := src.Close(); cleanupErr != nil {
			log.Warn("failed to cleanup source", "error", cleanupErr)
		}
	}()

	// Create SBOM from the source
	s, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SBOM for %s: %w", imageRef, err)
	}

	// Encode to syft JSON format
	encoder := syftjson.NewFormatEncoder()
	sbomBytes, err := format.Encode(*s, encoder)
	if err != nil {
		return nil, fmt.Errorf("failed to encode SBOM to JSON: %w", err)
	}

	log.Info("successfully generated SBOM",
		"image", imageRef,
		"size", len(sbomBytes),
		"packages", s.Artifacts.Packages.PackageCount())

	return sbomBytes, nil
}

// Close closes the Docker client
func (d *DockerClient) Close() error {
	if d.cli != nil {
		return d.cli.Close()
	}
	return nil
}
