package docker

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/logging"

	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
)

var log = logging.For(logging.ComponentContainers)

// extractImageReference extracts the image reference from a container image string
// This preserves the original reference exactly as specified by the user
// Example: "nginx:1.21" -> "nginx:1.21"
// Example: "nginx@sha256:abc123" -> "nginx@sha256:abc123" (digest reference preserved)
// Example: "nginx" -> "nginx" (preserved as-is, no normalization to :latest)
func extractImageReference(imageName string) string {
	// Return the image name exactly as specified - preserve user intent
	return imageName
}

// extractContainer creates a Container from Docker container info
func extractContainer(ctx context.Context, cli *client.Client, containerID string) (containers.Container, error) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	// Get detailed container info
	containerJSON, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return containers.Container{}, err
	}

	reference := extractImageReference(containerJSON.Config.Image)

	// Extract image digest from RepoDigests if available
	digest := ""
	if len(containerJSON.Image) > 0 {
		// The Image field contains the image ID (sha256:...)
		digest = containerJSON.Image
	}

	// Use container name (remove leading /)
	containerName := strings.TrimPrefix(containerJSON.Name, "/")
	if containerName == "" {
		containerName = containerID[:12] // Use short container ID as fallback
	}

	c := containers.Container{
		ID: containers.ContainerID{
			Namespace: hostname,
			Pod:       "host", // Indicate this is a host-level container
			Name:      containerName,
		},
		Image: containers.ImageID{
			Reference: reference,
			Digest:    digest,
		},
		NodeName:         hostname, // Use hostname as node name for agent deployments
		ContainerRuntime: "docker",
	}

	return c, nil
}

// IsDockerAvailable checks if Docker daemon is accessible
func IsDockerAvailable() bool {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return false
	}
	defer func() { _ = cli.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = cli.Ping(ctx)
	return err == nil
}

// WatchContainers watches for Docker container events and updates the container manager
func WatchContainers(ctx context.Context, manager *containers.Manager) error {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer func() { _ = cli.Close() }()

	// Test connection
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	_, err = cli.Ping(pingCtx)
	cancel()
	if err != nil {
		return err
	}

	log.Info("Docker watcher connected to Docker daemon")

	// Perform initial sync of running containers
	if err := syncInitialContainers(ctx, cli, manager); err != nil {
		log.Warn("initial container sync failed", "error", err)
	}

	// Start watching for events
	for {
		select {
		case <-ctx.Done():
			log.Info("Docker watcher shutting down")
			return nil
		default:
			// Watch for container events
			eventFilters := filters.NewArgs()
			eventFilters.Add("type", "container")

			eventsChan, errChan := cli.Events(ctx, events.ListOptions{
				Filters: eventFilters,
			})

			log.Info("Docker watcher started")

		eventLoop:
			for {
				select {
				case <-ctx.Done():
					log.Info("Docker watcher shutting down")
					return nil

				case err := <-errChan:
					if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
						log.Error("Docker events error", "error", err)
					}
					break eventLoop

				case event := <-eventsChan:
					switch event.Action {
					case "start":
						// Container started
						c, err := extractContainer(ctx, cli, event.Actor.ID)
						if err != nil {
							log.Error("failed to extract container", "container_id", event.Actor.ID[:12], "error", err)
							continue
						}
						manager.AddContainer(c)

					case "die", "kill", "stop":
						// Container stopped - we need to get the container info before it's removed
						c, err := extractContainer(ctx, cli, event.Actor.ID)
						if err != nil {
							// Container might already be removed, use event data
							hostname, _ := os.Hostname()
							if hostname == "" {
								hostname = "unknown"
							}
							containerName := event.Actor.Attributes["name"]
							if containerName == "" {
								containerName = event.Actor.ID[:12]
							}
							c = containers.Container{
								ID: containers.ContainerID{
									Namespace: hostname,
									Pod:       "host",
									Name:      containerName,
								},
								NodeName:         hostname,
								ContainerRuntime: "docker",
							}
						}
						manager.RemoveContainer(c.ID)
					}
				}
			}

			log.Info("Docker watcher connection closed, reconnecting")
			time.Sleep(1 * time.Second)
		}
	}
}

// syncInitialContainers performs an initial sync of all running containers
func syncInitialContainers(ctx context.Context, cli *client.Client, manager *containers.Manager) error {
	log.Info("Docker watcher performing initial container sync")

	containerList, err := cli.ContainerList(ctx, containertypes.ListOptions{
		All: false, // Only running containers
	})
	if err != nil {
		return err
	}

	var allContainers []containers.Container
	for _, dc := range containerList {
		c, err := extractContainer(ctx, cli, dc.ID)
		if err != nil {
			log.Warn("failed to extract container", "container_id", dc.ID[:12], "error", err)
			continue
		}
		allContainers = append(allContainers, c)
	}

	manager.SetContainers(allContainers)
	log.Info("Docker watcher initial sync complete", "container_count", manager.GetContainerCount())

	return nil
}
