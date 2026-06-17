package docker

import (
	"context"
	"time"

	"github.com/bvboe/b2s-go/scanner-core/containers"

	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)


// RefreshTrigger implements containers.RefreshTrigger for Docker
// It performs a full reconciliation of running containers when triggered
type RefreshTrigger struct {
	manager *containers.Manager
}

// NewRefreshTrigger creates a new Docker refresh trigger
func NewRefreshTrigger(manager *containers.Manager) *RefreshTrigger {
	return &RefreshTrigger{
		manager: manager,
	}
}

// TriggerRefresh performs a full reconciliation of running Docker containers
// This is called periodically by the refresh-images job to ensure the container
// list stays in sync with reality, catching any missed Docker events
func (t *RefreshTrigger) TriggerRefresh() error {
	log.Info("starting Docker container reconciliation")

	// Create a new Docker client for this refresh operation
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer func() { _ = cli.Close() }()

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = cli.Ping(ctx)
	if err != nil {
		return err
	}

	// List all running containers
	containerList, err := cli.ContainerList(ctx, containertypes.ListOptions{
		All: false, // Only running containers
	})
	if err != nil {
		return err
	}

	// Extract container details
	var allContainers []containers.Container
	for _, dc := range containerList {
		c, err := extractContainer(ctx, cli, dc.ID)
		if err != nil {
			log.Warn("failed to extract container", "container_id", dc.ID[:12], "error", err)
			continue
		}
		allContainers = append(allContainers, c)
	}

	// Update the manager with the current container set
	// This will reconcile with the database and enqueue scans for new images
	t.manager.SetContainers(allContainers)

	log.Info("reconciliation complete", "running_containers", len(allContainers))
	return nil
}

// Ensure RefreshTrigger implements containers.RefreshTrigger
var _ containers.RefreshTrigger = (*RefreshTrigger)(nil)
