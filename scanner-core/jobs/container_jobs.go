package jobs

import (
	"context"
	"fmt"

	"github.com/bvboe/b2s-go/scanner-core/containers"
	"github.com/bvboe/b2s-go/scanner-core/database"
	"github.com/bvboe/b2s-go/scanner-core/logging"
)

var log = logging.For(logging.ComponentJobs)

// RefreshImagesJob triggers a refresh of all running container images
// This job calls the RefreshTrigger to get updated container instance data
// and performs periodic reconciliation to catch any missed container events
type RefreshImagesJob struct {
	refreshTrigger containers.RefreshTrigger
}

// NewRefreshImagesJob creates a new refresh images job
func NewRefreshImagesJob(trigger containers.RefreshTrigger) *RefreshImagesJob {
	if trigger == nil {
		panic("RefreshImagesJob requires a non-nil RefreshTrigger")
	}
	return &RefreshImagesJob{
		refreshTrigger: trigger,
	}
}

func (j *RefreshImagesJob) Name() string {
	return "refresh-images"
}

func (j *RefreshImagesJob) Run(ctx context.Context) error {
	log.Info("starting periodic reconciliation of running containers")

	// Trigger the refresh - this will call back to agent/k8s-scan-server
	// which will gather running container data and call SetContainers
	err := j.refreshTrigger.TriggerRefresh()
	if err != nil {
		return fmt.Errorf("failed to trigger refresh: %w", err)
	}

	log.Info("reconciliation completed successfully")
	return nil
}

// ContainerLister provides the current set of active container IDs.
// Implemented by the container Manager in k8s-scan-server.
type ContainerLister interface {
	GetActiveContainerIDs() []containers.ContainerID
}

// CleanupOrphanedImagesJob deletes container images that have no associated container instances.
// If a ContainerLister is configured, it first removes stale container entries (containers in
// the DB whose pods no longer exist), then removes images that have become orphaned as a result.
type CleanupOrphanedImagesJob struct {
	db     DatabaseCleanup
	lister ContainerLister // optional; nil means skip stale-container cleanup
}

// DatabaseCleanup defines the interface for database cleanup operations
type DatabaseCleanup interface {
	CleanupStaleContainers(activeIDs []containers.ContainerID) (int, error)
	CleanupOrphanedImages() (*database.CleanupStats, error)
}

// NewCleanupOrphanedImagesJob creates a new cleanup job
func NewCleanupOrphanedImagesJob(db DatabaseCleanup) *CleanupOrphanedImagesJob {
	if db == nil {
		panic("CleanupOrphanedImagesJob requires a non-nil database")
	}
	return &CleanupOrphanedImagesJob{
		db: db,
	}
}

// SetContainerLister configures the job to remove stale containers before orphaned images.
func (j *CleanupOrphanedImagesJob) SetContainerLister(lister ContainerLister) {
	j.lister = lister
}

func (j *CleanupOrphanedImagesJob) Name() string {
	return "cleanup-orphaned-images"
}

func (j *CleanupOrphanedImagesJob) Run(ctx context.Context) error {
	log.Info("starting cleanup of orphaned container images")

	var totalStats database.CleanupStats

	// Step 1: remove stale containers (pods that no longer exist in K8s)
	if j.lister != nil {
		activeIDs := j.lister.GetActiveContainerIDs()
		removed, err := j.db.CleanupStaleContainers(activeIDs)
		if err != nil {
			return fmt.Errorf("stale container cleanup failed: %w", err)
		}
		totalStats.ContainersRemoved = removed
		if removed > 0 {
			log.Info("removed stale containers", "count", removed)
		}
	}

	// Step 2: remove images with no containers (and their packages/vulnerabilities)
	stats, err := j.db.CleanupOrphanedImages()
	if err != nil {
		return fmt.Errorf("orphaned image cleanup failed: %w", err)
	}

	if stats != nil {
		totalStats.ImagesRemoved = stats.ImagesRemoved
		totalStats.PackagesRemoved = stats.PackagesRemoved
		totalStats.VulnerabilitiesRemoved = stats.VulnerabilitiesRemoved
		totalStats.PackageDetailsRemoved = stats.PackageDetailsRemoved
		totalStats.VulnerabilityDetailsRemoved = stats.VulnerabilityDetailsRemoved
	}

	if totalStats.ContainersRemoved > 0 || totalStats.ImagesRemoved > 0 {
		log.Info("cleanup completed",
			"containers_removed", totalStats.ContainersRemoved,
			"images_removed", totalStats.ImagesRemoved,
			"packages_removed", totalStats.PackagesRemoved,
			"vulnerabilities_removed", totalStats.VulnerabilitiesRemoved)
	} else {
		log.Info("cleanup completed: nothing to remove")
	}

	return nil
}
