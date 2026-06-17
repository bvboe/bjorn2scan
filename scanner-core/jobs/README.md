# Scheduled Jobs

This package contains scheduled jobs that run periodically to maintain scanner-core's state.

## Refresh Images Job

**Purpose**: Keeps the database synchronized with running workloads by triggering periodic reconciliation.

**Schedule**: Every 6 hours (configurable)

**How it works**:
1. Job calls `RefreshTrigger.TriggerRefresh()`
2. Agent/k8s-scan-server gathers current running containers
3. Agent/k8s-scan-server calls `Manager.SetContainerInstances()` with complete list
4. Database reconciles changes:
   - Adds new container instances
   - Removes instances no longer running
   - Discovers and scans new images
5. Logs summary of changes

### Implementing RefreshTrigger

The `containers.RefreshTrigger` interface must be implemented by the agent or k8s-scan-server:

```go
type RefreshTrigger interface {
    TriggerRefresh() error
}
```

**Example implementation for k8s-scan-server**:

```go
type K8sRefreshTrigger struct {
    k8sClient *kubernetes.Clientset
    manager   *containers.Manager
}

func (t *K8sRefreshTrigger) TriggerRefresh() error {
    // 1. Query Kubernetes API for all pods
    pods, err := t.k8sClient.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
    if err != nil {
        return fmt.Errorf("failed to list pods: %w", err)
    }

    // 2. Convert to ContainerInstance slice
    instances := convertPodsToInstances(pods)

    // 3. Call SetContainerInstances to reconcile
    t.manager.SetContainerInstances(instances)

    return nil
}
```

**Example implementation for agent**:

```go
type AgentRefreshTrigger struct {
    dockerClient *docker.Client
    manager      *containers.Manager
}

func (t *AgentRefreshTrigger) TriggerRefresh() error {
    // 1. Query Docker/containerd for all containers
    containers, err := t.dockerClient.ContainerList(context.Background(), types.ContainerListOptions{})
    if err != nil {
        return fmt.Errorf("failed to list containers: %w", err)
    }

    // 2. Convert to ContainerInstance slice
    instances := convertContainersToInstances(containers)

    // 3. Call SetContainerInstances to reconcile
    t.manager.SetContainerInstances(instances)

    return nil
}
```

### Reconciliation Statistics

The reconciliation process tracks and logs:
- **InstancesAdded**: New container instances discovered
- **InstancesRemoved**: Container instances no longer running
- **ImagesAdded**: New container images discovered (triggers scans)

Example log output:
```
Set container instances: 42 instances, 12 unique images, 3 nodes
Reconciliation complete: added=42, removed=38, new_images=2
Reconciliation summary: 42 instances added, 38 instances removed, 2 new images discovered
```

### Configuration

```go
type Config struct {
    Jobs struct {
        RefreshImages struct {
            Enabled  bool          `yaml:"enabled"`
            Interval time.Duration `yaml:"interval"` // Default: 6h
            Timeout  time.Duration `yaml:"timeout"`  // Default: 10m
        } `yaml:"refresh_images"`
    } `yaml:"jobs"`
}
```

### Setup Example

```go
// In your main.go or setup function:

// 1. Create the refresh trigger (implemented by agent/k8s-scan-server)
refreshTrigger := &K8sRefreshTrigger{
    k8sClient: k8sClient,
    manager:   containerManager,
}

// 2. Create the scheduler
scheduler := scheduler.New()

// 3. Add the refresh job
refreshJob := jobs.NewRefreshImagesJob(refreshTrigger)
scheduler.AddJob(
    refreshJob,
    scheduler.NewIntervalSchedule(6*time.Hour),
    scheduler.JobConfig{
        Enabled: true,
        Timeout: 10*time.Minute,
    },
)

// 4. Start the scheduler
ctx := context.Background()
scheduler.Start(ctx)
```

### Testing

The job includes comprehensive tests:
```bash
go test ./jobs/
```

Test coverage includes:
- Successful refresh
- Failed refresh (error handling)
- Nil trigger (panics as expected)
- Context cancellation

## Cleanup Orphaned Images Job

**Purpose**: Removes container images that no longer have associated container instances, freeing up database space.

**Schedule**: Daily (24 hours)

**What it cleans**:
1. **Container Images**: Images with no running instances
2. **Packages**: SBOM packages for orphaned images
3. **Vulnerabilities**: Vulnerability data for orphaned images

**How it works**:
1. Job calls `database.CleanupOrphanedImages()`
2. Database identifies images with no `container_instances`
3. Deletes orphaned images and cascading data
4. Logs detailed statistics

### Example Log Output

```
[cleanup] Starting cleanup of orphaned container images
Cleanup complete: removed 5 images, 123 packages, 456 vulnerabilities
[cleanup] Cleanup job completed successfully
```

### Configuration

```go
type Config struct {
    Jobs struct {
        Cleanup struct {
            Enabled  bool          `yaml:"enabled"`
            Interval time.Duration `yaml:"interval"` // Default: 24h
            Timeout  time.Duration `yaml:"timeout"`  // Default: 1h
        } `yaml:"cleanup"`
    } `yaml:"jobs"`
}
```

### Setup Example

```go
// Create the scheduler
scheduler := scheduler.New()

// Add the cleanup job
cleanupJob := jobs.NewCleanupOrphanedImagesJob(database)
scheduler.AddJob(
    cleanupJob,
    scheduler.NewIntervalSchedule(24*time.Hour),
    scheduler.JobConfig{
        Enabled: true,
        Timeout: 1*time.Hour,
    },
)

scheduler.Start(ctx)
```

### Testing

```bash
go test ./jobs/ -run Cleanup
go test ./database/ -run Cleanup
```

## Future Jobs

Additional jobs can be added following the same pattern:
- **RescanDatabaseJob**: Check for Grype database updates, trigger rescans
- **TelemetryJob**: Send metrics to OpenTelemetry collector

Each job implements the `scheduler.Job` interface:
```go
type Job interface {
    Name() string
    Run(ctx context.Context) error
}
```
