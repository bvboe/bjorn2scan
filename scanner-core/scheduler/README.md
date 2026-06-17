# Job Scheduler Framework

A lightweight job scheduling framework for managing recurring tasks in scanner-core.

## Features

- **Interval-based scheduling** - Run jobs at fixed intervals (e.g., every 5 minutes)
- **Jitter support** - Add randomness to prevent thundering herd (e.g., OpenTelemetry batching)
- **Graceful shutdown** - Waits for running jobs to complete on shutdown
- **Timeout support** - Set maximum execution time per job
- **Manual triggering** - Trigger any job on-demand
- **Context-aware** - All jobs respect context cancellation
- **Simple & lightweight** - No external dependencies, easy to test

## Architecture

```
scheduler/
├── job.go           # Job interface and Schedule types
├── scheduler.go     # Main scheduler implementation
├── scheduler_test.go
└── example_usage.go # Usage examples

jobs/
├── example_jobs.go  # Placeholder job implementations
```

## Quick Start

### 1. Implement the Job interface

```go
type MyJob struct {
    // Your dependencies
}

func (j *MyJob) Name() string {
    return "my-job"
}

func (j *MyJob) Run(ctx context.Context) error {
    // Your job logic here
    // Respect ctx cancellation
    return nil
}
```

### 2. Register jobs with the scheduler

```go
s := scheduler.New()

// Simple interval job (every 5 minutes)
s.AddJob(
    jobs.NewRefreshImagesJob(),
    scheduler.NewIntervalSchedule(5*time.Minute),
    scheduler.JobConfig{
        Enabled: true,
        Timeout: 2*time.Minute,
    },
)

// Job with jitter (prevents all instances from running simultaneously)
s.AddJob(
    jobs.NewTelemetryJob(),
    scheduler.NewIntervalScheduleWithJitter(5*time.Minute, 2*time.Minute),
    scheduler.JobConfig{
        Enabled: true,
        Timeout: 30*time.Second,
    },
)
```

### 3. Start the scheduler

```go
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

if err := s.Start(ctx); err != nil {
    log.Fatalf("Failed to start scheduler: %v", err)
}

// ... your application runs ...

// Graceful shutdown
s.Stop()
```

## Planned Jobs

### 1. Refresh Images Job
- **Schedule**: Every 5 minutes
- **Purpose**: Trigger refresh of all running container images
- **Dependencies**: Callback to agent/k8s-scanner for container list

### 2. Rescan Database Job
- **Schedule**: Every 1 hour
- **Purpose**: Check if Grype database updated, trigger rescan if needed
- **Dependencies**: Database access, Grype DB version check

### 3. Cleanup Instances Job
- **Schedule**: Daily (e.g., 2am)
- **Purpose**: Delete orphaned data from container_instances and related tables
- **Dependencies**: Database access

### 4. Telemetry Job
- **Schedule**: Every 5 minutes + 2 minute jitter
- **Purpose**: Send metrics to OpenTelemetry collector
- **Dependencies**: OpenTelemetry client
- **Note**: Jitter prevents all instances from sending data simultaneously

## Configuration Example

```go
type Config struct {
    Jobs struct {
        RefreshImages struct {
            Enabled  bool
            Interval time.Duration
            Timeout  time.Duration
        }
        RescanDatabase struct {
            Enabled  bool
            Interval time.Duration
            Timeout  time.Duration
        }
        Cleanup struct {
            Enabled  bool
            Interval time.Duration
            Timeout  time.Duration
        }
        Telemetry struct {
            Enabled  bool
            Interval time.Duration
            Jitter   time.Duration
            Timeout  time.Duration
        }
    }
}
```

## Manual Job Triggering

You can manually trigger any job (useful for testing or on-demand execution):

```go
// Trigger job immediately (non-blocking)
if err := scheduler.RunJobNow("refresh-images"); err != nil {
    log.Printf("Failed to trigger job: %v", err)
}
```

## Error Handling

- Jobs that return errors are logged but don't stop the scheduler
- Failed jobs will retry at their next scheduled interval
- Timeouts are logged as errors

## Testing

Run tests:
```bash
go test ./scheduler/
```

The test suite covers:
- Basic scheduling and execution
- Jitter randomness
- Timeout handling
- Manual triggering
- Graceful shutdown
- Context cancellation

## Deployment Considerations

### Agent Mode
- Jobs run directly in the agent process
- Single instance per host
- No coordination needed

### Kubernetes Mode
- Scanner-core runs as a singleton deployment
- No distributed locking required
- All jobs run in single pod

## Future Enhancements

If needed, the framework can be extended with:
- Database-backed job state tracking
- Cron-style scheduling (specific times of day)
- Job dependency chains
- Retry with exponential backoff
- Job metrics/observability
