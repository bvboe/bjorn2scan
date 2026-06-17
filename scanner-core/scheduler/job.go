package scheduler

import (
	"context"
	"time"
)

// Job represents a scheduled task that can be executed
type Job interface {
	// Name returns the unique identifier for this job
	Name() string

	// Run executes the job. It should respect context cancellation.
	// Returns an error if the job fails.
	Run(ctx context.Context) error
}

// Schedule defines when a job should run
type Schedule interface {
	// Next calculates the next run time after the given time
	Next(after time.Time) time.Time
}

// IntervalSchedule runs a job at fixed intervals
type IntervalSchedule struct {
	interval time.Duration
	jitter   time.Duration // Random delay added to interval (0 to jitter)
}

// NewIntervalSchedule creates a schedule that runs every interval
func NewIntervalSchedule(interval time.Duration) *IntervalSchedule {
	return &IntervalSchedule{
		interval: interval,
		jitter:   0,
	}
}

// NewIntervalScheduleWithJitter creates a schedule with random jitter
// The job will run at interval + random(0, jitter)
// Example: interval=5m, jitter=2m means job runs every 5-7 minutes
func NewIntervalScheduleWithJitter(interval, jitter time.Duration) *IntervalSchedule {
	return &IntervalSchedule{
		interval: interval,
		jitter:   jitter,
	}
}

// Next returns the next scheduled time
func (s *IntervalSchedule) Next(after time.Time) time.Time {
	next := after.Add(s.interval)
	if s.jitter > 0 {
		// Add random jitter between 0 and jitter duration
		jitterAmount := time.Duration(randInt63n(int64(s.jitter)))
		next = next.Add(jitterAmount)
	}
	return next
}

// JobConfig holds configuration for a scheduled job
type JobConfig struct {
	Enabled        bool
	Timeout        time.Duration // Maximum execution time (0 = no timeout)
	RunImmediately bool          // If true, run once at startup before the first scheduled interval
}
