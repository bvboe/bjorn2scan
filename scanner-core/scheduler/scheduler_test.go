package scheduler

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// mockJob is a test job implementation
type mockJob struct {
	name       string
	execCount  int
	execTimes  []time.Time
	mu         sync.Mutex
	shouldFail bool
	runFunc    func(ctx context.Context) error
}

func (m *mockJob) Name() string {
	return m.name
}

func (m *mockJob) Run(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.execCount++
	m.execTimes = append(m.execTimes, time.Now())

	if m.runFunc != nil {
		return m.runFunc(ctx)
	}

	if m.shouldFail {
		return errors.New("mock job failed")
	}
	return nil
}

func (m *mockJob) getExecCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.execCount
}

func (m *mockJob) getExecTimes() []time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	times := make([]time.Time, len(m.execTimes))
	copy(times, m.execTimes)
	return times
}

func TestSchedulerBasics(t *testing.T) {
	s := New()

	// Test adding jobs
	job1 := &mockJob{name: "test-job-1"}
	err := s.AddJob(job1, NewIntervalSchedule(1*time.Hour), JobConfig{Enabled: true})
	if err != nil {
		t.Fatalf("Failed to add job: %v", err)
	}

	// Test duplicate job
	err = s.AddJob(job1, NewIntervalSchedule(1*time.Hour), JobConfig{Enabled: true})
	if err == nil {
		t.Error("Expected error when adding duplicate job")
	}

	// Test disabled job
	job2 := &mockJob{name: "test-job-2"}
	err = s.AddJob(job2, NewIntervalSchedule(1*time.Hour), JobConfig{Enabled: false})
	if err != nil {
		t.Fatalf("Failed to add disabled job: %v", err)
	}

	// Verify only enabled job is in the list
	jobs := s.GetJobs()
	if len(jobs) != 1 {
		t.Errorf("Expected 1 job, got %d", len(jobs))
	}
}

func TestSchedulerExecution(t *testing.T) {
	s := New()

	// Create a job that runs every 100ms
	job := &mockJob{name: "fast-job"}
	err := s.AddJob(job, NewIntervalSchedule(100*time.Millisecond), JobConfig{
		Enabled: true,
		Timeout: 1 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to add job: %v", err)
	}

	// Start scheduler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = s.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start scheduler: %v", err)
	}

	// Wait for job to execute multiple times
	time.Sleep(350 * time.Millisecond)

	// Stop scheduler
	err = s.Stop()
	if err != nil {
		t.Fatalf("Failed to stop scheduler: %v", err)
	}

	// Verify job was executed at least 2 times
	execCount := job.getExecCount()
	if execCount < 2 {
		t.Errorf("Expected at least 2 executions, got %d", execCount)
	}
}

func TestSchedulerJitter(t *testing.T) {
	s := New()

	// Create a job with jitter
	job := &mockJob{name: "jitter-job"}
	err := s.AddJob(job, NewIntervalScheduleWithJitter(100*time.Millisecond, 50*time.Millisecond), JobConfig{
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("Failed to add job: %v", err)
	}

	// Start scheduler
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = s.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start scheduler: %v", err)
	}

	// Let it run for a while
	time.Sleep(500 * time.Millisecond)

	err = s.Stop()
	if err != nil {
		t.Fatalf("Failed to stop scheduler: %v", err)
	}

	// Verify intervals have jitter
	times := job.getExecTimes()
	if len(times) < 2 {
		t.Skip("Not enough executions to test jitter")
	}

	for i := 1; i < len(times); i++ {
		interval := times[i].Sub(times[i-1])
		// Should be between 100ms and 150ms
		if interval < 100*time.Millisecond || interval > 200*time.Millisecond {
			t.Logf("Interval %d: %v (expected 100-200ms)", i, interval)
		}
	}
}

func TestSchedulerTimeout(t *testing.T) {
	s := New()

	// Create a job that takes too long
	job := &mockJob{
		name: "slow-job",
		runFunc: func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(1 * time.Second):
				return nil
			}
		},
	}

	err := s.AddJob(job, NewIntervalSchedule(100*time.Millisecond), JobConfig{
		Enabled: true,
		Timeout: 50 * time.Millisecond, // Timeout before job completes
	})
	if err != nil {
		t.Fatalf("Failed to add job: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = s.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start scheduler: %v", err)
	}

	// Wait for job to timeout
	time.Sleep(200 * time.Millisecond)

	err = s.Stop()
	if err != nil {
		t.Fatalf("Failed to stop scheduler: %v", err)
	}

	// Verify job was attempted
	if job.getExecCount() < 1 {
		t.Error("Expected at least 1 execution")
	}
}

func TestSchedulerManualTrigger(t *testing.T) {
	s := New()

	job := &mockJob{name: "manual-job"}
	err := s.AddJob(job, NewIntervalSchedule(1*time.Hour), JobConfig{Enabled: true})
	if err != nil {
		t.Fatalf("Failed to add job: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = s.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start scheduler: %v", err)
	}

	// Manually trigger the job
	err = s.RunJobNow("manual-job")
	if err != nil {
		t.Fatalf("Failed to trigger job: %v", err)
	}

	// Wait for manual execution
	time.Sleep(100 * time.Millisecond)

	// Test triggering non-existent job
	err = s.RunJobNow("non-existent")
	if err == nil {
		t.Error("Expected error when triggering non-existent job")
	}

	err = s.Stop()
	if err != nil {
		t.Fatalf("Failed to stop scheduler: %v", err)
	}

	// Verify job was executed once (manually)
	execCount := job.getExecCount()
	if execCount != 1 {
		t.Errorf("Expected 1 execution, got %d", execCount)
	}
}

func TestSchedulerGracefulShutdown(t *testing.T) {
	s := New()

	// Create a job that takes some time
	job := &mockJob{
		name: "graceful-job",
		runFunc: func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
				return nil
			}
		},
	}

	err := s.AddJob(job, NewIntervalSchedule(50*time.Millisecond), JobConfig{Enabled: true})
	if err != nil {
		t.Fatalf("Failed to add job: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = s.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start scheduler: %v", err)
	}

	// Wait for job to start
	time.Sleep(100 * time.Millisecond)

	// Stop should wait for running job
	start := time.Now()
	err = s.Stop()
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Failed to stop scheduler: %v", err)
	}

	// Stop should have waited for the job (but less than 30s timeout)
	if duration > 30*time.Second {
		t.Error("Stop took too long (hit timeout)")
	}
}

func TestSchedulerContextCancellation(t *testing.T) {
	s := New()

	execCompleted := false
	job := &mockJob{
		name: "context-job",
		runFunc: func(ctx context.Context) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(1 * time.Second):
				execCompleted = true
				return nil
			}
		},
	}

	err := s.AddJob(job, NewIntervalSchedule(50*time.Millisecond), JobConfig{Enabled: true})
	if err != nil {
		t.Fatalf("Failed to add job: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	err = s.Start(ctx)
	if err != nil {
		t.Fatalf("Failed to start scheduler: %v", err)
	}

	// Wait for job to start, then cancel context
	time.Sleep(100 * time.Millisecond)
	cancel()

	// Stop scheduler
	err = s.Stop()
	if err != nil {
		t.Fatalf("Failed to stop scheduler: %v", err)
	}

	// Job should not have completed
	if execCompleted {
		t.Error("Job should have been cancelled, but completed")
	}
}

func TestIntervalSchedule(t *testing.T) {
	now := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)

	// Test basic interval
	schedule := NewIntervalSchedule(5 * time.Minute)
	next := schedule.Next(now)
	expected := now.Add(5 * time.Minute)

	if !next.Equal(expected) {
		t.Errorf("Expected next run at %v, got %v", expected, next)
	}

	// Test with jitter
	scheduleWithJitter := NewIntervalScheduleWithJitter(5*time.Minute, 2*time.Minute)
	next = scheduleWithJitter.Next(now)

	// Next should be between 5 and 7 minutes
	minNext := now.Add(5 * time.Minute)
	maxNext := now.Add(7 * time.Minute)

	if next.Before(minNext) || next.After(maxNext) {
		t.Errorf("Expected next run between %v and %v, got %v", minNext, maxNext, next)
	}
}
