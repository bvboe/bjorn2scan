package metrics

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	metricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
)

// slowSender blocks for a fixed duration per Send, standing in for the receiver
// ingest that dominates the real send path.
type slowSender struct {
	delay time.Duration

	mu       sync.Mutex
	inFlight int
	maxSeen  int
	sends    int
	points   int

	failAfter int32 // if > 0, fail once this many sends have started
	started   int32
}

func (s *slowSender) Send(_ context.Context, metrics []*metricsv1.Metric) error {
	n := atomic.AddInt32(&s.started, 1)

	s.mu.Lock()
	s.inFlight++
	if s.inFlight > s.maxSeen {
		s.maxSeen = s.inFlight
	}
	s.mu.Unlock()

	time.Sleep(s.delay)

	s.mu.Lock()
	s.inFlight--
	s.sends++
	s.points += countPoints(metrics)
	s.mu.Unlock()

	if s.failAfter > 0 && n >= s.failAfter {
		return errors.New("simulated send failure")
	}
	return nil
}

func (s *slowSender) Close() error       { return nil }
func (s *slowSender) Stats() SenderStats { return SenderStats{} }

func recordN(a *DirectEmitAccumulator, n int) {
	for i := 0; i < n; i++ {
		a.Record("bjorn2scan_pipeline_test", "help",
			map[string]string{"i": string(rune('a' + i%26))}, float64(i))
	}
}

// TestSendOverlapsCollection is the point of the change.
//
// The export used to be strictly serial — collect a batch, send it, collect the
// next — on a pod with a 2-core limit that used one core. With sending on its own
// goroutine, the wall clock should approach the time spent sending rather than
// the sum of both phases.
//
// The producer here does negligible work, so with N batches each taking `delay`
// to send, a serial implementation takes about N*delay and a pipelined one is
// bounded below by the same N*delay (the sender is the bottleneck). What proves
// overlap is that the producer finishes long before the sends do.
func TestSendOverlapsCollection(t *testing.T) {
	const (
		batchSize = 10
		batches   = 5
		delay     = 60 * time.Millisecond
	)
	sender := &slowSender{delay: delay}
	acc := NewDirectEmitAccumulator(context.Background(), sender, batchSize, 1, 1)

	producerStart := time.Now()
	recordN(acc, batchSize*batches)
	producerElapsed := time.Since(producerStart)

	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	total := time.Since(producerStart)

	// Serial execution would keep the producer blocked inside Record for every
	// completed batch, so it could not return in much less than (batches-1)*delay.
	serialFloor := time.Duration(batches-1) * delay
	if producerElapsed >= serialFloor {
		t.Errorf("producer took %v, which is at least the serial floor %v — "+
			"collection is still blocking on sends", producerElapsed, serialFloor)
	}

	if sender.sends != batches {
		t.Errorf("sender saw %d batches, want %d", sender.sends, batches)
	}
	if got, want := sender.points, batchSize*batches; got != want {
		t.Errorf("sender received %d points, want %d", got, want)
	}
	t.Logf("producer returned in %v, whole cycle %v, %d batches x %v",
		producerElapsed.Round(time.Millisecond), total.Round(time.Millisecond), batches, delay)
}

// TestBackpressureBoundsQueuedBatches guards the memory side. Each queued or
// in-flight batch holds batchSize data points, and memory is this exporter's
// binding constraint, so the producer must not be able to run arbitrarily far
// ahead of a slow receiver. At concurrency 1 exactly one send is in flight and
// the channel holds one more.
func TestBackpressureBoundsQueuedBatches(t *testing.T) {
	sender := &slowSender{delay: 20 * time.Millisecond}
	acc := NewDirectEmitAccumulator(context.Background(), sender, 5, 1, 1)

	recordN(acc, 100) // 20 batches through a depth-1 channel
	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	if sender.maxSeen > 1 {
		t.Errorf("%d sends in flight at concurrency 1, want 1", sender.maxSeen)
	}
	if cap(acc.batches) > 1 {
		t.Errorf("batch channel depth %d at concurrency 1; each queued batch is "+
			"memory held on behalf of a slow receiver", cap(acc.batches))
	}
}

// TestConcurrentSendsOverlap is the option-4 claim: several batches must be in
// the send path at once.
//
// After sending moved off the collection goroutine it became the bottleneck and
// was serial within itself — marshal, compress, http, one batch at a time — with
// most of that time (2,285 of 4,158 ms measured) spent waiting on the receiver
// while the CPU idled. Overlapping sends is what recovers that wait.
func TestConcurrentSendsOverlap(t *testing.T) {
	const concurrency = 3
	sender := &slowSender{delay: 40 * time.Millisecond}
	acc := NewDirectEmitAccumulator(context.Background(), sender, 5, concurrency, 1)

	start := time.Now()
	recordN(acc, 60) // 12 batches
	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	elapsed := time.Since(start)

	if sender.maxSeen < 2 {
		t.Errorf("peak sends in flight was %d at concurrency %d; batches are still "+
			"being sent one at a time", sender.maxSeen, concurrency)
	}
	if sender.maxSeen > concurrency {
		t.Errorf("%d sends in flight exceeds the configured concurrency %d; each one "+
			"holds a batch in memory", sender.maxSeen, concurrency)
	}

	// 12 batches at 40ms serial is 480ms; with 3 in flight it should be far less.
	serial := 12 * 40 * time.Millisecond
	if elapsed > serial*3/4 {
		t.Errorf("took %v, close to the serial time %v — sends are not overlapping",
			elapsed.Round(time.Millisecond), serial)
	}

	if sender.sends != 12 || sender.points != 60 {
		t.Errorf("delivered %d batches / %d points, want 12 / 60 — concurrency must "+
			"not drop or duplicate data", sender.sends, sender.points)
	}
}

// TestConcurrentSendsAccountCorrectly checks the shared counters under
// concurrency. They are written by every sender goroutine, so an unguarded
// increment would lose batches and under-report what was pushed — silently, and
// only under load.
func TestConcurrentSendsAccountCorrectly(t *testing.T) {
	sender := &slowSender{delay: time.Millisecond}
	acc := NewDirectEmitAccumulator(context.Background(), sender, 10, 4, 1)

	recordN(acc, 1000) // 100 batches across 4 senders
	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	batches, points := acc.Totals()
	if batches != 100 || points != 1000 {
		t.Errorf("Totals() = (%d, %d), want (100, 1000)", batches, points)
	}
}

// TestSendErrorStopsCollection checks that a failure on the sender goroutine
// still reaches the producer. With sending inline the error surfaced
// immediately; asynchronously it has to be propagated, and a dropped error would
// mean silently exporting nothing while reporting success.
func TestSendErrorStopsCollection(t *testing.T) {
	sender := &slowSender{delay: time.Millisecond, failAfter: 1}
	acc := NewDirectEmitAccumulator(context.Background(), sender, 5, 1, 1)

	recordN(acc, 100)

	if err := acc.Flush(); err == nil {
		t.Error("Flush returned nil after the sender failed; the cycle would be "+
			"reported as successful", err)
	}
}

// TestFlushWaitsForSender ensures Totals and SendDuration are not read while the
// sender goroutine is still writing them. Without the wait this is a data race
// and the reported counts are whatever happened to be visible.
func TestFlushWaitsForSender(t *testing.T) {
	sender := &slowSender{delay: 30 * time.Millisecond}
	acc := NewDirectEmitAccumulator(context.Background(), sender, 10, 1, 1)

	recordN(acc, 40)
	if err := acc.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}

	batches, points := acc.Totals()
	if batches != 4 || points != 40 {
		t.Errorf("Totals() = (%d batches, %d points), want (4, 40) — Flush returned "+
			"before the sender finished accounting", batches, points)
	}
	if acc.SendDuration() < 4*30*time.Millisecond {
		t.Errorf("SendDuration %v is less than the 4 sends x 30ms actually performed",
			acc.SendDuration())
	}
}

// TestContextCancellationUnblocksProducer covers shutdown: if the context is
// cancelled while the producer is blocked on backpressure, it must not hang.
func TestContextCancellationUnblocksProducer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sender := &slowSender{delay: 500 * time.Millisecond}
	acc := NewDirectEmitAccumulator(ctx, sender, 2, 1, 1)

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		recordN(acc, 200)
		_ = acc.Flush()
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("producer did not unblock after context cancellation")
	}
}
