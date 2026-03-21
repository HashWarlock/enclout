package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakePendingPoller struct {
	mu       sync.Mutex
	results  []pollResult
	calls    int
}

type pollResult struct {
	requests []PendingRequest
	err      error
}

func (f *fakePendingPoller) ListPending(_ context.Context, _ string) ([]PendingRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.calls
	f.calls++
	if i >= len(f.results) {
		return nil, nil
	}
	return f.results[i].requests, f.results[i].err
}

func (f *fakePendingPoller) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestDaemon_PollsOnInterval(t *testing.T) {
	poller := &fakePendingPoller{
		results: []pollResult{
			{requests: nil},
			{requests: nil},
			{requests: nil},
		},
	}

	// Use a minimal runner (no real processing needed since no requests are returned).
	runner := NewRunner(
		&fakeRequestClient{},
		fakeDecisionSource{approved: true},
		&fakeBundleVerifier{},
		&fakeKeyInstaller{},
		&fakeTrustedKeys{},
		nil,
	)

	d := NewDaemon(poller, runner, "device-1", 50*time.Millisecond, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	_ = d.Run(ctx)

	calls := poller.callCount()
	if calls < 2 {
		t.Fatalf("expected at least 2 poll calls in 300ms with 50ms interval, got %d", calls)
	}
}

func TestDaemon_GracefulShutdown(t *testing.T) {
	poller := &fakePendingPoller{
		results: []pollResult{
			{requests: nil},
			{requests: nil},
		},
	}

	runner := NewRunner(
		&fakeRequestClient{},
		fakeDecisionSource{approved: true},
		&fakeBundleVerifier{},
		&fakeKeyInstaller{},
		&fakeTrustedKeys{},
		nil,
	)

	d := NewDaemon(poller, runner, "device-1", 50*time.Millisecond, nil)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- d.Run(ctx)
	}()

	// Let it poll at least once.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected nil error on graceful shutdown, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("daemon did not shut down within timeout")
	}
}

func TestDaemon_BackoffOnError(t *testing.T) {
	poller := &fakePendingPoller{
		results: []pollResult{
			{err: errors.New("network error")},
			{err: errors.New("network error")},
			{requests: nil}, // success resets backoff
			{requests: nil},
		},
	}

	runner := NewRunner(
		&fakeRequestClient{},
		fakeDecisionSource{approved: true},
		&fakeBundleVerifier{},
		&fakeKeyInstaller{},
		&fakeTrustedKeys{},
		nil,
	)

	d := NewDaemon(poller, runner, "device-1", 50*time.Millisecond, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_ = d.Run(ctx)

	calls := poller.callCount()
	if calls < 2 {
		t.Fatalf("expected at least 2 poll calls, got %d", calls)
	}
}
