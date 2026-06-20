package warden

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestDirectoryReconcilerRunsAndStops(t *testing.T) {
	source := &countingDirectorySource{called: make(chan struct{}, 4)}
	store := NewMemoryStore()
	svc, err := NewService(Config{
		Issuer:          "warden",
		MasterSecret:    testSecret,
		DirectorySource: source,
	}, store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	reconciler := NewDirectoryReconciler(svc, 5*time.Millisecond)
	reconciler.Start(context.Background())
	select {
	case <-source.called:
	case <-time.After(time.Second):
		t.Fatal("reconcile was not called")
	}
	reconciler.Stop(context.Background())
	afterStop := source.calls.Load()
	time.Sleep(20 * time.Millisecond)
	if got := source.calls.Load(); got != afterStop {
		t.Fatalf("reconcile calls after stop = %d, want %d", got, afterStop)
	}
}

type countingDirectorySource struct {
	calls  atomic.Int64
	called chan struct{}
}

func (s *countingDirectorySource) SyncUser(context.Context, string) ([]CasdoorDirectorySnapshot, error) {
	return nil, nil
}

func (s *countingDirectorySource) Reconcile(context.Context) error {
	s.calls.Add(1)
	select {
	case s.called <- struct{}{}:
	default:
	}
	return nil
}
