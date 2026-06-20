package warden

import (
	"context"
	"sync"
	"time"
)

type DirectoryReconciler struct {
	service  *Service
	interval time.Duration

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func NewDirectoryReconciler(service *Service, interval time.Duration) *DirectoryReconciler {
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	return &DirectoryReconciler{service: service, interval: interval}
}

func (r *DirectoryReconciler) Start(ctx context.Context) {
	if r == nil || r.service == nil {
		return
	}
	r.mu.Lock()
	if r.cancel != nil {
		r.mu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	r.cancel = cancel
	r.done = done
	r.mu.Unlock()

	go r.loop(runCtx, done)
}

func (r *DirectoryReconciler) Stop(ctx context.Context) {
	if r == nil {
		return
	}
	r.mu.Lock()
	cancel := r.cancel
	done := r.done
	r.cancel = nil
	r.done = nil
	r.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (r *DirectoryReconciler) loop(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = r.service.ReconcileDirectory(ctx)
		}
	}
}
