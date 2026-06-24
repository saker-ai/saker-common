package discovery

import (
	"context"
	"sync"
	"time"
)

type Registration struct {
	provider Registrar
	instance ServiceInstance
	cancel   context.CancelFunc
	done     chan struct{}
	once     sync.Once
	mu       sync.RWMutex
}

func Start(ctx context.Context, provider Registrar, instance ServiceInstance) (*Registration, error) {
	normalized, err := Normalize(instance)
	if err != nil {
		return nil, err
	}
	if err := provider.Register(ctx, normalized); err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(ctx)
	reg := &Registration{provider: provider, instance: normalized, cancel: cancel, done: make(chan struct{})}
	go reg.loop(runCtx, normalized.TTL/3)
	return reg, nil
}

func (r *Registration) Stop(ctx context.Context) error {
	var err error
	r.once.Do(func() {
		r.cancel()
		<-r.done
		r.mu.RLock()
		instanceID := r.instance.InstanceID
		r.mu.RUnlock()
		err = r.provider.Deregister(ctx, instanceID)
		closeErr := r.provider.Close()
		if err == nil {
			err = closeErr
		}
	})
	return err
}

func (r *Registration) loop(ctx context.Context, interval time.Duration) {
	defer close(r.done)
	if interval <= 0 {
		interval = 10 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.mu.RLock()
			serviceID := r.instance.ID
			instanceID := r.instance.InstanceID
			r.mu.RUnlock()
			_ = r.provider.Heartbeat(ctx, serviceID, instanceID)
		}
	}
}
