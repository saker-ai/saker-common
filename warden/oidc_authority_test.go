package warden

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestOIDCDiscoveryIsLazyAndSharedAcrossConcurrentLogins(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	callback := "https://portal.example/warden/auth/oidc/callback"
	svc, err := NewService(Config{MasterSecret: testSecret, OIDCRedirectURL: callback, OIDCFactory: func(context.Context) (*OIDCClient, error) {
		calls.Add(1)
		return &OIDCClient{Verifier: &OIDCVerifier{Issuer: "https://id.example", ClientID: "app", AuthorizationURL: "https://id.example/authorize", RedirectURL: callback}}, nil
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("construction performed discovery before managed services start")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := svc.StartOIDCLogin(t.Context(), StartOIDCLoginRequest{}); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("discovery attempts=%d", calls.Load())
	}
}

func TestOIDCWaitingLoginCanCancelWithoutInterruptingSharedDiscovery(t *testing.T) {
	t.Parallel()
	entered, release := make(chan struct{}), make(chan struct{})
	callback := "https://portal.example/callback"
	svc, err := NewService(Config{MasterSecret: testSecret, OIDCRedirectURL: callback, OIDCFactory: func(context.Context) (*OIDCClient, error) {
		close(entered)
		<-release
		return &OIDCClient{Verifier: &OIDCVerifier{Issuer: "https://id.example", ClientID: "app", RedirectURL: callback}}, nil
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := svc.StartOIDCLogin(t.Context(), StartOIDCLoginRequest{}); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery did not start")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := svc.StartOIDCLogin(ctx, StartOIDCLoginRequest{}); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled login=%v", err)
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shared discovery did not complete")
	}
}

func TestOIDCDiscoveryFailureIsSanitizedAndBackedOff(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	svc, err := NewService(Config{MasterSecret: testSecret, OIDCRedirectURL: "https://portal.example/callback", OIDCFactory: func(context.Context) (*OIDCClient, error) {
		calls.Add(1)
		return nil, errors.New("upstream contained secret")
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := svc.StartOIDCLogin(t.Context(), StartOIDCLoginRequest{}); !errors.Is(err, ErrOIDCUnavailable) {
			t.Fatalf("unsanitized discovery error=%v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("discovery outage was not backed off: %d", calls.Load())
	}
}

func TestCanceledDiscoveryDoesNotPoisonNextLogin(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	entered := make(chan struct{})
	callback := "https://portal.example/callback"
	svc, err := NewService(Config{MasterSecret: testSecret, OIDCRedirectURL: callback, OIDCFactory: func(ctx context.Context) (*OIDCClient, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return &OIDCClient{Verifier: &OIDCVerifier{Issuer: "https://id.example", ClientID: "app", RedirectURL: callback}}, nil
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := svc.StartOIDCLogin(ctx, StartOIDCLoginRequest{}); done <- err }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled discovery=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("discovery did not cancel")
	}
	if _, err := svc.StartOIDCLogin(t.Context(), StartOIDCLoginRequest{}); err != nil {
		t.Fatalf("canceled browser poisoned next login: %v", err)
	}
}
