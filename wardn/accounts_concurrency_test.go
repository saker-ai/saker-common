package wardn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

type accountsTransport func(*http.Request) (*http.Response, error)

func (f accountsTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func accountResponse(revision int64, status int) *http.Response {
	raw, _ := json.Marshal(AccountState{Active: true, Subject: "user", Owner: "saker", Revision: revision})
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(raw)))}
}

func testAccounts(t *testing.T, transport accountsTransport) *Accounts {
	t.Helper()
	a, err := NewAccounts(Config{Issuer: "https://identity.example.test/identity", ClientID: "app", ClientSecret: "secret", HTTPClient: &http.Client{Transport: transport}})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAccountsShareConcurrentResults(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int64
				release := make(chan struct{})
				a := testAccounts(t, func(r *http.Request) (*http.Response, error) {
					calls.Add(1)
					<-release
					return accountResponse(0, status), nil
				})
				var want error
				if status == http.StatusServiceUnavailable {
					want = ErrUnavailable
				} else if status == http.StatusForbidden {
					want = ErrRevoked
				}
				var wg sync.WaitGroup
				for range 32 {
					wg.Go(func() {
						if _, err := a.Check(t.Context(), "user", 0); !errors.Is(err, want) {
							t.Errorf("Check = %v, want %v", err, want)
						}
					})
				}
				synctest.Wait()
				if calls.Load() != 1 {
					t.Fatalf("concurrent RPCs = %d", calls.Load())
				}
				close(release)
				wg.Wait()
				if calls.Load() != 1 {
					t.Fatalf("waiters retried failed RPC: %d", calls.Load())
				}
				_, _ = a.Check(t.Context(), "user", 0)
				wantCalls := int64(1)
				if want != nil {
					wantCalls = 2
				}
				if calls.Load() != wantCalls {
					t.Fatalf("subsequent RPCs = %d, want %d", calls.Load(), wantCalls)
				}
			})
		})
	}
}

func TestAccountsCaptureCacheExpiresWithoutStaleFallback(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls int
		status := http.StatusOK
		a := testAccounts(t, func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Method != http.MethodPost || r.URL.Path != "/identity/api/login/oauth/wardn-account-state" || r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("Accept") != "application/json" || r.Header.Get("Cookie") != "" {
				t.Error("stateless request contract changed")
			}
			return accountResponse(0, status), nil
		})
		if _, err := a.Capture(t.Context(), "user", "signed-token"); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Check(t.Context(), "user", 0); err != nil || calls != 1 {
			t.Fatalf("first page refetched login state: calls=%d err=%v", calls, err)
		}
		time.Sleep(2 * time.Second)
		status = http.StatusServiceUnavailable
		if _, err := a.Check(t.Context(), "user", 0); !errors.Is(err, ErrUnavailable) || calls != 2 {
			t.Fatalf("expired authorization reused: calls=%d err=%v", calls, err)
		}
		status = http.StatusOK
		if _, err := a.Check(t.Context(), "user", 0); err != nil || calls != 3 {
			t.Fatalf("failure cached: calls=%d err=%v", calls, err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := a.Check(ctx, "user", 0); !errors.Is(err, ErrUnavailable) || calls != 3 {
			t.Fatal("canceled check admitted from cache or made RPC")
		}
		if _, err := a.Check(t.Context(), "user", -1); !errors.Is(err, ErrRevoked) || calls != 3 {
			t.Fatal("invalid revision made RPC")
		}
	})
}

func TestAccountsLateCaptureCannotWarmAfterInvalidation(t *testing.T) {
	for _, newerCheck := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalidate", true: "newer check"}[newerCheck], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int64
				release := make(chan struct{})
				a := testAccounts(t, func(r *http.Request) (*http.Response, error) {
					if calls.Add(1) == 1 {
						<-release
						return accountResponse(0, http.StatusOK), nil
					}
					return accountResponse(1, http.StatusOK), nil
				})
				captureDone := make(chan error, 1)
				go func() {
					_, err := a.Capture(t.Context(), "user", "signed-token")
					captureDone <- err
				}()
				synctest.Wait()
				if newerCheck {
					if _, err := a.Check(t.Context(), "user", 1); err != nil {
						t.Fatal(err)
					}
				} else {
					a.Invalidate("")
				}
				close(release)
				err := <-captureDone
				if newerCheck && !errors.Is(err, ErrRevoked) {
					t.Fatalf("old login accepted after newer check: %v", err)
				}
				if _, err := a.Check(t.Context(), "user", 0); !errors.Is(err, ErrRevoked) || calls.Load() != 2 {
					t.Fatalf("late capture replaced revocation: calls=%d err=%v", calls.Load(), err)
				}
			})
		})
	}
}

func TestAccountsCaptureAlwaysValidatesTokenAndKeepsInflightBudget(t *testing.T) {
	var calls int
	a := testAccounts(t, func(r *http.Request) (*http.Response, error) {
		calls++
		_ = r.ParseForm()
		if r.Form.Get("id_token") != "valid" {
			return accountResponse(0, http.StatusForbidden), nil
		}
		return accountResponse(0, http.StatusOK), nil
	})
	if _, err := a.Capture(t.Context(), "user", "valid"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Capture(t.Context(), "user", "invalid"); !errors.Is(err, ErrRevoked) || calls != 2 {
		t.Fatal("cached account bypassed ID token validation")
	}
	a.Invalidate("")
	for i := range 1024 {
		a.cache[fmt.Sprint(i)] = &accountSnapshot{done: make(chan struct{})}
	}
	if _, err := a.Capture(t.Context(), "user", "valid"); err != nil || len(a.cache) != 1024 || a.cache["user"] != nil {
		t.Fatalf("prewarming displaced an inflight query: %v", err)
	}
	if _, err := a.Check(t.Context(), "user", 0); !errors.Is(err, ErrUnavailable) || calls != 3 {
		t.Fatalf("cache budget exceeded: calls=%d err=%v", calls, err)
	}
}

func TestAccountsCanceledOwnerDoesNotPoisonLiveWaiters(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusForbidden, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int64
				a := testAccounts(t, func(r *http.Request) (*http.Response, error) {
					if calls.Add(1) == 1 {
						<-r.Context().Done()
						return nil, r.Context().Err()
					}
					return accountResponse(0, status), nil
				})
				owner, cancel := context.WithCancel(t.Context())
				defer cancel()
				ownerResult := make(chan error, 1)
				go func() { _, err := a.Check(owner, "user", 0); ownerResult <- err }()
				synctest.Wait()
				var waiters sync.WaitGroup
				var want error
				if status == http.StatusForbidden {
					want = ErrRevoked
				}
				if status == http.StatusServiceUnavailable {
					want = ErrUnavailable
				}
				for range 16 {
					waiters.Go(func() {
						_, err := a.Check(t.Context(), "user", 0)
						if !errors.Is(err, want) {
							t.Errorf("live waiter inherited abandoned query: %v, want %v", err, want)
						}
					})
				}
				synctest.Wait()
				cancel()
				ownerErr := <-ownerResult
				waiters.Wait()
				if !errors.Is(ownerErr, ErrUnavailable) || !errors.Is(ownerErr, context.Canceled) {
					t.Errorf("owner cancellation lost: %v", ownerErr)
				}
				// Successful state is reused; a genuine failed authority read may be retried
				// by later arriving callers, but none may inherit the canceled owner's result.
				if status == http.StatusOK && calls.Load() != 2 {
					t.Fatalf("coalesced successful recovery calls=%d", calls.Load())
				}
				if calls.Load() < 2 {
					t.Fatal("live callers never revalidated original authority")
				}
			})
		})
	}
}
