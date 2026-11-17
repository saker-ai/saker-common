package wardn

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAccountsLifecycle(t *testing.T) {
	var revision atomic.Int64
	var unavailable atomic.Bool
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		id, secret, ok := r.BasicAuth()
		if !ok || id != "app" || secret != "secret" || r.Method != "POST" || r.URL.RawQuery != "" {
			t.Error("credentials or request boundary")
			http.Error(w, "bad", 400)
			return
		}
		if unavailable.Load() {
			http.Error(w, "unavailable", 503)
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("subject") != "user" {
			http.Error(w, "bad subject", 400)
			return
		}
		_ = json.NewEncoder(w).Encode(AccountState{Active: true, Subject: "user", Owner: "saker", Revision: revision.Load(), DisplayName: "Alice", Email: "alice@example.test", EmailVerified: true})
	}))
	defer server.Close()
	accounts, err := NewAccounts(Config{Issuer: server.URL, ClientID: "app", ClientSecret: "secret", AllowInsecureLoopback: true})
	if err != nil {
		t.Fatal(err)
	}
	state, err := accounts.Capture(t.Context(), "user", "signed-id-token")
	if err != nil || state.Revision != 0 || state.Profile().AccountName() != "Alice" {
		t.Fatalf("capture: %v", err)
	}
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() {
			if _, err := accounts.Check(t.Context(), "user", 0); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("login state was fetched again: %d", calls.Load())
	}
	revision.Store(1)
	accounts.mu.Lock()
	accounts.cache["user"].until = time.Time{}
	accounts.mu.Unlock()
	if _, err = accounts.Check(t.Context(), "user", 0); !errors.Is(err, ErrRevoked) {
		t.Fatalf("old session: %v", err)
	}
	if _, err = accounts.Check(t.Context(), "user", 1); err != nil {
		t.Fatal(err)
	}
	unavailable.Store(true)
	accounts.mu.Lock()
	accounts.cache["user"].until = time.Time{}
	accounts.mu.Unlock()
	if _, err = accounts.Check(t.Context(), "user", 1); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("outage: %v", err)
	}
}

func TestAccountsRejectInvalidAuthority(t *testing.T) {
	for _, name := range []string{"wrong subject", "wrong owner", "duplicate", "trailing", "redirect"} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch name {
				case "wrong subject":
					w.Write([]byte(`{"active":true,"sub":"other","owner":"saker"}`))
				case "wrong owner":
					w.Write([]byte(`{"active":true,"sub":"user","owner":"other"}`))
				case "duplicate":
					w.Write([]byte(`{"active":false,"active":true,"sub":"user","owner":"saker"}`))
				case "trailing":
					w.Write([]byte(`{"active":true,"sub":"user","owner":"saker"} {}`))
				case "redirect":
					http.Redirect(w, r, "https://example.test", 302)
				}
			}))
			defer server.Close()
			accounts, _ := NewAccounts(Config{Issuer: server.URL, ClientID: "app", ClientSecret: "secret", AllowInsecureLoopback: true})
			if _, err := accounts.Check(t.Context(), "user", 0); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}

func TestAccountsInvalidate(t *testing.T) {
	for _, subject := range []string{"user", ""} {
		t.Run("subject="+subject, func(t *testing.T) {
			pending := &accountSnapshot{done: make(chan struct{})}
			accounts := &Accounts{cache: map[string]*accountSnapshot{
				"user":    {until: time.Now().Add(time.Hour)},
				"other":   {until: time.Now().Add(time.Hour)},
				"pending": pending,
			}}
			accounts.Invalidate(subject)
			if accounts.cache["user"] != nil || accounts.cache["pending"] != pending {
				t.Fatal("completed cache retained or pending query removed")
			}
			if (accounts.cache["other"] == nil) != (subject == "") {
				t.Fatal("invalidation affected the wrong subject")
			}
		})
	}
}
