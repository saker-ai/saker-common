//go:build integration

package warden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type directoryFixture struct {
	config CasdoorDirectoryConfig
	mode   atomic.Int32
}

func newDirectoryFixture(t *testing.T) *directoryFixture {
	t.Helper()
	f := &directoryFixture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, secret, ok := r.BasicAuth()
		if !ok || id != "directory-client" || secret != "fixture-secret" || r.URL.Path != "/api/get-user" || r.URL.Query().Get("owner") != "acme" || r.URL.Query().Get("userId") == "" {
			t.Error("directory request did not use scoped, authenticated UUID lookup")
			w.WriteHeader(400)
			return
		}
		mode := f.mode.Load()
		if mode == 3 {
			w.WriteHeader(503)
			return
		}
		var user any
		if mode != 5 {
			subject, owner := r.URL.Query().Get("userId"), "acme"
			if mode == 4 {
				subject = "other-user"
			}
			if mode == 6 {
				owner = "other-organization"
			}
			groups := []string{"acme/research"}
			if mode == 2 {
				groups = nil
			}
			user = map[string]any{
				"id": subject, "owner": owner, "name": "alice", "email": "alice@example.invalid", "isAdmin": true,
				"isForbidden": mode == 7, "groups": groups,
				"roles": []any{map[string]any{"owner": "acme", "name": "chat", "isEnabled": mode != 1}, map[string]any{"owner": "acme", "name": "admin", "isEnabled": true}},
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "data": user})
	}))
	t.Cleanup(server.Close)
	f.config = CasdoorDirectoryConfig{BaseURL: server.URL, ClientID: "directory-client", ClientSecret: "fixture-secret", Mappings: []CasdoorTenantMapping{{
		Organization: "acme", TenantID: "tenant-a", RequiredGroups: []string{"acme/research"}, DefaultRoles: []string{RoleFrontendUser},
		RoleMappings: map[string][]string{"acme/chat": {RoleChatHubUser}},
	}}}
	return f
}

func directoryService(t *testing.T, f *directoryFixture, store Store, refresh bool) (*Service, *CasdoorDirectorySource) {
	t.Helper()
	source, err := NewCasdoorDirectorySource(f.config)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(Config{MasterSecret: testSecret, DirectorySource: source, DirectoryRefreshOnSession: refresh}, store)
	if err != nil {
		t.Fatal(err)
	}
	return svc, source
}

func directorySession(t *testing.T, svc *Service, source *CasdoorDirectorySource, subject string) Session {
	t.Helper()
	principals, err := svc.SyncDirectoryUser(t.Context(), source, subject)
	if err != nil || len(principals) != 1 {
		t.Fatalf("projection=%v, err=%v", principals, err)
	}
	if has(roleKeys(principals[0].Roles), RoleTenantAdmin) {
		t.Fatal("Casdoor isAdmin or unmapped role granted Warden admin")
	}
	session, err := svc.CreateSession(t.Context(), principals[0].ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestDynamicDirectoryRefreshRemovesRolesWithoutElevatingExternalAdmin(t *testing.T) {
	t.Parallel()
	f := newDirectoryFixture(t)
	svc, source := directoryService(t, f, NewMemoryStore(), true)
	session := directorySession(t, svc, source, "stable-user-uuid")
	_, principal, err := svc.ValidateSession(t.Context(), session.ID, time.Now())
	if err != nil || !has(roleKeys(principal.Roles), RoleChatHubUser) {
		t.Fatalf("principal=%+v, err=%v", principal, err)
	}
	f.mode.Store(1)
	_, principal, err = svc.ValidateSession(t.Context(), session.ID, time.Now())
	if err != nil || has(roleKeys(principal.Roles), RoleChatHubUser) {
		t.Fatalf("stale role retained: %+v, %v", principal, err)
	}
}

func TestDynamicDirectorySessionValidationFailsClosed(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		mode    int32
		revoked bool
	}{
		{"membership-removed", 2, true}, {"directory-outage", 3, false}, {"subject-mismatch", 4, false},
		{"user-deleted", 5, true}, {"organization-mismatch", 6, false}, {"user-disabled", 7, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newDirectoryFixture(t)
			store := NewMemoryStore()
			svc, source := directoryService(t, f, store, true)
			session := directorySession(t, svc, source, "stable-user-uuid")
			f.mode.Store(tt.mode)
			if _, _, err := svc.ValidateSession(t.Context(), session.ID, time.Now()); err == nil {
				t.Fatal("directory failure or revocation accepted")
			}
			_, err := store.GetSession(t.Context(), session.ID)
			if tt.revoked && !errors.Is(err, ErrNotFound) {
				t.Fatalf("revoked session survived: %v", err)
			}
			if !tt.revoked {
				if err != nil {
					t.Fatal("transient failure destroyed session")
				}
				f.mode.Store(0)
				if _, _, err := svc.ValidateSession(t.Context(), session.ID, time.Now()); err != nil {
					t.Fatalf("session did not recover: %v", err)
				}
			}
		})
	}
}

func TestDirectoryReconcileFindsPersistedProjectionsAfterRestart(t *testing.T) {
	t.Parallel()
	f := newDirectoryFixture(t)
	store := newTestGORMStore(t)
	defer func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	}()
	svc, source := directoryService(t, f, store, false)
	session := directorySession(t, svc, source, "stable-user-uuid")
	// A fresh source has no process-local list of users. Reconcile must discover
	// persisted subjects and revoke removed membership without a browser request.
	restarted, _ := directoryService(t, f, store, false)
	f.mode.Store(2)
	if err := restarted.ReconcileDirectory(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := restarted.ValidateSession(t.Context(), session.ID, time.Now()); err == nil {
		t.Fatal("reconcile retained removed membership")
	}
}

func TestDirectorySubjectEnumerationIsCompleteAndTenantScoped(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"memory", "sqlite"} {
		t.Run(kind, func(t *testing.T) {
			var store Store = NewMemoryStore()
			if kind == "sqlite" {
				db := newTestGORMStore(t)
				defer func() {
					if err := db.Close(); err != nil {
						t.Error(err)
					}
				}()
				store = db
			}
			if err := store.UpsertTenant(t.Context(), Tenant{ID: "tenant-a", Slug: "a", Status: "active"}); err != nil {
				t.Fatal(err)
			}
			if err := store.UpsertTenant(t.Context(), Tenant{ID: "tenant-b", Slug: "b", Status: "active"}); err != nil {
				t.Fatal(err)
			}
			for i := range 501 {
				status := PrincipalStatusActive
				if i == 0 {
					status = PrincipalStatusDisabled
				}
				if err := store.UpsertPrincipal(t.Context(), Principal{ID: fmt.Sprintf("p-%03d", i), TenantID: "tenant-a", CasdoorUserID: fmt.Sprintf("u-%03d", i), Type: PrincipalTypeUser, Status: status}); err != nil {
					t.Fatal(err)
				}
			}
			if err := store.UpsertPrincipal(t.Context(), Principal{ID: "other", TenantID: "tenant-b", CasdoorUserID: "other", Type: PrincipalTypeUser, Status: "active"}); err != nil {
				t.Fatal(err)
			}
			ids, err := store.(directorySubjectLister).ListDirectorySubjects(t.Context(), "tenant-a")
			if err != nil || len(ids) != 501 || !slices.Contains(ids, "u-000") || slices.Contains(ids, "other") {
				t.Fatalf("subjects=%d, err=%v", len(ids), err)
			}
		})
	}
}

func TestGORMOIDCStateIsBoundDurableAndConsumedOnce(t *testing.T) {
	t.Parallel()
	store := newTestGORMStore(t)
	defer func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	}()
	state := OIDCLoginState{State: "state", Nonce: "nonce", CodeVerifier: "verifier", BrowserBinding: oidcBindingHash("browser"), ExpiresAt: time.Now().Add(time.Minute)}
	if err := store.PutOIDCLoginState(t.Context(), state); err != nil {
		t.Fatal(err)
	}
	if _, err := store.TakeBoundOIDCLoginState(t.Context(), state.State, oidcBindingHash("other-browser")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong browser=%v", err)
	}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			stored, err := store.TakeBoundOIDCLoginState(t.Context(), state.State, state.BrowserBinding)
			if err == nil {
				accepted.Add(1)
				if stored.BrowserBinding != state.BrowserBinding {
					t.Error("binding lost across SQL storage")
				}
			} else if !errors.Is(err, ErrNotFound) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("state accepted %d times", accepted.Load())
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.ListDirectorySubjects(ctx, "tenant-a"); err == nil {
		t.Fatal("canceled query succeeded")
	}
}
