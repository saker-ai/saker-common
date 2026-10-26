package warden

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDirectoryProjectionPreservesDisabledTenant(t *testing.T) {
	t.Parallel()
	store := NewMemoryStore()
	if err := store.UpsertTenant(t.Context(), Tenant{ID: "tenant", Status: PrincipalStatusDisabled}); err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(Config{MasterSecret: testSecret}, store)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := svc.SyncDirectorySnapshot(t.Context(), CasdoorDirectorySnapshot{Tenant: Tenant{ID: "tenant", Status: "active"}, User: CasdoorUser{ID: "user"}})
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := store.GetTenant(t.Context(), "tenant")
	if err != nil || tenant.Status != PrincipalStatusDisabled {
		t.Fatalf("disabled tenant reactivated: %+v, %v", tenant, err)
	}
	if err := store.PutSession(t.Context(), Session{ID: "session", PrincipalID: principal.ID, TenantID: "tenant", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.ValidateSession(t.Context(), "session", time.Now()); err == nil {
		t.Fatal("disabled tenant session accepted")
	}
}

type failedPrincipalRead struct {
	Store
	failure error
	wrote   bool
}

func (s *failedPrincipalRead) GetPrincipal(context.Context, string) (Principal, error) {
	return Principal{}, s.failure
}
func (s *failedPrincipalRead) UpsertPrincipal(context.Context, Principal) error {
	s.wrote = true
	return nil
}

func TestDirectoryProjectionDoesNotTreatReadFailureAsNewUser(t *testing.T) {
	t.Parallel()
	failure := errors.New("database unavailable")
	store := &failedPrincipalRead{Store: NewMemoryStore(), failure: failure}
	svc, err := NewService(Config{MasterSecret: testSecret}, store)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.SyncDirectorySnapshot(t.Context(), CasdoorDirectorySnapshot{Tenant: Tenant{ID: "tenant"}, User: CasdoorUser{ID: "user"}})
	if !errors.Is(err, failure) || store.wrote {
		t.Fatalf("failed lookup led to new projection: %v, wrote=%t", err, store.wrote)
	}
}
