package warden

import (
	"context"
	"errors"
	"testing"
)

func TestSyncDirectorySnapshotNormalizesProjection(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	principal, err := svc.SyncDirectorySnapshot(ctx, CasdoorDirectorySnapshot{
		Tenant: Tenant{ID: "tenant-a", CasdoorOrgName: "acme", Slug: "acme", DisplayName: "Acme"},
		User:   CasdoorUser{ID: "user-a", Username: "alice", Email: "alice@example.com", DisplayName: "Alice"},
		Groups: []CasdoorGroup{{ID: "group-a", Name: "research", DisplayName: "Research"}},
		Roles:  []string{"admin", "app.chathub.user", "unknown.role", "admin"},
	})
	if err != nil {
		t.Fatalf("SyncDirectorySnapshot: %v", err)
	}
	if principal.ID == "" || principal.Status != "active" || len(principal.Teams) != 1 {
		t.Fatalf("principal = %+v", principal)
	}
	if !has(roleKeys(principal.Roles), RoleTenantAdmin) || !has(roleKeys(principal.Roles), RoleChatHubUser) || has(roleKeys(principal.Roles), "unknown.role") {
		t.Fatalf("roles = %+v", principal.Roles)
	}
	loaded, err := store.GetPrincipal(ctx, principal.ID)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}
	if loaded.CasdoorUserID != "user-a" || len(loaded.Teams) != 1 {
		t.Fatalf("loaded principal = %+v", loaded)
	}
}

func TestSyncDirectorySnapshotDisabledRevokesSessions(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	principal, err := svc.SyncDirectorySnapshot(ctx, CasdoorDirectorySnapshot{
		Tenant: Tenant{ID: "tenant-a", Slug: "acme", DisplayName: "Acme"},
		User:   CasdoorUser{ID: "user-a", Username: "alice"},
		Roles:  []string{"viewer"},
	})
	if err != nil {
		t.Fatal(err)
	}
	session, err := svc.CreateSession(ctx, principal.ID, testNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSession(ctx, session.ID); err != nil {
		t.Fatal(err)
	}

	disabled, err := svc.SyncDirectorySnapshot(ctx, CasdoorDirectorySnapshot{
		Tenant: Tenant{ID: "tenant-a", Slug: "acme", DisplayName: "Acme"},
		User:   CasdoorUser{ID: "user-a", Username: "alice", Disabled: true},
		Roles:  []string{"viewer"},
	})
	if err != nil {
		t.Fatalf("SyncDirectorySnapshot disabled: %v", err)
	}
	if disabled.Status != "disabled" {
		t.Fatalf("disabled principal = %+v", disabled)
	}
	if _, err := store.GetSession(ctx, session.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session err = %v, want ErrNotFound", err)
	}
	if _, err := svc.CreateSession(ctx, principal.ID, testNow()); !errors.Is(err, ErrDisabled) {
		t.Fatalf("CreateSession err = %v, want ErrDisabled", err)
	}
}
