package warden

import (
	"context"
	"errors"
	"testing"
	"time"
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

func TestSyncDirectorySnapshotApprovalRequiredSetsPending(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	svc, err := NewService(Config{
		Issuer:             "warden",
		MasterSecret:       testSecret,
		InternalTTL:        time.Minute,
		RegistrationPolicy: RegistrationPolicyApprovalRequired,
	}, store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	principal, err := svc.SyncDirectorySnapshot(ctx, CasdoorDirectorySnapshot{
		Tenant: Tenant{ID: "tenant-a", Slug: "acme", DisplayName: "Acme"},
		User:   CasdoorUser{ID: "user-a", Username: "alice", Email: "alice@example.com"},
	})
	if err != nil {
		t.Fatalf("SyncDirectorySnapshot: %v", err)
	}
	if principal.Status != PrincipalStatusPending {
		t.Fatalf("status=%s want %s", principal.Status, PrincipalStatusPending)
	}
	if _, err := svc.CreateSession(ctx, principal.ID, testNow()); !errors.Is(err, ErrAuthorizationPending) {
		t.Fatalf("pending login err=%v want ErrAuthorizationPending", err)
	}
}

func TestSyncDirectorySnapshotPreservesAdminDisabledStatus(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	principal, err := svc.SyncDirectorySnapshot(ctx, CasdoorDirectorySnapshot{
		Tenant: Tenant{ID: "tenant-a", Slug: "acme", DisplayName: "Acme"},
		User:   CasdoorUser{ID: "user-a", Username: "alice"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpdatePrincipalStatus(ctx, principal.ID, PrincipalStatusDisabled); err != nil {
		t.Fatal(err)
	}

	synced, err := svc.SyncDirectorySnapshot(ctx, CasdoorDirectorySnapshot{
		Tenant: Tenant{ID: "tenant-a", Slug: "acme", DisplayName: "Acme"},
		User:   CasdoorUser{ID: "user-a", Username: "alice"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if synced.Status != PrincipalStatusDisabled {
		t.Fatalf("status=%s want %s (admin-set status should be preserved on re-sync)", synced.Status, PrincipalStatusDisabled)
	}
}

func TestSyncDirectorySnapshotProjectsEmailVerified(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	principal, err := svc.SyncDirectorySnapshot(ctx, CasdoorDirectorySnapshot{
		Tenant: Tenant{ID: "tenant-a", Slug: "acme", DisplayName: "Acme"},
		User:   CasdoorUser{ID: "user-a", Username: "alice", Email: "alice@example.com", EmailVerified: true},
	})
	if err != nil {
		t.Fatalf("SyncDirectorySnapshot: %v", err)
	}
	if !principal.EmailVerified {
		t.Fatalf("principal.EmailVerified=false, want true")
	}
	loaded, err := store.GetPrincipal(ctx, principal.ID)
	if err != nil {
		t.Fatalf("GetPrincipal: %v", err)
	}
	if !loaded.EmailVerified {
		t.Fatalf("loaded.EmailVerified=false, want true")
	}

	unverified, err := svc.SyncDirectorySnapshot(ctx, CasdoorDirectorySnapshot{
		Tenant: Tenant{ID: "tenant-a", Slug: "acme", DisplayName: "Acme"},
		User:   CasdoorUser{ID: "user-a", Username: "alice", Email: "alice@example.com", EmailVerified: false},
	})
	if err != nil {
		t.Fatalf("SyncDirectorySnapshot unverified: %v", err)
	}
	if unverified.EmailVerified {
		t.Fatalf("unverified.EmailVerified=true, want false")
	}
	loaded2, err := store.GetPrincipal(ctx, principal.ID)
	if err != nil {
		t.Fatalf("GetPrincipal after unverified: %v", err)
	}
	if loaded2.EmailVerified {
		t.Fatalf("loaded2.EmailVerified=true, want false (Casdoor is source of truth)")
	}
}

func TestIdentityContextExposesEmailVerified(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	seedPrincipal(t, ctx, store, Principal{
		ID: "user-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RoleFrontendUser}}, EmailVerified: true,
	})
	session, err := svc.CreateSession(ctx, "user-a", testNow())
	if err != nil {
		t.Fatal(err)
	}
	identity, err := svc.IdentityContext(ctx, session.ID, testNow())
	if err != nil {
		t.Fatalf("IdentityContext: %v", err)
	}
	if !identity.EmailVerified {
		t.Fatalf("identity.EmailVerified=false, want true")
	}
}

func TestSyncDirectorySnapshotMapsLegacyRoles(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestService(t)
	principal, err := svc.SyncDirectorySnapshot(ctx, CasdoorDirectorySnapshot{
		Tenant: Tenant{ID: "tenant-a", Slug: "acme", DisplayName: "Acme"},
		User:   CasdoorUser{ID: "user-a", Username: "alice"},
		Roles:  []string{"user", "moderator"},
	})
	if err != nil {
		t.Fatalf("SyncDirectorySnapshot: %v", err)
	}
	keys := roleKeys(principal.Roles)
	if !has(keys, RoleFrontendUser) {
		t.Fatalf("legacy 'user' not mapped to frontend.user: %+v", principal.Roles)
	}
	if !has(keys, RoleSkillHubPublisher) {
		t.Fatalf("legacy 'moderator' not mapped to app.skillhub.publisher: %+v", principal.Roles)
	}
}

func TestSyncDirectorySnapshotAuditsUnknownRoles(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	if _, err := svc.SyncDirectorySnapshot(ctx, CasdoorDirectorySnapshot{
		Tenant: Tenant{ID: "tenant-a", Slug: "acme", DisplayName: "Acme"},
		User:   CasdoorUser{ID: "user-a", Username: "alice"},
		Roles:  []string{"frontend.user", "totally.unknown.role", "another.unknown"},
	}); err != nil {
		t.Fatalf("SyncDirectorySnapshot: %v", err)
	}
	events := store.AuditEvents()
	var unknownCount int
	for _, event := range events {
		if event.Action == "directory.unknown_role" && event.Decision == "deny" {
			unknownCount++
		}
	}
	if unknownCount != 2 {
		t.Fatalf("unknown role audit events = %d, want 2", unknownCount)
	}
}

func TestSyncDirectorySnapshotNotifiesUnknownRoles(t *testing.T) {
	ctx := context.Background()
	notifier := &captureSecurityNotifier{notify: make(chan struct{}, 4)}
	svc, store := newTestServiceWithNotifier(t, notifier)
	seedPrincipal(t, ctx, store, Principal{
		ID: "admin-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RolePlatformAdmin}},
	})
	if _, err := svc.SyncDirectorySnapshot(ctx, CasdoorDirectorySnapshot{
		Tenant: Tenant{ID: "tenant-a", Slug: "acme", DisplayName: "Acme"},
		User:   CasdoorUser{ID: "user-a", Username: "alice"},
		Roles:  []string{"frontend.user", "totally.unknown.role", "another.unknown"},
	}); err != nil {
		t.Fatalf("SyncDirectorySnapshot: %v", err)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-notifier.notify:
		case <-time.After(time.Second):
			t.Fatalf("notifier call %d missing", i+1)
		}
	}
	if len(notifier.Events()) != 2 {
		t.Fatalf("events=%d want 2", len(notifier.Events()))
	}
	for _, ev := range notifier.Events() {
		if ev.Type != "directory.unknown_role" {
			t.Fatalf("type=%q want directory.unknown_role", ev.Type)
		}
		if ev.TenantID != "tenant-a" {
			t.Fatalf("tenant_id=%q want tenant-a", ev.TenantID)
		}
		if ev.Severity != "warning" {
			t.Fatalf("severity=%q want warning", ev.Severity)
		}
	}
}

func newTestServiceWithNotifier(t *testing.T, notifier SecurityNotifier) (*Service, *MemoryStore) {
	t.Helper()
	store := NewMemoryStore()
	svc, err := NewService(Config{
		Issuer:           "warden",
		MasterSecret:     testSecret,
		InternalTTL:      time.Minute,
		SecurityNotifier: notifier,
	}, store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, store
}
