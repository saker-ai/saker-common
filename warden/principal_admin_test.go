package warden

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestServiceDisablePrincipalRevokesSessions(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	seedPrincipal(t, ctx, store, Principal{
		ID: "admin-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RolePlatformAdmin}},
	})
	seedPrincipal(t, ctx, store, Principal{
		ID: "user-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RoleFrontendUser}},
	})
	adminSession, err := svc.CreateSession(ctx, "admin-a", testNow())
	if err != nil {
		t.Fatal(err)
	}
	userSession, err := svc.CreateSession(ctx, "user-a", testNow())
	if err != nil {
		t.Fatal(err)
	}

	updated, err := svc.DisablePrincipal(ctx, adminSession.ID, "user-a", testNow())
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if updated.Status != PrincipalStatusDisabled {
		t.Fatalf("status=%s want %s", updated.Status, PrincipalStatusDisabled)
	}

	if _, _, err := svc.ValidateSession(ctx, userSession.ID, testNow()); err == nil {
		t.Fatal("user session should be revoked after disable")
	}
}

func TestServiceEnablePrincipalRestoresLogin(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	seedPrincipal(t, ctx, store, Principal{
		ID: "admin-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RolePlatformAdmin}},
	})
	seedPrincipal(t, ctx, store, Principal{
		ID: "user-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusDisabled,
		Roles: []RoleGrant{{Key: RoleFrontendUser}},
	})
	adminSession, err := svc.CreateSession(ctx, "admin-a", testNow())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.CreateSession(ctx, "user-a", testNow()); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled login err=%v want ErrDisabled", err)
	}

	updated, err := svc.EnablePrincipal(ctx, adminSession.ID, "user-a", testNow())
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if updated.Status != PrincipalStatusActive {
		t.Fatalf("status=%s want %s", updated.Status, PrincipalStatusActive)
	}

	if _, err := svc.CreateSession(ctx, "user-a", testNow()); err != nil {
		t.Fatalf("login after enable: %v", err)
	}
}

func TestServiceApprovePrincipalActivatesPending(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	seedPrincipal(t, ctx, store, Principal{
		ID: "admin-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RolePlatformAdmin}},
	})
	seedPrincipal(t, ctx, store, Principal{
		ID: "pending-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusPending,
		Roles: []RoleGrant{{Key: RoleFrontendUser}},
	})
	adminSession, err := svc.CreateSession(ctx, "admin-a", testNow())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.CreateSession(ctx, "pending-a", testNow()); !errors.Is(err, ErrAuthorizationPending) {
		t.Fatalf("pending login err=%v want ErrAuthorizationPending", err)
	}

	updated, err := svc.ApprovePrincipal(ctx, adminSession.ID, "pending-a", testNow())
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if updated.Status != PrincipalStatusActive {
		t.Fatalf("status=%s want %s", updated.Status, PrincipalStatusActive)
	}
	if _, err := svc.CreateSession(ctx, "pending-a", testNow()); err != nil {
		t.Fatalf("login after approve: %v", err)
	}
}

func TestServiceApprovePrincipalRejectsNonPending(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	seedPrincipal(t, ctx, store, Principal{
		ID: "admin-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RolePlatformAdmin}},
	})
	seedPrincipal(t, ctx, store, Principal{
		ID: "user-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RoleFrontendUser}},
	})
	adminSession, err := svc.CreateSession(ctx, "admin-a", testNow())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.ApprovePrincipal(ctx, adminSession.ID, "user-a", testNow()); !errors.Is(err, ErrForbidden) {
		t.Fatalf("approve active err=%v want ErrForbidden", err)
	}
}

func TestServiceRejectPrincipalDisablesPending(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	seedPrincipal(t, ctx, store, Principal{
		ID: "admin-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RolePlatformAdmin}},
	})
	seedPrincipal(t, ctx, store, Principal{
		ID: "pending-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusPending,
		Roles: []RoleGrant{{Key: RoleFrontendUser}},
	})
	adminSession, err := svc.CreateSession(ctx, "admin-a", testNow())
	if err != nil {
		t.Fatal(err)
	}

	updated, err := svc.RejectPrincipal(ctx, adminSession.ID, "pending-a", testNow())
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if updated.Status != PrincipalStatusDisabled {
		t.Fatalf("status=%s want %s", updated.Status, PrincipalStatusDisabled)
	}
}

func TestServicePrincipalAdminRequiresAdminRole(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	seedPrincipal(t, ctx, store, Principal{
		ID: "user-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RoleFrontendUser}},
	})
	seedPrincipal(t, ctx, store, Principal{
		ID: "user-b", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RoleFrontendUser}},
	})
	userSession, err := svc.CreateSession(ctx, "user-a", testNow())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.DisablePrincipal(ctx, userSession.ID, "user-b", testNow()); !errors.Is(err, ErrForbidden) {
		t.Fatalf("non-admin disable err=%v want ErrForbidden", err)
	}
}

func TestServiceDisablePrincipalNotFound(t *testing.T) {
	ctx := context.Background()
	svc, store := newTestService(t)
	seedPrincipal(t, ctx, store, Principal{
		ID: "admin-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RolePlatformAdmin}},
	})
	adminSession, err := svc.CreateSession(ctx, "admin-a", testNow())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.DisablePrincipal(ctx, adminSession.ID, "missing-id", testNow()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("disable missing err=%v want ErrNotFound", err)
	}
}

type captureMailer struct {
	emails []Email
	notify chan struct{}
}

func (m *captureMailer) Send(_ context.Context, msg Email) error {
	m.emails = append(m.emails, msg)
	if m.notify != nil {
		m.notify <- struct{}{}
	}
	return nil
}

func newServiceWithMailer(t *testing.T, mailer Mailer) (*Service, *MemoryStore) {
	t.Helper()
	store := NewMemoryStore()
	svc, err := NewService(Config{
		Issuer:       "warden",
		MasterSecret: testSecret,
		InternalTTL:  5 * time.Minute,
		Mailer:       mailer,
	}, store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, store
}

func TestServiceApprovePrincipalSendsEmail(t *testing.T) {
	ctx := context.Background()
	mailer := &captureMailer{notify: make(chan struct{}, 4)}
	svc, store := newServiceWithMailer(t, mailer)
	seedPrincipal(t, ctx, store, Principal{
		ID: "admin-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RolePlatformAdmin}},
	})
	seedPrincipal(t, ctx, store, Principal{
		ID: "pending-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusPending,
		Email: "pending@example.com", DisplayName: "Pending User",
		Roles: []RoleGrant{{Key: RoleFrontendUser}},
	})
	adminSession, err := svc.CreateSession(ctx, "admin-a", testNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApprovePrincipal(ctx, adminSession.ID, "pending-a", testNow()); err != nil {
		t.Fatalf("approve: %v", err)
	}
	select {
	case <-mailer.notify:
	case <-time.After(time.Second):
		t.Fatal("approve email not sent")
	}
	if len(mailer.emails) != 1 {
		t.Fatalf("emails=%d want 1", len(mailer.emails))
	}
	got := mailer.emails[0]
	if got.To != "pending@example.com" {
		t.Fatalf("to=%s", got.To)
	}
	if !strings.Contains(got.Subject, "approved") {
		t.Fatalf("subject=%s", got.Subject)
	}
	if !strings.Contains(got.Body, "Pending User") {
		t.Fatalf("body=%s", got.Body)
	}
}

func TestServiceRejectPrincipalSendsEmail(t *testing.T) {
	ctx := context.Background()
	mailer := &captureMailer{notify: make(chan struct{}, 4)}
	svc, store := newServiceWithMailer(t, mailer)
	seedPrincipal(t, ctx, store, Principal{
		ID: "admin-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RolePlatformAdmin}},
	})
	seedPrincipal(t, ctx, store, Principal{
		ID: "pending-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusPending,
		Email: "pending@example.com", DisplayName: "Pending User",
		Roles: []RoleGrant{{Key: RoleFrontendUser}},
	})
	adminSession, err := svc.CreateSession(ctx, "admin-a", testNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RejectPrincipal(ctx, adminSession.ID, "pending-a", testNow()); err != nil {
		t.Fatalf("reject: %v", err)
	}
	select {
	case <-mailer.notify:
	case <-time.After(time.Second):
		t.Fatal("reject email not sent")
	}
	if len(mailer.emails) != 1 {
		t.Fatalf("emails=%d want 1", len(mailer.emails))
	}
	got := mailer.emails[0]
	if !strings.Contains(got.Subject, "rejected") {
		t.Fatalf("subject=%s", got.Subject)
	}
}

func TestServiceNoEmailWhenNoAddress(t *testing.T) {
	ctx := context.Background()
	mailer := &captureMailer{}
	svc, store := newServiceWithMailer(t, mailer)
	seedPrincipal(t, ctx, store, Principal{
		ID: "admin-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RolePlatformAdmin}},
	})
	seedPrincipal(t, ctx, store, Principal{
		ID: "pending-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusPending,
		Roles: []RoleGrant{{Key: RoleFrontendUser}},
	})
	adminSession, err := svc.CreateSession(ctx, "admin-a", testNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApprovePrincipal(ctx, adminSession.ID, "pending-a", testNow()); err != nil {
		t.Fatalf("approve: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if len(mailer.emails) != 0 {
		t.Fatalf("emails=%d want 0 when no email address", len(mailer.emails))
	}
}

type captureSecurityNotifier struct {
	mu     sync.Mutex
	events []SecurityEvent
	notify chan struct{}
}

func (n *captureSecurityNotifier) NotifySecurity(_ context.Context, event SecurityEvent) error {
	n.mu.Lock()
	n.events = append(n.events, event)
	n.mu.Unlock()
	if n.notify != nil {
		n.notify <- struct{}{}
	}
	return nil
}

func (n *captureSecurityNotifier) Events() []SecurityEvent {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]SecurityEvent, len(n.events))
	copy(out, n.events)
	return out
}

func newServiceWithSecurityNotifier(t *testing.T, notifier SecurityNotifier) (*Service, *MemoryStore) {
	t.Helper()
	store := NewMemoryStore()
	svc, err := NewService(Config{
		Issuer:           "warden",
		MasterSecret:     testSecret,
		InternalTTL:      5 * time.Minute,
		SecurityNotifier: notifier,
	}, store)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, store
}

func TestServiceDisablePrincipalNotifiesSecurity(t *testing.T) {
	ctx := context.Background()
	notifier := &captureSecurityNotifier{notify: make(chan struct{}, 4)}
	svc, store := newServiceWithSecurityNotifier(t, notifier)
	seedPrincipal(t, ctx, store, Principal{
		ID: "admin-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RolePlatformAdmin}},
	})
	seedPrincipal(t, ctx, store, Principal{
		ID: "user-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RoleFrontendUser}},
	})
	adminSession, err := svc.CreateSession(ctx, "admin-a", testNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DisablePrincipal(ctx, adminSession.ID, "user-a", testNow()); err != nil {
		t.Fatalf("disable: %v", err)
	}
	select {
	case <-notifier.notify:
	case <-time.After(time.Second):
		t.Fatal("security notifier not called")
	}
	if len(notifier.Events()) != 1 {
		t.Fatalf("events=%d want 1", len(notifier.Events()))
	}
	ev := notifier.Events()[0]
	if ev.Type != "principal.disable" {
		t.Fatalf("type=%q want principal.disable", ev.Type)
	}
	if ev.PrincipalID != "user-a" {
		t.Fatalf("principal_id=%q want user-a", ev.PrincipalID)
	}
	if ev.TenantID != "tenant-a" {
		t.Fatalf("tenant_id=%q want tenant-a", ev.TenantID)
	}
	if ev.SourceApp != "warden" {
		t.Fatalf("source_app=%q want warden", ev.SourceApp)
	}
	if ev.Severity != "warning" {
		t.Fatalf("severity=%q want warning", ev.Severity)
	}
}

func TestServiceRejectPrincipalNotifiesSecurity(t *testing.T) {
	ctx := context.Background()
	notifier := &captureSecurityNotifier{notify: make(chan struct{}, 4)}
	svc, store := newServiceWithSecurityNotifier(t, notifier)
	seedPrincipal(t, ctx, store, Principal{
		ID: "admin-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusActive,
		Roles: []RoleGrant{{Key: RolePlatformAdmin}},
	})
	seedPrincipal(t, ctx, store, Principal{
		ID: "pending-a", TenantID: "tenant-a", Type: PrincipalTypeUser, Status: PrincipalStatusPending,
		Roles: []RoleGrant{{Key: RoleFrontendUser}},
	})
	adminSession, err := svc.CreateSession(ctx, "admin-a", testNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RejectPrincipal(ctx, adminSession.ID, "pending-a", testNow()); err != nil {
		t.Fatalf("reject: %v", err)
	}
	select {
	case <-notifier.notify:
	case <-time.After(time.Second):
		t.Fatal("security notifier not called")
	}
	ev := notifier.Events()[0]
	if ev.Type != "principal.reject" {
		t.Fatalf("type=%q want principal.reject", ev.Type)
	}
	if ev.PrincipalID != "pending-a" {
		t.Fatalf("principal_id=%q want pending-a", ev.PrincipalID)
	}
}
