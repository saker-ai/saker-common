package warden

import (
	"strings"
	"testing"
)

func TestTemplateRegistryRenderApproved(t *testing.T) {
	r := DefaultTemplateRegistry()
	email, err := r.Render("principal.approved", map[string]string{
		"DisplayName": "Alice",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(email.Body, "Hello Alice,") {
		t.Fatalf("body missing rendered name: %q", email.Body)
	}
	if !strings.Contains(email.Subject, "approved") {
		t.Fatalf("subject=%q", email.Subject)
	}
}

func TestTemplateRegistryRenderRejected(t *testing.T) {
	r := DefaultTemplateRegistry()
	email, err := r.Render("principal.rejected", map[string]string{
		"DisplayName": "Bob",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(email.Body, "Hello Bob,") {
		t.Fatalf("body missing rendered name: %q", email.Body)
	}
	if !strings.Contains(email.Subject, "rejected") {
		t.Fatalf("subject=%q", email.Subject)
	}
}

func TestTemplateRegistryRenderInvitation(t *testing.T) {
	r := DefaultTemplateRegistry()
	email, err := r.Render("invitation.created", map[string]string{
		"TenantID":  "tenant-xyz",
		"AcceptURL": "/auth/invitations/abc123",
		"ExpiresAt": "2026-12-31T23:59:59Z",
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(email.Body, "tenant-xyz") {
		t.Fatalf("body missing TenantID: %q", email.Body)
	}
	if !strings.Contains(email.Body, "/auth/invitations/abc123") {
		t.Fatalf("body missing AcceptURL: %q", email.Body)
	}
	if !strings.Contains(email.Body, "2026-12-31T23:59:59Z") {
		t.Fatalf("body missing ExpiresAt: %q", email.Body)
	}
}

func TestTemplateRegistryUnknown(t *testing.T) {
	r := DefaultTemplateRegistry()
	if _, err := r.Render("does.not.exist", nil); err == nil {
		t.Fatal("want error for unknown template")
	}
}

func TestTemplateRegistryCustom(t *testing.T) {
	r := NewTemplateRegistry()
	r.Register("custom", EmailTemplate{Subject: "S {{Name}}", Body: "B {{Name}}"})
	email, err := r.Render("custom", map[string]string{"Name": "Bob"})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if email.Subject != "S Bob" {
		t.Fatalf("subject=%q", email.Subject)
	}
	if email.Body != "B Bob" {
		t.Fatalf("body=%q", email.Body)
	}
}

func TestTemplateRegistryRenderNoData(t *testing.T) {
	r := DefaultTemplateRegistry()
	email, err := r.Render("principal.rejected", nil)
	if err != nil {
		t.Fatalf("Render nil data: %v", err)
	}
	if !strings.Contains(email.Body, "{{DisplayName}}") {
		t.Fatalf("body should retain placeholder when data nil: %q", email.Body)
	}
}

func TestTemplateRegistryNil(t *testing.T) {
	var r *TemplateRegistry
	if _, err := r.Render("principal.approved", nil); err == nil {
		t.Fatal("want error for nil registry")
	}
}
