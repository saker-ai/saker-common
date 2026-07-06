package warden

import (
	"errors"
	"fmt"
	"strings"
)

type EmailTemplate struct {
	Subject string
	Body    string
}

type TemplateRegistry struct {
	templates map[string]EmailTemplate
}

func NewTemplateRegistry() *TemplateRegistry {
	return &TemplateRegistry{templates: map[string]EmailTemplate{}}
}

func DefaultTemplateRegistry() *TemplateRegistry {
	r := NewTemplateRegistry()
	r.Register("principal.approved", EmailTemplate{
		Subject: "Your Saker account has been approved",
		Body: "Hello {{DisplayName}},\n\n" +
			"Your account registration has been approved.\n" +
			"You may now sign in to the platform or contact your administrator.\n\n" +
			"— Saker Warden",
	})
	r.Register("principal.rejected", EmailTemplate{
		Subject: "Your Saker account registration was rejected",
		Body: "Hello {{DisplayName}},\n\n" +
			"Your account registration has been rejected.\n" +
			"If you believe this is a mistake, please contact your administrator.\n\n" +
			"— Saker Warden",
	})
	r.Register("invitation.created", EmailTemplate{
		Subject: "You are invited to join Saker",
		Body: "Hello,\n\n" +
			"You have been invited to join tenant {{TenantID}} on Saker.\n" +
			"Accept your invitation by visiting:\n" +
			"{{AcceptURL}}\n\n" +
			"This invitation expires at {{ExpiresAt}}.\n\n" +
			"— Saker Warden",
	})
	return r
}

func (r *TemplateRegistry) Register(name string, t EmailTemplate) {
	if r == nil || name == "" {
		return
	}
	r.templates[name] = t
}

func (r *TemplateRegistry) Lookup(name string) (EmailTemplate, bool) {
	if r == nil {
		return EmailTemplate{}, false
	}
	t, ok := r.templates[name]
	return t, ok
}

func (r *TemplateRegistry) Render(name string, data map[string]string) (Email, error) {
	if r == nil {
		return Email{}, errors.New("template registry is nil")
	}
	t, ok := r.templates[name]
	if !ok {
		return Email{}, fmt.Errorf("unknown email template %q", name)
	}
	return Email{
		Subject: renderTemplateString(t.Subject, data),
		Body:    renderTemplateString(t.Body, data),
	}, nil
}

func renderTemplateString(s string, data map[string]string) string {
	if data == nil {
		return s
	}
	for key, value := range data {
		s = strings.ReplaceAll(s, "{{"+key+"}}", value)
	}
	return s
}
