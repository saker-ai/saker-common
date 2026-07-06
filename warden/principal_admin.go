package warden

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/saker-ai/saker-common/internaljwt"
)

func (s *Service) DisablePrincipal(ctx context.Context, sessionID, principalID string, now time.Time) (Principal, error) {
	actor, err := s.requirePrincipalAdmin(ctx, sessionID, now)
	if err != nil {
		return Principal{}, err
	}
	if strings.TrimSpace(principalID) == "" {
		return Principal{}, ErrInvalidInput
	}
	if err := s.store.UpdatePrincipalStatus(ctx, principalID, PrincipalStatusDisabled); err != nil {
		if errors.Is(err, ErrNotFound) {
			return Principal{}, ErrNotFound
		}
		return Principal{}, err
	}
	if err := s.store.DeleteSessionsByPrincipal(ctx, principalID); err != nil {
		return Principal{}, err
	}
	updated, err := s.store.GetPrincipal(ctx, principalID)
	if err != nil {
		return Principal{}, err
	}
	s.audit(ctx, actor, "principal.disable", &internaljwt.ResourceRef{Type: "principal", ID: principalID}, "allow", "")
	s.notifySecurity(ctx, SecurityEvent{
		Type:        "principal.disable",
		TenantID:    actor.TenantID,
		PrincipalID: principalID,
		SourceApp:   "warden",
		Title:       securityTitleFor("principal.disable", principalID),
		Body:        securityBodyFor("principal.disable", principalID, ""),
	})
	return updated, nil
}

func (s *Service) EnablePrincipal(ctx context.Context, sessionID, principalID string, now time.Time) (Principal, error) {
	actor, err := s.requirePrincipalAdmin(ctx, sessionID, now)
	if err != nil {
		return Principal{}, err
	}
	if strings.TrimSpace(principalID) == "" {
		return Principal{}, ErrInvalidInput
	}
	if err := s.store.UpdatePrincipalStatus(ctx, principalID, PrincipalStatusActive); err != nil {
		if errors.Is(err, ErrNotFound) {
			return Principal{}, ErrNotFound
		}
		return Principal{}, err
	}
	updated, err := s.store.GetPrincipal(ctx, principalID)
	if err != nil {
		return Principal{}, err
	}
	s.audit(ctx, actor, "principal.enable", &internaljwt.ResourceRef{Type: "principal", ID: principalID}, "allow", "")
	return updated, nil
}

func (s *Service) ApprovePrincipal(ctx context.Context, sessionID, principalID string, now time.Time) (Principal, error) {
	actor, err := s.requirePrincipalAdmin(ctx, sessionID, now)
	if err != nil {
		return Principal{}, err
	}
	if strings.TrimSpace(principalID) == "" {
		return Principal{}, ErrInvalidInput
	}
	current, err := s.store.GetPrincipal(ctx, principalID)
	if err != nil {
		return Principal{}, err
	}
	if current.Status != PrincipalStatusPending {
		return Principal{}, ErrForbidden
	}
	if err := s.store.UpdatePrincipalStatus(ctx, principalID, PrincipalStatusActive); err != nil {
		return Principal{}, err
	}
	updated, err := s.store.GetPrincipal(ctx, principalID)
	if err != nil {
		return Principal{}, err
	}
	s.audit(ctx, actor, "principal.approve", &internaljwt.ResourceRef{Type: "principal", ID: principalID}, "allow", "")
	s.notifyPrincipalDecision(updated, "approved")
	s.notifySecurity(ctx, SecurityEvent{
		Type:        "principal.approve",
		TenantID:    actor.TenantID,
		PrincipalID: principalID,
		SourceApp:   "warden",
		Title:       securityTitleFor("principal.approve", principalID),
		Body:        securityBodyFor("principal.approve", principalID, ""),
	})
	return updated, nil
}

func (s *Service) RejectPrincipal(ctx context.Context, sessionID, principalID string, now time.Time) (Principal, error) {
	actor, err := s.requirePrincipalAdmin(ctx, sessionID, now)
	if err != nil {
		return Principal{}, err
	}
	if strings.TrimSpace(principalID) == "" {
		return Principal{}, ErrInvalidInput
	}
	current, err := s.store.GetPrincipal(ctx, principalID)
	if err != nil {
		return Principal{}, err
	}
	if current.Status != PrincipalStatusPending {
		return Principal{}, ErrForbidden
	}
	if err := s.store.UpdatePrincipalStatus(ctx, principalID, PrincipalStatusDisabled); err != nil {
		return Principal{}, err
	}
	if err := s.store.DeleteSessionsByPrincipal(ctx, principalID); err != nil {
		return Principal{}, err
	}
	updated, err := s.store.GetPrincipal(ctx, principalID)
	if err != nil {
		return Principal{}, err
	}
	s.audit(ctx, actor, "principal.reject", &internaljwt.ResourceRef{Type: "principal", ID: principalID}, "allow", "")
	s.notifyPrincipalDecision(updated, "rejected")
	s.notifySecurity(ctx, SecurityEvent{
		Type:        "principal.reject",
		TenantID:    actor.TenantID,
		PrincipalID: principalID,
		SourceApp:   "warden",
		Title:       securityTitleFor("principal.reject", principalID),
		Body:        securityBodyFor("principal.reject", principalID, ""),
	})
	return updated, nil
}

func (s *Service) notifyPrincipalDecision(principal Principal, decision string) {
	email := strings.TrimSpace(principal.Email)
	if email == "" || s.mailer == nil {
		return
	}
	templateName := "principal." + decision
	msg, err := s.templates.Render(templateName, map[string]string{
		"DisplayName": defaultDisplayName(principal),
	})
	if err != nil {
		return
	}
	msg.To = email
	go func() {
		_ = s.mailer.Send(context.Background(), msg)
	}()
}

func defaultDisplayName(p Principal) string {
	if strings.TrimSpace(p.DisplayName) != "" {
		return p.DisplayName
	}
	if strings.TrimSpace(p.Username) != "" {
		return p.Username
	}
	return p.ID
}

func (s *Service) requirePrincipalAdmin(ctx context.Context, sessionID string, now time.Time) (Principal, error) {
	_, principal, err := s.ValidateSession(ctx, sessionID, now)
	if err != nil {
		return Principal{}, err
	}
	if !canManageServiceAccounts(principal.Roles) {
		return Principal{}, ErrForbidden
	}
	return principal, nil
}
