package warden

import (
	"context"
	"log/slog"
	"strings"
	"time"
)

type SecurityEvent struct {
	Type        string
	TenantID    string
	PrincipalID string
	SourceApp   string
	Severity    string
	Title       string
	Body        string
	Href        string
	CreatedAt   time.Time
}

type SecurityNotifier interface {
	NotifySecurity(ctx context.Context, event SecurityEvent) error
}

type NoopSecurityNotifier struct{}

func (NoopSecurityNotifier) NotifySecurity(context.Context, SecurityEvent) error { return nil }

type LoggingSecurityNotifier struct {
	Logger *slog.Logger
}

func (n LoggingSecurityNotifier) NotifySecurity(_ context.Context, event SecurityEvent) error {
	if n.Logger != nil {
		n.Logger.Info("warden security event",
			"type", event.Type,
			"tenant_id", event.TenantID,
			"principal_id", event.PrincipalID,
			"severity", event.Severity,
			"title", event.Title,
		)
	}
	return nil
}

func securitySeverityFor(action string) string {
	switch action {
	case "principal.disable", "principal.reject", "directory.unknown_role":
		return "warning"
	case "principal.enable", "principal.approve":
		return "info"
	default:
		return "info"
	}
}

func securityTitleFor(action, principalID string) string {
	switch action {
	case "principal.disable":
		return "Principal disabled"
	case "principal.enable":
		return "Principal enabled"
	case "principal.approve":
		return "Principal approved"
	case "principal.reject":
		return "Principal rejected"
	case "directory.unknown_role":
		return "Unknown directory role detected"
	default:
		return "Security event: " + action
	}
}

func securityBodyFor(action, principalID, extra string) string {
	switch action {
	case "principal.disable":
		return "Principal " + principalID + " has been disabled. Active sessions were revoked."
	case "principal.enable":
		return "Principal " + principalID + " has been re-enabled."
	case "principal.approve":
		return "Pending principal " + principalID + " has been approved and can now sign in."
	case "principal.reject":
		return "Pending principal " + principalID + " has been rejected. Sessions were revoked."
	case "directory.unknown_role":
		if strings.TrimSpace(extra) == "" {
			return "Directory sync encountered an unknown role for principal " + principalID + "."
		}
		return "Directory sync encountered unknown role \"" + extra + "\" for principal " + principalID + ". No permissions were granted."
	default:
		return "Security event recorded for principal " + principalID + "."
	}
}

func (s *Service) notifySecurity(ctx context.Context, event SecurityEvent) {
	if s.securityNotifier == nil {
		return
	}
	if strings.TrimSpace(event.Type) == "" {
		return
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	if strings.TrimSpace(event.Severity) == "" {
		event.Severity = securitySeverityFor(event.Type)
	}
	go func() {
		_ = s.securityNotifier.NotifySecurity(context.Background(), event)
	}()
}
