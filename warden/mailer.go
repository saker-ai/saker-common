package warden

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

type Email struct {
	To      string
	Subject string
	Body    string
}

type Mailer interface {
	Send(ctx context.Context, msg Email) error
}

type NoopMailer struct{}

func (NoopMailer) Send(context.Context, Email) error { return nil }

type LoggingMailer struct {
	Logger *slog.Logger
}

func (m LoggingMailer) Send(_ context.Context, msg Email) error {
	if m.Logger != nil {
		m.Logger.Info("warden email sent", "to", maskEmail(msg.To), "subject", msg.Subject)
	}
	return nil
}

func maskEmail(addr string) string {
	at := strings.Index(addr, "@")
	if at <= 0 || at == len(addr)-1 {
		return addr
	}
	local := addr[:at]
	domain := addr[at:]
	if len(local) <= 2 {
		return fmt.Sprintf("%s%s", local[0:1]+"***", domain)
	}
	return fmt.Sprintf("%s%s", string(local[0])+"***"+string(local[len(local)-1]), domain)
}
