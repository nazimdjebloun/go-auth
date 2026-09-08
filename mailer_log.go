package goauth

import (
	"context"
	"log/slog"
)

// LogMailer is a dev-only port.Mailer that writes emails to a logger instead
// of sending them. NewConfig rejects it outside EnvironmentDev — see
// config.validate().
type LogMailer struct {
	log *slog.Logger
}

// NewLogMailer builds a *LogMailer. If logger is nil, slog.Default() is used.
func NewLogMailer(logger *slog.Logger) *LogMailer {
	if logger == nil {
		logger = slog.Default()
	}
	return &LogMailer{log: logger}
}

func (m *LogMailer) Send(ctx context.Context, to, subject, html, text string) error {
	m.log.Info("mail (log driver — not delivered)", "to", to, "subject", subject, "text", text)
	return nil
}
