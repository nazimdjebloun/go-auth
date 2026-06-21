package goauth

import (
	"context"
	"fmt"

	"github.com/wneessen/go-mail"
)

type SMTPMailer struct {
	cfg EmailConfig
}

func newSMTPMailer(cfg EmailConfig) (*SMTPMailer, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("goauth: SMTP host is required")
	}
	if cfg.From == "" {
		return nil, fmt.Errorf("goauth: email From address is required")
	}
	return &SMTPMailer{cfg: cfg}, nil
}

func (m *SMTPMailer) Send(ctx context.Context, to, subject, html, text string) error {
	msg := mail.NewMsg()
	if err := msg.From(m.cfg.From); err != nil {
		return fmt.Errorf("goauth: invalid From address: %w", err)
	}
	if err := msg.To(to); err != nil {
		return fmt.Errorf("goauth: invalid To address: %w", err)
	}
	msg.Subject(subject)
	msg.SetBodyString(mail.TypeTextHTML, html)
	msg.AddAlternativeString(mail.TypeTextPlain, text)

	client, err := mail.NewClient(
		m.cfg.Host,
		mail.WithPort(m.cfg.Port),
		mail.WithUsername(m.cfg.User),
		mail.WithPassword(m.cfg.Pass),
		mail.WithTLSPolicy(mail.TLSOpportunistic),
		mail.WithSMTPAuth(mail.SMTPAuthPlain),
	)
	if err != nil {
		return fmt.Errorf("goauth: failed to create SMTP client: %w", err)
	}

	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		return fmt.Errorf("goauth: failed to send email: %w", err)
	}
	return nil
}
