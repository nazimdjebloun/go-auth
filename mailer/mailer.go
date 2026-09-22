// Package mailer holds go-auth's port.Mailer implementations: SMTP for real
// delivery, and Log for development.
//
// It sits beside the other port implementations — hasher, token, emailtemplate,
// provider/github, provider/google — rather than in the root package, so that
// every adapter in the library is found the same way.
//
// The root package aliases Config and TLSMode, so goauth.EmailConfig and
// goauth.TLSMode still name these types and WithEmail is unchanged.
package mailer

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/wneessen/go-mail"
)

// TLSMode selects the transport security an SMTP connection negotiates.
type TLSMode int

const (
	TLSStart    TLSMode = iota // STARTTLS, typically port 587 — the zero value, so an unset TLSMode is never plaintext
	TLSImplicit                // implicit TLS, typically port 465
	TLSNone                    // plaintext — dev/local only
)

// Config configures SMTP email delivery (transport only). Aliased in the root
// package as goauth.EmailConfig, which is the name a consumer writes.
type Config struct {
	From string
	Host string
	Port int
	User string
	Pass string
	TLS  TLSMode
}

// SMTP is a port.Mailer that delivers over SMTP.
type SMTP struct {
	cfg Config
}

// NewSMTP builds an *SMTP from the given transport config.
func NewSMTP(cfg Config) (*SMTP, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("goauth: SMTP host is required")
	}
	if cfg.From == "" {
		return nil, fmt.Errorf("goauth: email From address is required")
	}
	return &SMTP{cfg: cfg}, nil
}

func (m *SMTP) Send(ctx context.Context, to, subject, html, text string) error {
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

	tlsOption := mail.WithTLSPolicy(mail.NoTLS)
	switch m.cfg.TLS {
	case TLSStart:
		tlsOption = mail.WithTLSPolicy(mail.TLSMandatory)
	case TLSImplicit:
		tlsOption = mail.WithSSL()
	}

	opts := []mail.Option{
		mail.WithPort(m.cfg.Port),
		tlsOption,
	}
	if m.cfg.User != "" {
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthPlain),
			mail.WithUsername(m.cfg.User),
			mail.WithPassword(m.cfg.Pass),
		)
	}
	client, err := mail.NewClient(m.cfg.Host, opts...)
	if err != nil {
		return fmt.Errorf("goauth: failed to create SMTP client: %w", err)
	}

	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		return fmt.Errorf("goauth: failed to send email: %w", err)
	}
	return nil
}

// Log is a dev-only port.Mailer that writes emails to a logger instead of
// sending them. NewConfig rejects it outside EnvironmentDev — see
// Config.validate() in the root package.
type Log struct {
	log *slog.Logger
}

// NewLog builds a *Log. If logger is nil, slog.Default() is used.
func NewLog(logger *slog.Logger) *Log {
	if logger == nil {
		logger = slog.Default()
	}
	return &Log{log: logger}
}

func (m *Log) Send(_ context.Context, to, subject, _, text string) error {
	m.log.Info("mail (log driver — not delivered)", "to", to, "subject", subject, "text", text)
	return nil
}
