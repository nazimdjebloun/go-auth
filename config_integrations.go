package goauth

import (
	"errors"
	"fmt"
	"net/mail"
	"time"

	"golang.org/x/oauth2"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/mailer"
	"github.com/nazimdjebloun/go-auth/port"
)

// EmailConfig and TLSMode live in the mailer package, beside the SMTP client
// that reads them — the same place every other port implementation keeps its
// own config. They are aliased here because WithEmail takes an EmailConfig,
// so goauth.EmailConfig is the name a consumer writes.
type EmailConfig = mailer.Config

// TLSMode selects the SMTP transport security mode.
type TLSMode = mailer.TLSMode

// TLSStart and the following values select SMTP transport security.
const (
	TLSStart    = mailer.TLSStart
	TLSImplicit = mailer.TLSImplicit
	TLSNone     = mailer.TLSNone
)

// AuditConfig controls audit logging behavior.
type AuditConfig struct {
	Enabled       bool
	FailureMode   audit.FailureMode
	RetentionDays int           // days of audit rows to retain; 0 = keep forever
	QueueSize     int           // Deprecated: the in-memory queue is gone; the outbox is the queue. Ignored.
	Workers       int           // dispatcher workers, default 3
	BatchSize     int           // dispatch batch size, default 50
	FlushInterval time.Duration // dispatch poll interval, default 100ms
	Sinks         []audit.EventSink

	// EnqueueFailureMode resolves the enqueue failure mode per event.
	// Nil = fail-open for every event (the default): a failed durable write
	// never takes authentication down. See audit.Record.
	EnqueueFailureMode audit.EnqueueFailureModeResolver

	// Outbox delivery tuning. Defaults in audit.defaultConfig.
	MaxAttempts   int           // attempts before dead-lettering (default 10)
	ClaimLease    time.Duration // claim lease; must exceed each sink's declared max batch time (default 10m)
	OutboxMaxAge  time.Duration // pending-row age bound (default 7d)
	DeadLetterTTL time.Duration // dead-letter evidence window (default 7d)
	OutboxMaxRows int           // emergency backlog valve (default 100000)
}

func (c *Config) applyMailerDefaults() {
	// In dev, an unconfigured mailer defaults to the log driver instead of
	// silently no-oping every send — but only when neither WithMailer nor
	// WithEmail was called; an explicit choice is never overridden.
	if c.mailer == nil && c.email == nil && c.app.Environment.normalize() == EnvironmentDev {
		c.mailer = mailer.NewLog(c.logger)
	}
}

// WithEmail configures SMTP email delivery (transport only).
func WithEmail(cfg EmailConfig) Option {
	return func(c *Config) {
		c.email = &cfg
	}
}

// WithMailer provides a custom mailer implementation.
func WithMailer(m port.Mailer) Option {
	return func(c *Config) {
		c.mailer = m
	}
}

// WithTemplates provides a custom email template provider.
// When set, the provider's Render method is called for every email instead of
// the built-in default templates.
func WithTemplates(p port.TemplateProvider) Option {
	return func(c *Config) {
		c.templates = p
	}
}

// WithProvider registers an OAuth provider.
// The provider's Name() must be non-empty and unique across all registered providers.
// Nil providers are rejected.
func WithProvider(p port.OAuthProvider) Option {
	return func(c *Config) {
		c.providers = append(c.providers, p)
	}
}

// WithAudit configures audit logging. Sinks listed in cfg are registered once
// regardless of how many times this option is applied; appending them here
// instead would duplicate every sink — and so every audit event — on a repeat
// call. New() reads cfg.Sinks and the WithAuditSink list together.
func WithAudit(cfg AuditConfig) Option {
	return func(c *Config) {
		c.audit = cfg
	}
}

// WithAuditSink adds a custom audit event sink (e.g. Kafka, NATS, webhook).
// Only takes effect when audit is enabled via WithAudit.
func WithAuditSink(sink audit.EventSink) Option {
	return func(c *Config) {
		c.auditSinks = append(c.auditSinks, sink)
	}
}

func (c *Config) validateMailer() []error {
	var errs []error
	// SMTP fields only matter when go-auth builds the mailer itself; a custom
	// Mailer owns its own transport config.
	if c.email != nil && c.mailer == nil {
		e := c.email
		if e.Host == "" {
			errs = append(errs, errors.New("email: host is required"))
		}
		if e.Port <= 0 || e.Port > 65535 {
			errs = append(errs, fmt.Errorf("email: port must be between 1 and 65535, got %d", e.Port))
		}
		if e.From == "" {
			errs = append(errs, errors.New("email: from address is required"))
		} else if _, err := mail.ParseAddress(e.From); err != nil {
			errs = append(errs, fmt.Errorf("email: from address %q is not valid: %w", e.From, err))
		}
		if (e.User == "") != (e.Pass == "") {
			errs = append(errs, errors.New("email: user and pass must both be set or both be empty"))
		}
		if e.TLS < TLSStart || e.TLS > TLSNone {
			errs = append(
				errs,
				fmt.Errorf("email: tls mode must be one of TLSNone, TLSStart, or TLSImplicit, got %d", e.TLS),
			)
		}
		if e.TLS == TLSNone && c.app.Environment.normalize() != EnvironmentDev {
			errs = append(errs, errors.New("email: TLSNone is only allowed in EnvironmentDev — use TLSStart or TLSImplicit outside development"))
		}
	}
	return errs
}

func (c *Config) validateProviders() []error {
	var errs []error
	seen := map[string]bool{}
	for _, p := range c.providers {
		if p == nil {
			errs = append(errs, errors.New("provider: nil provider registered via WithProvider"))
			continue
		}
		name := p.Name()
		if name == "" {
			errs = append(errs, errors.New("provider: provider with empty name"))
			continue
		}
		if seen[name] {
			errs = append(errs, fmt.Errorf("provider: duplicate provider %q", name))
		}
		seen[name] = true
		if cfg, ok := p.(interface{ OAuth2Config() *oauth2.Config }); ok {
			c := cfg.OAuth2Config()
			if c.ClientID == "" {
				errs = append(errs, fmt.Errorf("provider %q: client_id is required", name))
			}
			if c.ClientSecret == "" {
				errs = append(errs, fmt.Errorf("provider %q: client_secret is required", name))
			}
		}
	}
	return errs
}

// mailerReasons lists which enabled features require a Mailer or Email
// config, by the exported field name a consumer would recognize. Empty means
// no configured feature sends email, so the mailer is genuinely optional.
func (c *Config) mailerReasons() []string {
	var reasons []string
	if c.registration.EnableInvite {
		reasons = append(reasons, "EnableInvite")
	}
	if c.registration.RequireEmailVerification {
		reasons = append(reasons, "RequireEmailVerification")
	}
	if c.twoFactor.RequireEmail2FA {
		reasons = append(reasons, "RequireEmail2FA")
	}
	if c.twoFactor.DefaultEnabled {
		reasons = append(reasons, "DefaultEnabled")
	}
	if !c.twoFactor.DisableAdminTwoFactor {
		reasons = append(reasons, "AdminLogin two-factor (set DisableAdminTwoFactor to opt out)")
	}
	return reasons
}
