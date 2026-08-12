package goauth

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/port"
)

func TestLogMailer_Send(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	m := NewLogMailer(logger)

	if err := m.Send(context.Background(), "user@example.com", "subject line", "<p>html</p>", "text body"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"user@example.com", "subject line", "text body"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected log output to contain %q, got: %s", want, out)
		}
	}
	if strings.Contains(out, "<p>html</p>") {
		t.Errorf("expected log output to omit html body, got: %s", out)
	}
}

func TestLogMailer_NilLoggerDefaultsToSlogDefault(t *testing.T) {
	m := NewLogMailer(nil)
	if m.log == nil {
		t.Fatal("expected default logger to be set")
	}
}

func TestNewConfig_LogMailerRejectedOutsideDev(t *testing.T) {
	opts := append(validConfigOpts(), func(c *config) {
		c.mailer = NewLogMailer(nil)
		c.environment = EnvironmentStaging
	})
	_, err := NewConfig(opts...)
	if err == nil {
		t.Fatal("expected error when LogMailer is used outside EnvironmentDev")
	}
	if !strings.Contains(err.Error(), "LogMailer cannot be used outside EnvironmentDev") {
		t.Fatalf("expected LogMailer env error, got: %v", err)
	}
}

func TestNewConfig_LogMailerRejectedInProd(t *testing.T) {
	opts := append(validConfigOpts(), func(c *config) {
		c.mailer = NewLogMailer(nil)
		c.environment = EnvironmentProd
	})
	_, err := NewConfig(opts...)
	if err == nil {
		t.Fatal("expected error when LogMailer is used in EnvironmentProd")
	}
}

func TestNewConfig_LogMailerAllowedInDev(t *testing.T) {
	opts := append(validConfigOpts(), func(c *config) {
		c.mailer = NewLogMailer(nil)
		c.environment = EnvironmentDev
	})
	_, err := NewConfig(opts...)
	if err != nil {
		t.Fatalf("unexpected error when LogMailer is used in EnvironmentDev: %v", err)
	}
}

func TestNewConfig_DevDefaultsToLogMailerWhenUnconfigured(t *testing.T) {
	opts := append(validConfigOpts(), func(c *config) {
		c.environment = EnvironmentDev
	})
	cfg, err := NewConfig(opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := cfg.mailer.(*LogMailer); !ok {
		t.Fatalf("expected mailer to default to *LogMailer in dev, got %T", cfg.mailer)
	}
}

func TestNewConfig_DevDefaultDoesNotOverrideExplicitMailer(t *testing.T) {
	custom := &mockMailer{}
	opts := append(validConfigOpts(), func(c *config) {
		c.environment = EnvironmentDev
		c.mailer = custom
	})
	cfg, err := NewConfig(opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.mailer != port.Mailer(custom) {
		t.Fatalf("expected explicit mailer to be preserved, got %T", cfg.mailer)
	}
}

func TestNewConfig_DevDefaultDoesNotOverrideExplicitEmail(t *testing.T) {
	opts := append(validConfigOpts(), func(c *config) {
		c.environment = EnvironmentDev
		c.email = &EmailConfig{Host: "smtp.example.com", From: "auth@example.com", Port: 587}
	})
	cfg, err := NewConfig(opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := cfg.mailer.(*LogMailer); ok {
		t.Fatal("expected explicit WithEmail config not to be overridden by the log-mailer default")
	}
}

func TestNewConfig_ProdOrStagingWithNoMailer_Rejected(t *testing.T) {
	for _, env := range []Environment{EnvironmentProd, EnvironmentStaging} {
		t.Run(string(env), func(t *testing.T) {
			opts := append(validConfigOpts(), func(c *config) {
				c.environment = env
			})
			_, err := NewConfig(opts...)
			if err == nil {
				t.Fatalf("expected error for %s config with no mailer configured", env)
			}
			if !strings.Contains(err.Error(), "Mailer or Email config required") {
				t.Fatalf("expected mailer-required error, got: %v", err)
			}
		})
	}
}
