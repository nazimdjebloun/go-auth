package goauth

import (
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/mailer"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestNewConfig_LogMailerRejectedOutsideDev(t *testing.T) {
	opts := append(validConfigOpts(), func(c *Config) {
		c.mailer = mailer.NewLog(nil)
		c.environment = EnvironmentStaging
	})
	_, err := NewConfig(opts...)
	if err == nil {
		t.Fatal("expected error when mailer.Log is used outside EnvironmentDev")
	}
	if !strings.Contains(err.Error(), "mailer.Log cannot be used outside EnvironmentDev") {
		t.Fatalf("expected Log env error, got: %v", err)
	}
}

func TestNewConfig_LogMailerRejectedInProd(t *testing.T) {
	opts := append(validConfigOpts(), func(c *Config) {
		c.mailer = mailer.NewLog(nil)
		c.environment = EnvironmentProd
	})
	_, err := NewConfig(opts...)
	if err == nil {
		t.Fatal("expected error when mailer.Log is used in EnvironmentProd")
	}
}

func TestNewConfig_LogMailerAllowedInDev(t *testing.T) {
	opts := append(validConfigOpts(), func(c *Config) {
		c.mailer = mailer.NewLog(nil)
		c.environment = EnvironmentDev
	})
	_, err := NewConfig(opts...)
	if err != nil {
		t.Fatalf("unexpected error when mailer.Log is used in EnvironmentDev: %v", err)
	}
}

func TestNewConfig_DevDefaultsToLogMailerWhenUnconfigured(t *testing.T) {
	opts := append(validConfigOpts(), func(c *Config) {
		c.environment = EnvironmentDev
	})
	cfg, err := NewConfig(opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := cfg.mailer.(*mailer.Log); !ok {
		t.Fatalf("expected mailer to default to *mailer.Log in dev, got %T", cfg.mailer)
	}
}

func TestNewConfig_DevDefaultDoesNotOverrideExplicitMailer(t *testing.T) {
	custom := &mockMailer{}
	opts := append(validConfigOpts(), func(c *Config) {
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
	opts := append(validConfigOpts(), func(c *Config) {
		c.environment = EnvironmentDev
		c.email = &EmailConfig{Host: "smtp.example.com", From: "auth@example.com", Port: 587}
	})
	cfg, err := NewConfig(opts...)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := cfg.mailer.(*mailer.Log); ok {
		t.Fatal("expected explicit WithEmail config not to be overridden by the log-mailer default")
	}
}

func TestNewConfig_ProdOrStagingWithNoMailer_Rejected(t *testing.T) {
	for _, env := range []Environment{EnvironmentProd, EnvironmentStaging} {
		t.Run(string(env), func(t *testing.T) {
			opts := append(validConfigOpts(), func(c *Config) {
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
