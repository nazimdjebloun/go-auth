package goauth

import (
	"strings"
	"testing"
	"time"
)

func TestNewRejectsSecurityOptionsAppliedAfterValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		option Option
		want   string
	}{
		{"empty root secret", WithSecret(""), "secret"},
		{"short root secret", WithSecret("too short"), "secret"},
		{"both CSRF protections disabled", WithSecurity(SecurityConfig{
			AllowedOrigins:   []string{"http://localhost"},
			DisableCSRFToken: true, AllowMissingCSRFHeaders: true,
		}), "DisableCSRFToken and AllowMissingCSRFHeaders"},
		{"negative session lifetime", WithSession(SessionConfig{TTL: -time.Second}), "session"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := NewConfig(validConfigOpts()...)
			if err != nil {
				t.Fatal(err)
			}
			tc.option(cfg)
			auth, err := New(cfg)
			if auth != nil {
				auth.Close()
				t.Fatal("New accepted invalid options applied after validation")
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestPrepareConfigDefaultsLateOptionsWithoutMutatingCaller(t *testing.T) {
	cfg, err := NewConfig(validConfigOpts()...)
	if err != nil {
		t.Fatal(err)
	}
	grace := 2 * time.Second
	WithSession(SessionConfig{GraceWindow: &grace})(cfg)
	prepared, _, err := prepareConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.session.TTL <= 0 || prepared.resolved.graceWindow != grace {
		t.Fatalf("late session option was not defaulted/resolved: %+v", prepared.session)
	}
	if cfg.session.TTL != 0 {
		t.Fatal("startup defaulting mutated the caller config")
	}
}
