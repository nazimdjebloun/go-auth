package goauth

import (
	"context"
	"testing"

	"github.com/nazimdjebloun/go-auth/port"
)

// mockProvider implements port.OAuthProvider for testing.
type mockProvider struct {
	name string
}

func (m *mockProvider) Name() string                          { return m.name }
func (m *mockProvider) AuthURL(state string) string           { return "https://auth.example.com/" + state }
func (m *mockProvider) Exchange(_ context.Context, _ string) (*port.OAuthProfile, error) {
	return &port.OAuthProfile{Provider: m.name, ProviderUserID: "1", Email: "test@example.com", EmailVerified: true}, nil
}

func TestWithProvider_Nil(t *testing.T) {
	cfg := DefaultConfig()
	WithProvider(nil)(&cfg)
	if len(cfg.providers) != 1 {
		t.Fatal("expected 1 provider (nil) in slice")
	}
	if cfg.providers[0] != nil {
		t.Fatal("expected nil provider in slice")
	}
}

func TestWithProvider_EmptyName(t *testing.T) {
	cfg := DefaultConfig()
	WithProvider(&mockProvider{name: ""})(&cfg)
	if len(cfg.providers) != 1 {
		t.Fatal("expected 1 provider in slice")
	}
}

func TestWithProvider_Valid(t *testing.T) {
	cfg := DefaultConfig()
	WithProvider(&mockProvider{name: "test"})(&cfg)
	if len(cfg.providers) != 1 {
		t.Fatal("expected 1 provider")
	}
	if cfg.providers[0].Name() != "test" {
		t.Errorf("expected name 'test', got %q", cfg.providers[0].Name())
	}
}

func TestWithProvider_Multiple(t *testing.T) {
	cfg := DefaultConfig()
	WithProvider(&mockProvider{name: "a"})(&cfg)
	WithProvider(&mockProvider{name: "b"})(&cfg)
	WithProvider(&mockProvider{name: "c"})(&cfg)
	if len(cfg.providers) != 3 {
		t.Fatalf("expected 3 providers, got %d", len(cfg.providers))
	}
	names := map[string]bool{}
	for _, p := range cfg.providers {
		names[p.Name()] = true
	}
	for _, n := range []string{"a", "b", "c"} {
		if !names[n] {
			t.Errorf("missing provider %q", n)
		}
	}
}

func TestNewConfig_WithProvider(t *testing.T) {
	opts := validConfigOpts()
	opts = append(opts, WithProvider(&mockProvider{name: "mock"}))
	cfg, err := NewConfig(opts...)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.providers) != 1 {
		t.Fatalf("expected 1 provider, got %d", len(cfg.providers))
	}
	if cfg.providers[0].Name() != "mock" {
		t.Errorf("expected name 'mock', got %q", cfg.providers[0].Name())
	}
}
