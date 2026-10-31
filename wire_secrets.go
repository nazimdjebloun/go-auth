package goauth

import (
	"fmt"

	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/hasher/registry"
	"github.com/nazimdjebloun/go-auth/internal/keyring"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/middleware"
)

// prepareConfig clones and checks the caller's config before New mutates its
// resolved defaults. The returned copy shares only consumer-owned live objects.
func prepareConfig(in *Config) (Config, keyring.Keys, error) {
	if in == nil {
		return Config{}, keyring.Keys{}, fmt.Errorf("goauth: nil config — build one with goauth.NewConfig(goauth.WithApp(...), ...)")
	}
	cfg := in.clone()
	if !cfg.resolved.validated {
		return Config{}, keyring.Keys{}, fmt.Errorf(
			"goauth: config was not built via NewConfig(opts...) — " +
				"construct it with goauth.NewConfig(goauth.WithApp(...), ...) so " +
				"required fields and security settings are validated",
		)
	}
	// Exported options remain callable after NewConfig. Resolve intent fields
	// again and validate the final clone before deriving keys or opening stores.
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return Config{}, keyring.Keys{}, fmt.Errorf("goauth: invalid configuration: %w", err)
	}
	if cfg.app.Environment.normalize() == EnvironmentDev && cfg.logger != nil {
		cfg.logger.Warn("goauth: running in dev environment", "cookie_secure", cfg.resolved.cookieSecure)
	}
	keys := keyring.Derive([]byte(cfg.secret))
	applyCSRFTokenDefaults(&cfg, keys)
	return cfg, keys, nil
}

// buildPasswordHasher keeps prefix-based verifier selection and independently
// derived, versioned pepper keys together in the startup sequence.
func buildPasswordHasher(cfg *Config) (*service.PasswordHasher, map[uint32][]byte, error) {
	// The legacy bcrypt verifier stays at cost 12 even when a custom current
	// hasher is configured. Stored hashes select their verifier by prefix.
	const defaultBcryptCost = 12
	currentHasher := cfg.passwordHasher
	if currentHasher == nil {
		cost := defaultBcryptCost
		if cfg.bcryptCost > 0 {
			cost = cfg.bcryptCost
		}
		currentHasher = hasher.New(cost)
	}
	passwordRegistry, err := registry.New(currentHasher, hasher.New(defaultBcryptCost))
	if err != nil {
		return nil, nil, fmt.Errorf("goauth: building password hasher registry: %w", err)
	}
	passwordPepperKeys := make(map[uint32][]byte, len(cfg.passwordPepper.Keys))
	for version, secret := range cfg.passwordPepper.Keys {
		passwordPepperKeys[version] = keyring.DerivePasswordPepper([]byte(secret))
	}
	passwordHasher, err := service.NewPasswordHasher(passwordRegistry, cfg.passwordPepper.CurrentVersion, passwordPepperKeys)
	if err != nil {
		return nil, nil, fmt.Errorf("goauth: building password hasher: %w", err)
	}
	return passwordHasher, passwordPepperKeys, nil
}

// applyCSRFTokenDefaults builds the mandatory browser protection settings.
func applyCSRFTokenDefaults(cfg *Config, keys keyring.Keys) {
	cfg.csrf = &middleware.CSRFTokenConfig{

		CookieSecure: cfg.resolved.cookieSecure, CookieSameSite: cfg.browser.Cookies.SameSite,
		Secret: keys.CSRF, Logger: cfg.logger,
	}
}
