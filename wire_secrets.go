package goauth

import (
	"fmt"
	"net/http"

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

// applyCSRFTokenDefaults resolves the CSRF double-submit layer against the
// rest of the config: it is on unless explicitly disabled, inherits the
// session cookie's scope, and warns about the SameSite/ExposeCSRFTokenInBody
// pairing. Mutates cfg.security.CSRFToken in place; nil there means the layer is off.
func applyCSRFTokenDefaults(cfg *Config, keys keyring.Keys) {
	// The double-submit token layer is on unless explicitly disabled. A nil
	// CSRFToken means "build one with defaults", not "off" — middleware.CSRFToken
	// treats a nil config as a pass-through, so disabling is expressed by
	// leaving csrfToken nil here.
	if cfg.security.DisableCSRFToken {
		cfg.security.CSRFToken = nil
		if cfg.logger != nil {
			cfg.logger.Warn("goauth: CSRF double-submit token disabled",
				"note", "origin/referer checking still applies",
				"fix", "re-enable by removing SecurityConfig.DisableCSRFToken")
		}
	} else if cfg.security.CSRFToken == nil {
		cfg.security.CSRFToken = &middleware.CSRFTokenConfig{
			CookieName: "_csrf",
			HeaderName: "X-CSRF-Token",
			CookiePath: "/",
		}
	}
	if cfg.security.CSRFToken != nil {
		cfg.security.CSRFToken.CookieSecure = cfg.resolved.cookieSecure
		cfg.security.CSRFToken.Secret = keys.CSRF
		cfg.security.CSRFToken.Logger = cfg.logger
		// Default the token cookie's scope to the session cookie's. A
		// deployment that widened the session cookie to ".example.com" so a
		// sibling subdomain could hold a session almost certainly needs the
		// CSRF token readable there too — and a session that works while
		// every mutation 403s is the worst of the two failure modes, because
		// it looks like a permissions bug rather than a cookie-scope one.
		// An explicit CookieDomain still wins.
		if cfg.security.CSRFToken.CookieDomain == "" {
			cfg.security.CSRFToken.CookieDomain = cfg.cookie.Domain
		}

		// SameSite=None and ExposeCSRFTokenInBody are the same decision seen from
		// two sides: one lets the cookie be *sent* cross-site, the other lets
		// the frontend *read* the token it has to echo back. A browser
		// frontend needs both or neither, and setting one alone produces a
		// deployment that half-works in a way that reads as a bug in this
		// library rather than a config mismatch — reads fine, every write
		// 403s, or nothing authenticates at all.
		//
		// A warning, not a rejection: a native or mobile client keeps its own
		// cookie jar and is not subject to SameSite, so either setting on its
		// own is legitimate there.
		if cfg.logger != nil {
			crossSiteCookie := cfg.cookie.SameSite == http.SameSiteNoneMode
			switch {
			case crossSiteCookie && !cfg.security.CSRFToken.ExposeCSRFTokenInBody:
				cfg.logger.Warn("goauth: cookie SameSite=None without CSRFTokenConfig.ExposeCSRFTokenInBody — a cross-site browser frontend receives the session cookie but cannot read the CSRF token, so every state-changing request will 403")
			case !crossSiteCookie && cfg.security.CSRFToken.ExposeCSRFTokenInBody:
				cfg.logger.Warn("goauth: CSRFTokenConfig.ExposeCSRFTokenInBody without cookie SameSite=None — a cross-site browser frontend can read the CSRF token but is never sent the session cookie, so every request arrives unauthenticated",
					"same_site", cfg.cookie.SameSite)
			}
		}
	}
}
