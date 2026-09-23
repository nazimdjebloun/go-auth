package goauth

import (
	"fmt"

	"github.com/nazimdjebloun/go-auth/emailtemplate"
	"github.com/nazimdjebloun/go-auth/mailer"
	"github.com/nazimdjebloun/go-auth/port"
)

// resolveMailer picks the consumer's own Mailer over the built-in SMTP one.
// Returns nil when neither is configured — validate() has already refused
// that combination for any feature that actually sends mail.
func resolveMailer(cfg *Config) (port.Mailer, error) {
	if cfg.mailer != nil {
		return cfg.mailer, nil
	}
	if cfg.email != nil {
		smtp, err := mailer.NewSMTP(*cfg.email)
		if err != nil {
			return nil, err
		}
		return smtp, nil
	}
	// Neither configured: validate() has already refused this for any feature
	// that actually sends mail, so a nil Mailer here means nothing needs one.
	return nil, nil
}

// resolveTemplates picks the consumer's TemplateProvider over the built-in
// one. The URLValidator comes back alongside it because only the built-in
// templates have one — a custom provider builds its own links and is
// trusted to decide its own http/https policy.
func resolveTemplates(cfg *Config) (port.TemplateProvider, *port.URLValidator, error) {
	var templateProvider port.TemplateProvider
	var urlValidator *port.URLValidator
	if cfg.templates != nil {
		templateProvider = cfg.templates
	} else {
		allowHTTP := cfg.resolved.allowHTTPURLs
		urlValidator = &port.URLValidator{AllowHTTP: allowHTTP}
		p, err := emailtemplate.New(urlValidator)
		if err != nil {
			return nil, nil, err
		}
		templateProvider = p
	}
	return templateProvider, urlValidator, nil
}

// collectOAuthProviders indexes the providers registered via WithProvider by
// name, rejecting nils, empty names and duplicates — a duplicate would
// otherwise silently win the /auth/oauth/{provider} route.
func collectOAuthProviders(cfg *Config) (map[string]port.OAuthProvider, error) {
	oauthProviders := make(map[string]port.OAuthProvider)
	for _, p := range cfg.providers {
		if p == nil {
			return nil, fmt.Errorf("goauth: nil provider registered via WithProvider")
		}
		name := p.Name()
		if name == "" {
			return nil, fmt.Errorf("goauth: provider with empty name registered via WithProvider")
		}
		if _, exists := oauthProviders[name]; exists {
			return nil, fmt.Errorf("goauth: duplicate provider %q", name)
		}
		oauthProviders[name] = p
	}
	return oauthProviders, nil
}
