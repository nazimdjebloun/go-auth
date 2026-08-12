package service

import (
	"github.com/nazimdjebloun/go-auth/emailtemplate"
	"github.com/nazimdjebloun/go-auth/port"
)

// resolveTemplates returns the given provider, or creates the default
// embedded-template provider. Panics if the default templates cannot
// be parsed (should never happen with embedded templates).
func resolveTemplates(p port.TemplateProvider, validator *port.URLValidator) port.TemplateProvider {
	if p != nil {
		return p
	}
	provider, err := emailtemplate.New(validator)
	if err != nil {
		panic("goauth: failed to initialize default email templates: " + err.Error())
	}
	return provider
}
