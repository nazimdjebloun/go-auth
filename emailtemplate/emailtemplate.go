// Package emailtemplate provides the default email template provider for go-auth.
// It parses embedded HTML and text templates once at startup and renders them
// using html/template (auto-escaping) and text/template.
package emailtemplate

import (
	"embed"
	"fmt"
	"html/template"
	"strings"
	textTmpl "text/template"
	"time"

	"github.com/nazimdjebloun/go-auth/port"
)

//go:embed templates/*
var templateFS embed.FS

// emailTemplates holds pre-parsed HTML and text templates for each email type.
type emailTemplates struct {
	html map[port.EmailTemplateType]*template.Template
	text map[port.EmailTemplateType]*textTmpl.Template
}

// templateFiles maps each email type to its base filename.
var templateFiles = map[port.EmailTemplateType]string{
	port.TemplatePasswordReset:       "password_reset",
	port.TemplateSetPassword:         "set_password",
	port.TemplateVerification:        "verification",
	port.TemplateInvite:              "invite",
	port.TemplateOrgInvite:           "org_invite",
	port.TemplateDeleteAccount:       "delete_account",
	port.TemplateTwoFactor:           "two_factor",
	port.TemplateTwoFactorSuspicious: "two_factor_suspicious",
}

// subjects holds the default subject line prefix for each email type.
var subjects = map[port.EmailTemplateType]string{
	port.TemplatePasswordReset:       "Reset your password",
	port.TemplateSetPassword:         "Set your password",
	port.TemplateVerification:        "Verify your email",
	port.TemplateInvite:              "You've been invited",
	port.TemplateOrgInvite:           "Organization invitation",
	port.TemplateDeleteAccount:       "Delete your account",
	port.TemplateTwoFactor:           "Your login code",
	port.TemplateTwoFactorSuspicious: "Unusual sign-in activity",
}

// FormatDuration formats a time.Duration into a human-readable string.
// Examples: "1 hour", "10 minutes", "30 seconds".
func FormatDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	h := int(d.Hours())
	if h > 0 && d%time.Hour == 0 {
		if h == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", h)
	}
	m := int(d.Minutes())
	if m == 1 {
		return "1 minute"
	}
	if m == 0 {
		return "less than a minute"
	}
	return fmt.Sprintf("%d minutes", m)
}

// newEmailTemplates parses all embedded templates once at startup.
func newEmailTemplates() (*emailTemplates, error) {
	htmlTpls := make(map[port.EmailTemplateType]*template.Template, len(templateFiles))
	textTpls := make(map[port.EmailTemplateType]*textTmpl.Template, len(templateFiles))

	funcMap := template.FuncMap{
		"formatDuration": FormatDuration,
	}

	for ttype, base := range templateFiles {
		htmlPath := "templates/" + base + ".html"
		txtPath := "templates/" + base + ".txt"

		htmlContent, err := templateFS.ReadFile(htmlPath)
		if err != nil {
			return nil, fmt.Errorf("goauth: read html template %s: %w", htmlPath, err)
		}
		htmlTpls[ttype], err = template.New(string(ttype)).Funcs(funcMap).Parse(string(htmlContent))
		if err != nil {
			return nil, fmt.Errorf("goauth: parse html template %s: %w", htmlPath, err)
		}

		txtContent, err := templateFS.ReadFile(txtPath)
		if err != nil {
			return nil, fmt.Errorf("goauth: read text template %s: %w", txtPath, err)
		}
		textTpls[ttype], err = textTmpl.New(string(ttype)).Funcs(textTmpl.FuncMap{
			"formatDuration": FormatDuration,
		}).Parse(string(txtContent))
		if err != nil {
			return nil, fmt.Errorf("goauth: parse text template %s: %w", txtPath, err)
		}
	}

	return &emailTemplates{html: htmlTpls, text: textTpls}, nil
}

// Provider is the built-in TemplateProvider that renders embedded email
// templates using html/template and text/template. Templates are parsed
// once at construction time.
type Provider struct {
	tpls      *emailTemplates
	validator *port.URLValidator
}

// New creates a new Provider with all templates parsed at startup.
// The validator controls URL safety checks. If nil, HTTPS-only validation is used.
func New(validator *port.URLValidator) (*Provider, error) {
	tpls, err := newEmailTemplates()
	if err != nil {
		return nil, err
	}
	if validator == nil {
		validator = &port.URLValidator{}
	}
	return &Provider{tpls: tpls, validator: validator}, nil
}

// Render executes the template determined by the data object.
// It validates URLs first (if the data implements URLValidatable),
// then executes the HTML and text templates.
func (p *Provider) Render(data port.TemplateData) (port.TemplateResult, error) {
	if uv, ok := data.(port.URLValidatable); ok {
		if err := uv.ValidateURLs(p.validator); err != nil {
			return port.TemplateResult{}, err
		}
	}

	tmplType := data.Template()

	htmlTpl, ok := p.tpls.html[tmplType]
	if !ok {
		return port.TemplateResult{}, fmt.Errorf("goauth: unknown template type %q", tmplType)
	}
	textTpl := p.tpls.text[tmplType]

	var htmlBuf, textBuf strings.Builder
	if err := htmlTpl.Execute(&htmlBuf, data); err != nil {
		return port.TemplateResult{}, fmt.Errorf("goauth: execute html template %s: %w", tmplType, err)
	}
	if err := textTpl.Execute(&textBuf, data); err != nil {
		return port.TemplateResult{}, fmt.Errorf("goauth: execute text template %s: %w", tmplType, err)
	}

	subject := subjects[tmplType] + " - " + appNameFromData(data)

	return port.TemplateResult{
		Subject: subject,
		HTML:    htmlBuf.String(),
		Text:    textBuf.String(),
	}, nil
}

// appNameFromData extracts the AppName field from any data struct.
func appNameFromData(data port.TemplateData) string {
	type named interface{ GetAppName() string }
	if n, ok := data.(named); ok {
		return n.GetAppName()
	}
	// Fallback: type switch for all known types
	switch d := data.(type) {
	case port.PasswordResetData:
		return d.AppName
	case port.SetPasswordData:
		return d.AppName
	case port.VerificationData:
		return d.AppName
	case port.InviteData:
		return d.AppName
	case port.OrgInviteData:
		return d.AppName
	case port.DeleteAccountData:
		return d.AppName
	case port.TwoFactorData:
		return d.AppName
	case port.TwoFactorSuspiciousData:
		return d.AppName
	}
	return ""
}
