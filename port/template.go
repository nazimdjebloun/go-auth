package port

import "time"

// EmailTemplateType identifies the kind of email being rendered.
type EmailTemplateType string

const (
	TemplatePasswordReset EmailTemplateType = "password_reset"
	TemplateSetPassword   EmailTemplateType = "set_password"
	TemplateVerification  EmailTemplateType = "verification"
	TemplateInvite        EmailTemplateType = "invite"
	TemplateOrgInvite     EmailTemplateType = "org_invite"
	TemplateDeleteAccount EmailTemplateType = "delete_account"
)

// TemplateData is implemented by every template data struct.
// The Template method tells the renderer which template to use.
type TemplateData interface {
	Template() EmailTemplateType
}

// URLValidatable is optionally implemented by TemplateData types
// that contain URLs requiring validation before rendering.
type URLValidatable interface {
	ValidateURLs(v *URLValidator) error
}

// URLValidator validates URLs in template data.
type URLValidator struct {
	AllowHTTP bool
}

// Validate checks that a URL is safe to render.
// It rejects empty URLs and schemes other than https (and http when allowed).
func (v *URLValidator) Validate(raw, fieldName string) error {
	return validateURL(raw, fieldName, v.AllowHTTP)
}

// TemplateResult holds the rendered email content.
type TemplateResult struct {
	Subject string
	HTML    string
	Text    string
}

// TemplateProvider renders email templates.
// Implement this interface to provide custom email templates.
type TemplateProvider interface {
	Render(data TemplateData) (TemplateResult, error)
}

// ─── Per-template data types ────────────────────────────────

type PasswordResetData struct {
	AppName   string
	ResetURL  string
	ExpiresIn time.Duration
}

func (d PasswordResetData) Template() EmailTemplateType { return TemplatePasswordReset }
func (d PasswordResetData) ValidateURLs(v *URLValidator) error {
	return v.Validate(d.ResetURL, "ResetURL")
}

type SetPasswordData struct {
	AppName   string
	Code      string
	ExpiresIn time.Duration
}

func (d SetPasswordData) Template() EmailTemplateType { return TemplateSetPassword }

type VerificationData struct {
	AppName   string
	Code      string
	ExpiresIn time.Duration
}

func (d VerificationData) Template() EmailTemplateType { return TemplateVerification }

type InviteData struct {
	AppName   string
	InviteURL string
}

func (d InviteData) Template() EmailTemplateType { return TemplateInvite }
func (d InviteData) ValidateURLs(v *URLValidator) error {
	return v.Validate(d.InviteURL, "InviteURL")
}

type OrgInviteData struct {
	AppName   string
	OrgName   string
	InviteURL string
	ExpiresIn time.Duration
}

func (d OrgInviteData) Template() EmailTemplateType { return TemplateOrgInvite }
func (d OrgInviteData) ValidateURLs(v *URLValidator) error {
	return v.Validate(d.InviteURL, "InviteURL")
}

type DeleteAccountData struct {
	AppName   string
	Code      string
	ExpiresIn time.Duration
}

func (d DeleteAccountData) Template() EmailTemplateType { return TemplateDeleteAccount }

// ─── URL validation (unexported, used by emailtemplate) ────

func validateURL(raw, fieldName string, allowHTTP bool) error {
	if raw == "" {
		return &URLError{Field: fieldName, Detail: "URL is empty"}
	}
	// Minimal parse to extract scheme without importing net/url here.
	scheme := ""
	for i, c := range raw {
		if c == ':' {
			scheme = raw[:i]
			break
		}
		if c == '/' || c == '?' || c == '#' {
			break // no scheme found — relative URL
		}
	}
	if scheme == "" {
		return nil // relative URL, always allowed
	}
	switch scheme {
	case "https":
		return nil
	case "http":
		if allowHTTP {
			return nil
		}
		return &URLError{
			Field:  fieldName,
			Detail: "http:// URLs are not allowed in production — use https:// (set AllowHTTPURLs for local development)",
		}
	default:
		return &URLError{Field: fieldName, Detail: "unsupported scheme " + scheme}
	}
}

// URLError describes an invalid URL in template data.
type URLError struct {
	Field  string
	Detail string
}

func (e *URLError) Error() string {
	return "go-auth: template URL field " + e.Field + ": " + e.Detail
}
