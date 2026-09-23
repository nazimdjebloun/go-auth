package port

import "time"

// EmailTemplateType identifies the kind of email being rendered.
type EmailTemplateType string

// TemplatePasswordReset and the following values identify built-in email templates.
const (
	TemplatePasswordReset EmailTemplateType = "password_reset"
	TemplateSetPassword   EmailTemplateType = "set_password"
	TemplateVerification  EmailTemplateType = "verification"
	TemplateInvite        EmailTemplateType = "invite"
	TemplateOrgInvite     EmailTemplateType = "org_invite"
	TemplateDeleteAccount EmailTemplateType = "delete_account"
	TemplateTwoFactor     EmailTemplateType = "2fa"

	// TemplateTwoFactorSuspicious is the notify-only warning sent when an
	// account crosses the failed-2FA threshold. It carries no code and no
	// action link other than password reset, so it is useless to an
	// attacker who intercepts it.
	TemplateTwoFactorSuspicious EmailTemplateType = "2fa_suspicious"
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

// PasswordResetData supplies values for a password-reset email.
type PasswordResetData struct {
	AppName   string
	ResetURL  string
	ExpiresIn time.Duration
}

// Template selects the password-reset email template.
func (d PasswordResetData) Template() EmailTemplateType { return TemplatePasswordReset }

// ValidateURLs validates the password-reset link.
func (d PasswordResetData) ValidateURLs(v *URLValidator) error {
	return v.Validate(d.ResetURL, "ResetURL")
}

// SetPasswordData supplies values for a set-password email.
type SetPasswordData struct {
	AppName   string
	Code      string
	ExpiresIn time.Duration
}

// Template selects the set-password email template.
func (d SetPasswordData) Template() EmailTemplateType { return TemplateSetPassword }

// VerificationData supplies values for an email-verification message.
type VerificationData struct {
	AppName   string
	Code      string
	ExpiresIn time.Duration
}

// Template selects the verification email template.
func (d VerificationData) Template() EmailTemplateType { return TemplateVerification }

// InviteData supplies values for a platform invitation email.
type InviteData struct {
	AppName   string
	InviteURL string
	ExpiresIn time.Duration
}

// Template selects the platform invitation email template.
func (d InviteData) Template() EmailTemplateType { return TemplateInvite }

// ValidateURLs validates the platform invitation link.
func (d InviteData) ValidateURLs(v *URLValidator) error {
	return v.Validate(d.InviteURL, "InviteURL")
}

// OrgInviteData supplies values for an organization invitation email.
type OrgInviteData struct {
	AppName   string
	OrgName   string
	InviteURL string
	ExpiresIn time.Duration
}

// Template selects the organization invitation email template.
func (d OrgInviteData) Template() EmailTemplateType { return TemplateOrgInvite }

// ValidateURLs validates the organization invitation link.
func (d OrgInviteData) ValidateURLs(v *URLValidator) error {
	return v.Validate(d.InviteURL, "InviteURL")
}

// DeleteAccountData supplies values for an account-deletion email.
type DeleteAccountData struct {
	AppName   string
	Code      string
	ExpiresIn time.Duration
}

// Template selects the account-deletion email template.
func (d DeleteAccountData) Template() EmailTemplateType { return TemplateDeleteAccount }

// TwoFactorData supplies values for a two-factor code email.
type TwoFactorData struct {
	AppName   string
	Code      string
	ExpiresIn time.Duration
}

// Template selects the two-factor code email template.
func (d TwoFactorData) Template() EmailTemplateType { return TemplateTwoFactor }

// TwoFactorSuspiciousData supplies values for a suspicious-attempt warning.
type TwoFactorSuspiciousData struct {
	AppName          string
	AttemptCount     int
	ResetPasswordURL string
}

// Template selects the suspicious-attempt email template.
func (d TwoFactorSuspiciousData) Template() EmailTemplateType { return TemplateTwoFactorSuspicious }

// ValidateURLs validates the password-reset link.
func (d TwoFactorSuspiciousData) ValidateURLs(v *URLValidator) error {
	return v.Validate(d.ResetPasswordURL, "ResetPasswordURL")
}

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
	return "goauth: template URL field " + e.Field + ": " + e.Detail
}
