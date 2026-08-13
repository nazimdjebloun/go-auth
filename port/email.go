package port

import "context"

// Mailer delivers a rendered email. Implement this to plug in a transactional
// email provider (Resend, Postmark, SES, ...) via WithMailer; the built-in
// SMTPMailer and LogMailer (dev-only) both satisfy it. subject/html/text are
// already rendered by a TemplateProvider before Send is called — Mailer only
// handles transport, never template content. text may be empty if the
// TemplateProvider didn't produce a plain-text part; html is never empty.
// Send should return a non-nil error only on a real delivery failure —
// go-auth surfaces that as a 500 to the caller, so don't wrap validation
// errors that belong further up the stack in it.
type Mailer interface {
	Send(ctx context.Context, to, subject, html, text string) error
}
