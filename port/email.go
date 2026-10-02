package port

import "context"

// Mailer delivers a rendered email. Implement this to plug in a transactional
// email provider (Resend, Postmark, SES, ...) via WithMailer; the built-in
// SMTPMailer and LogMailer (dev-only) both satisfy it. subject/html/text are
// already rendered by a TemplateProvider before Send is called — Mailer only
// handles transport, never template content. text may be empty if the
// TemplateProvider didn't produce a plain-text part; html is never empty.
// Send should return a non-nil error only on a real delivery failure —
// synchronous operations may surface that as a 500; queued public recovery
// retries it outside the request. Send must honor context cancellation and
// deadlines so Auth.Close can stop an in-flight recovery delivery.
type Mailer interface {
	Send(ctx context.Context, to, subject, html, text string) error
}
