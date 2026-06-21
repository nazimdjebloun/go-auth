package goauth

import "context"

type Mailer interface {
	Send(ctx context.Context, to, subject, html, text string) error
}
