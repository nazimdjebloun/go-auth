package goauth

import "context"

type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}
