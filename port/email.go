package port

import "context"

type EmailData struct {
	To           string
	Subject      string
	HTML         string
	Text         string
	TemplateName string
	TemplateData map[string]any
}

type EmailSender interface {
	Send(ctx context.Context, data EmailData) error
}
