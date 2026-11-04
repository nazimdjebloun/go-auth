package service

import (
	"context"
	"fmt"
	"time"

	"github.com/nazimdjebloun/go-auth/port"
)

// Delivery can fail because the request was canceled. Give cleanup a separate
// bounded context so an undelivered code cannot suppress the next request.
func discardUndeliveredToken(ctx context.Context, tokens port.TokenRepository, id string) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := tokens.DeleteUnusedByID(cleanupCtx, id); err != nil {
		return fmt.Errorf("discard undelivered token: %w", err)
	}
	return nil
}

func sendEmailChangedNotice(ctx context.Context, mailer port.Mailer, templates port.TemplateProvider, appName, email string) error {
	message, err := templates.Render(port.EmailChangedData{AppName: appName})
	if err != nil {
		return err
	}
	return mailer.Send(ctx, email, message.Subject, message.HTML, message.Text)
}
