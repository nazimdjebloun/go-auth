package service

import (
	"context"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/port"
)

// Password delivery tests run the queued consumer inline. Queue persistence,
// request isolation, retries, and lifecycle are covered separately against SQL.
type passwordDeliveryTestQueue struct{ service *PasswordService }

func (q passwordDeliveryTestQueue) Enqueue(ctx context.Context, _ port.RecoveryKind, email string) error {
	_ = q.service.sendPasswordReset(ctx, api.ForgotPasswordInput{Email: email})
	return nil
}

func newPasswordDeliveryTestService(users port.UserRepository, tokens port.TokenRepository,
	hasher port.Hasher, gen port.TokenGenerator, mailer port.Mailer, sessions port.SessionRevoker,
	txManager port.TxManager, config Config,
) *PasswordService {
	svc := NewPasswordService(users, tokens, hasher, gen, mailer, sessions, txManager, config)
	svc.recovery = passwordDeliveryTestQueue{service: svc}
	return svc
}
