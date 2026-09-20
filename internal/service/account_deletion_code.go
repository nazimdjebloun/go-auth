package service

import (
	"context"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// deleteWithCode claims the exact validated code in the same transaction as
// deletion. A failed claim or deletion rolls everything back; a successful
// deletion may cascade the claimed token row, so no write follows commit.
func (d *AccountDeletion) deleteWithCode(
	ctx context.Context,
	userID string,
	tokens port.TokenRepository,
	token *domain.VerificationToken,
	record func(context.Context) error,
) error {
	return d.users.WithAdminGuard(ctx, func(txCtx context.Context) error {
		claimed, err := tokens.ConsumeIfValid(txCtx, port.ConsumeTokenInput{
			ID: token.ID, TokenHash: token.TokenHash, UserID: userID,
			Type: domain.TokenDeleteAccount, UsedAt: time.Now().UTC(),
		})
		if err != nil {
			return err
		}
		if !claimed {
			return domain.ErrDeleteCodeInvalid
		}
		return d.DeleteUserAndRecord(txCtx, userID, record)
	})
}
