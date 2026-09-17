package service

import (
	"context"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

func updateUserName(ctx context.Context, users port.UserRepository, user *domain.User, name string, now time.Time) error {
	if writer, ok := users.(port.UserNameUpdater); ok {
		updated, err := writer.UpdateName(ctx, user.ID, name, now)
		if err != nil {
			return err
		}
		if !updated {
			return domain.ErrUserNotFound
		}
		return nil
	}
	// Compatibility for custom repositories without the narrow capability.
	// Copy the snapshot so a failed write does not mutate a shared read result.
	updated := *user
	updated.Name, updated.UpdatedAt = name, now
	return users.Update(ctx, &updated)
}

func verifyUserEmail(ctx context.Context, users port.UserRepository, user *domain.User, email string, now time.Time) (bool, error) {
	if user.Email != email {
		return false, nil
	}
	if writer, ok := users.(port.UserEmailVerifier); ok {
		return writer.VerifyEmailIfMatches(ctx, user.ID, email, now)
	}
	// Legacy implementations retain their own concurrency guarantees.
	updated := *user
	updated.IsVerified, updated.VerifiedAt, updated.UpdatedAt = true, &now, now
	if err := users.Update(ctx, &updated); err != nil {
		return false, err
	}
	return true, nil
}
