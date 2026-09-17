package service

import (
	"context"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

func updateUserName(ctx context.Context, users port.UserRepository, user *domain.User, name string, now time.Time) error {
	updated, err := users.UpdateName(ctx, user.ID, name, now)
	if err != nil {
		return err
	}
	if !updated {
		return domain.ErrUserNotFound
	}
	return nil
}

func verifyUserEmail(ctx context.Context, users port.UserRepository, user *domain.User, email string, now time.Time) (bool, error) {
	if user.Email != email {
		return false, nil
	}
	return users.VerifyEmailIfMatches(ctx, user.ID, email, now)
}
