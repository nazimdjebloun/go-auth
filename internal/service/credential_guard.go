package service

import (
	"context"
	"fmt"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// lockPasswordIdentity reasserts the KDF's snapshot under the same row lock that
// credential replacement takes. Call only inside the issuance transaction.
func lockPasswordIdentity(ctx context.Context, users port.UserAuthenticationLocker, expected *domain.User) (*domain.User, error) {
	current, err := users.GetByIDForUpdate(ctx, expected.ID)
	if err != nil {
		return nil, fmt.Errorf("locking password identity: %w", err)
	}
	if current == nil || !current.HasPassword() || !expected.HasPassword() ||
		*current.PasswordHash != *expected.PasswordHash ||
		passwordPepperVersionValue(current.PasswordPepperVersion) != passwordPepperVersionValue(expected.PasswordPepperVersion) {
		return nil, domain.ErrInvalidCredentials
	}
	if current.IsBanned {
		return nil, domain.ErrUserBanned
	}
	// Metadata changes that alter authentication requirements also require a
	// fresh login rather than completing a decision made before that change.
	if current.Role != expected.Role || current.Email != expected.Email ||
		current.IsVerified != expected.IsVerified || current.TwoFactorEnabled != expected.TwoFactorEnabled {
		return nil, domain.ErrInvalidCredentials
	}
	return current, nil
}
