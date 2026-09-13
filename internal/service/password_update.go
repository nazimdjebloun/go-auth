package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

var errPasswordPepperDowngrade = errors.New("service: password pepper version downgrade")

// guardedPasswordUpdate is the only service-layer path that replaces an
// existing password credential. The repository compare-and-swap prevents a
// stale read from overwriting a concurrent password change, while the local
// comparison rejects a lower pepper version before any database call.
func guardedPasswordUpdate(
	ctx context.Context,
	users port.PasswordHashUpdater,
	user *domain.User,
	newHash string,
	newPepperVersion *uint32,
	updatedAt time.Time,
) (bool, error) {
	if user == nil || user.PasswordHash == nil {
		return false, errors.New("service: guarded password update requires an existing password")
	}
	oldPepperVersion := passwordPepperVersionValue(user.PasswordPepperVersion)
	if newVersion := passwordPepperVersionValue(newPepperVersion); newVersion < oldPepperVersion {
		return false, fmt.Errorf("%w: stored=%d new=%d", errPasswordPepperDowngrade, oldPepperVersion, newVersion)
	}

	oldHash := *user.PasswordHash
	updated, err := users.UpdatePasswordHash(
		ctx,
		user.ID,
		oldHash,
		user.PasswordPepperVersion,
		newHash,
		newPepperVersion,
		updatedAt,
	)
	if err != nil {
		return false, fmt.Errorf("guarded password update: %w", err)
	}
	if !updated {
		return false, nil
	}

	user.PasswordHash = &newHash
	user.PasswordPepperVersion = clonePasswordPepperVersion(newPepperVersion)
	user.UpdatedAt = updatedAt
	return true, nil
}

func passwordPepperVersionValue(version *uint32) uint32 {
	if version == nil {
		return 0
	}
	return *version
}

func clonePasswordPepperVersion(version *uint32) *uint32 {
	if version == nil {
		return nil
	}
	value := *version
	return &value
}
