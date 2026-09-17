package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/nazimdjebloun/go-auth/domain"
)

// targetUser distinguishes absence from a failed read. Keep the cause for
// direct service callers; HTTP handlers log it and emit a generic 500.
func (s *AdminService) targetUser(ctx context.Context, id string) (*domain.User, error) {
	user, err := s.users.GetByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrUserNotFound
		}
		return nil, fmt.Errorf("admin target user lookup: %w", err)
	}
	if user == nil {
		return nil, domain.ErrUserNotFound
	}
	return user, nil
}
