package service

import (
	"context"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type AdminService struct {
	users    port.UserRepository
	sessions port.SessionRepository
}

func NewAdminService(
	users port.UserRepository,
	sessions port.SessionRepository,
) *AdminService {
	return &AdminService{
		users:    users,
		sessions: sessions,
	}
}

func (s *AdminService) ListUsers(ctx context.Context, input AdminListUsersInput) (*AdminListUsersResult, *domain.AuthError) {
	filter := port.UserFilter{
		Email:  input.Email,
		Role:   input.Role,
		Offset: input.Offset,
		Limit:  input.Limit,
	}

	users, total, err := s.users.List(ctx, filter)
	if err != nil {
		return nil, domain.NewError("internal_error", "Failed to list users", 500)
	}

	return &AdminListUsersResult{
		Users: users,
		Total: total,
	}, nil
}

func (s *AdminService) BanUser(ctx context.Context, userID string) *domain.AuthError {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if user.IsBanned {
		return domain.NewError("already_banned", "User is already banned", 400)
	}

	now := time.Now().UTC()
	user.IsBanned = true
	user.BannedAt = &now
	user.UpdatedAt = now

	if err := s.users.Update(ctx, user); err != nil {
		return domain.NewError("internal_error", "Failed to ban user", 500)
	}

	if err := s.sessions.DeleteAllForUser(ctx, userID); err != nil {
		return domain.NewError("internal_error", "Failed to revoke sessions", 500)
	}

	return nil
}

func (s *AdminService) UnbanUser(ctx context.Context, userID string) *domain.AuthError {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if !user.IsBanned {
		return domain.NewError("not_banned", "User is not banned", 400)
	}

	user.IsBanned = false
	user.BannedAt = nil
	user.UpdatedAt = time.Now().UTC()

	if err := s.users.Update(ctx, user); err != nil {
		return domain.NewError("internal_error", "Failed to unban user", 500)
	}

	return nil
}

func (s *AdminService) UpdateUserRole(ctx context.Context, userID string, role string) *domain.AuthError {
	if role != "user" && role != "admin" {
		return domain.NewError("invalid_role", "Role must be 'user' or 'admin'", 400)
	}

	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	user.Role = domain.Role(role)
	user.UpdatedAt = time.Now().UTC()

	if err := s.users.Update(ctx, user); err != nil {
		return domain.NewError("internal_error", "Failed to update role", 500)
	}

	return nil
}

func (s *AdminService) DeleteUser(ctx context.Context, userID string) *domain.AuthError {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if err := s.sessions.DeleteAllForUser(ctx, userID); err != nil {
		return domain.NewError("internal_error", "Failed to revoke sessions", 500)
	}

	if err := s.users.Delete(ctx, userID); err != nil {
		return domain.NewError("internal_error", "Failed to delete user", 500)
	}

	return nil
}

func (s *AdminService) RevokeUserSessions(ctx context.Context, userID string) *domain.AuthError {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if err := s.sessions.DeleteAllForUser(ctx, userID); err != nil {
		return domain.NewError("internal_error", "Failed to revoke sessions", 500)
	}

	return nil
}
