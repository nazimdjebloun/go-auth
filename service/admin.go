package service

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type AdminService struct {
	users      port.UserRepository
	sessions   port.SessionRepository
	hasher     port.Hasher
	config     Config
	sessionSvc *SessionService
	log        *slog.Logger
}

func NewAdminService(
	users port.UserRepository,
	sessions port.SessionRepository,
	hasher port.Hasher,
	config Config,
	sessionSvc *SessionService,
) *AdminService {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &AdminService{
		users:      users,
		sessions:   sessions,
		hasher:     hasher,
		config:     config,
		sessionSvc: sessionSvc,
		log:        config.Logger,
	}
}

func (s *AdminService) ListUsers(ctx context.Context, input AdminListUsersInput) (*AdminListUsersResult, *domain.AuthError) {
	filter := port.UserFilter{
		Email:          input.Email,
		Role:           input.Role,
		Offset:         input.Offset,
		Limit:          input.Limit,
		Search:         input.Search,
		OrderBy:        input.OrderBy,
		OrderDirection: input.OrderDirection,
	}

	users, total, err := s.users.List(ctx, filter)
	if err != nil {
		s.log.Error("failed to list users", "err", err)
		return nil, domain.NewError("internal_error", "Internal server error", 500)
	}

	if users == nil {
		users = []domain.User{}
	}

	return &AdminListUsersResult{
		Users:  users,
		Total:  total,
		Limit:  input.Limit,
		Offset: input.Offset,
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

	// Prevent banning the last admin.
	if user.Role == domain.RoleAdmin {
		adminRole := domain.RoleAdmin
		_, total, err := s.users.List(ctx, port.UserFilter{Role: &adminRole, Limit: 1})
		if err != nil {
			s.log.Error("failed to check admin count", "err", err)
			return domain.NewError("internal_error", "Internal server error", 500)
		}
		if total <= 1 {
			s.log.Warn("last admin ban blocked", "user_id", userID)
			return domain.NewError("last_admin", "Cannot ban the last admin", 400)
		}
	}

	now := time.Now().UTC()
	if err := s.users.SetBanStatus(ctx, userID, true, &now, now); err != nil {
		s.log.Error("failed to ban user", "err", err, "user_id", userID)
		return domain.NewError("internal_error", "Internal server error", 500)
	}

	if err := s.sessionSvc.RevokeAll(ctx, userID); err != nil {
		s.log.Error("failed to revoke sessions after ban", "err", err, "user_id", userID)
		return domain.NewError("internal_error", "Internal server error", 500)
	}

	s.log.Info("user banned", "user_id", userID)
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

	now := time.Now().UTC()
	if err := s.users.SetBanStatus(ctx, userID, false, nil, now); err != nil {
		s.log.Error("failed to unban user", "err", err, "user_id", userID)
		return domain.NewError("internal_error", "Internal server error", 500)
	}

	s.log.Info("user unbanned", "user_id", userID)
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

	// Prevent demoting the last admin.
	if user.Role == domain.RoleAdmin && role == "user" {
		adminRole := domain.RoleAdmin
		_, total, err := s.users.List(ctx, port.UserFilter{Role: &adminRole, Limit: 1})
		if err != nil {
			s.log.Error("failed to check admin count", "err", err)
			return domain.NewError("internal_error", "Internal server error", 500)
		}
		if total <= 1 {
			s.log.Warn("last admin demotion blocked", "user_id", userID)
			return domain.NewError("last_admin", "Cannot demote the last admin", 400)
		}
	}

	user.Role = domain.Role(role)
	user.UpdatedAt = time.Now().UTC()

	if err := s.users.Update(ctx, user); err != nil {
		s.log.Error("failed to update role", "err", err, "user_id", userID)
		return domain.NewError("internal_error", "Internal server error", 500)
	}

	s.log.Info("user role updated", "user_id", userID, "new_role", role)
	return nil
}

func (s *AdminService) DeleteUser(ctx context.Context, userID string) *domain.AuthError {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	// Prevent deleting the last admin.
	if user.Role == domain.RoleAdmin {
		adminRole := domain.RoleAdmin
		_, total, err := s.users.List(ctx, port.UserFilter{Role: &adminRole, Limit: 1})
		if err != nil {
			s.log.Error("failed to check admin count", "err", err)
			return domain.NewError("internal_error", "Internal server error", 500)
		}
		if total <= 1 {
			s.log.Warn("last admin deletion blocked", "user_id", userID)
			return domain.NewError("last_admin", "Cannot delete the last admin", 400)
		}
	}

	if err := s.sessionSvc.RevokeAll(ctx, userID); err != nil {
		s.log.Error("failed to revoke sessions", "err", err, "user_id", userID)
		return domain.NewError("internal_error", "Internal server error", 500)
	}

	if err := s.users.Delete(ctx, userID); err != nil {
		s.log.Error("failed to delete user", "err", err, "user_id", userID)
		return domain.NewError("internal_error", "Internal server error", 500)
	}

	s.log.Info("user deleted by admin", "user_id", userID)
	return nil
}

func (s *AdminService) RevokeUserSessions(ctx context.Context, userID string) *domain.AuthError {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if err := s.sessionSvc.RevokeAll(ctx, userID); err != nil {
		s.log.Error("failed to revoke sessions", "err", err, "user_id", userID)
		return domain.NewError("internal_error", "Internal server error", 500)
	}

	s.log.Info("user sessions revoked by admin", "user_id", userID)
	return nil
}

func (s *AdminService) CreateUser(ctx context.Context, input CreateUserInput) (*domain.User, *domain.AuthError) {
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))
	if err := validateEmail(input.Email); err != nil {
		return nil, err
	}
	if err := s.config.PasswordPolicy.Validate(input.Password); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.Name) == "" {
		return nil, domain.NewError("name_required", "Name is required", 400)
	}
	input.Name = strings.TrimSpace(input.Name)

	role := domain.RoleUser
	if input.Role == "admin" {
		role = domain.RoleAdmin
	}

	hash, err := s.hasher.Hash(input.Password)
	if err != nil {
		s.log.Error("failed to hash password", "err", err)
		return nil, domain.NewError("internal_error", "Internal server error", 500)
	}

	now := time.Now().UTC()
	user := &domain.User{
		ID:           uuid.New().String(),
		Email:        input.Email,
		PasswordHash: &hash,
		Name:         input.Name,
		Role:         role,
		IsVerified:   true,
		VerifiedAt:   &now,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.users.Create(ctx, user); err != nil {
		if authErr, ok := err.(*domain.AuthError); ok && authErr.Code == "email_already_exists" {
			return nil, authErr
		}
		s.log.Error("failed to create user", "err", err, "email", input.Email)
		return nil, domain.NewError("internal_error", "Internal server error", 500)
	}

	s.log.Info("user created by admin", "user_id", user.ID, "email", user.Email, "role", role)
	return user, nil
}

func (s *AdminService) ListUserSessions(ctx context.Context, input AdminListUserSessionsInput) ([]domain.Session, *domain.AuthError) {
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil || user == nil {
		return nil, domain.ErrUserNotFound
	}

	sessions, err := s.sessions.ListByUserID(ctx, input.UserID)
	if err != nil {
		s.log.Error("failed to list user sessions", "err", err, "user_id", input.UserID)
		return nil, domain.NewError("internal_error", "Internal server error", 500)
	}

	if input.Limit > 0 {
		start := input.Offset
		if start > len(sessions) {
			return []domain.Session{}, nil
		}
		end := start + input.Limit
		if end > len(sessions) {
			end = len(sessions)
		}
		return sessions[start:end], nil
	}

	return sessions, nil
}

func (s *AdminService) RevokeUserSession(ctx context.Context, userID, sessionID string) *domain.AuthError {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	sessions, err := s.sessions.ListByUserID(ctx, userID)
	if err != nil {
		s.log.Error("failed to list user sessions", "err", err, "user_id", userID)
		return domain.NewError("internal_error", "Internal server error", 500)
	}

	found := false
	for _, sess := range sessions {
		if sess.ID == sessionID {
			found = true
			break
		}
	}
	if !found {
		return domain.NewError("session_not_found", "Session not found", 404)
	}

	if err := s.sessions.DeleteByID(ctx, sessionID); err != nil {
		s.log.Error("failed to revoke session", "err", err, "user_id", userID, "session_id", sessionID)
		return domain.NewError("internal_error", "Internal server error", 500)
	}

	s.log.Info("user session revoked by admin", "user_id", userID, "session_id", sessionID)
	return nil
}
