package service

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type AdminService struct {
	users    port.UserRepository
	sessions port.SessionRepository
	hasher   port.Hasher
	config   Config
}

func NewAdminService(
	users port.UserRepository,
	sessions port.SessionRepository,
	hasher port.Hasher,
	config Config,
) *AdminService {
	return &AdminService{
		users:    users,
		sessions: sessions,
		hasher:   hasher,
		config:   config,
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
		return nil, domain.NewError("internal_error", "Failed to list users", 500)
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

	existing, _ := s.users.GetByEmail(ctx, input.Email)
	if existing != nil {
		return nil, domain.ErrEmailAlreadyExists
	}

	hash, err := s.hasher.Hash(input.Password)
	if err != nil {
		return nil, domain.NewError("internal_error", "Failed to hash password", 500)
	}

	role := domain.RoleUser
	if input.Role == "admin" {
		role = domain.RoleAdmin
	}

	now := time.Now().UTC()
	user := &domain.User{
		ID:           uuid.New().String(),
		Email:        input.Email,
		PasswordHash: hash,
		Name:         input.Name,
		Role:         role,
		IsVerified:   true,
		VerifiedAt:   &now,
		IsBanned:     false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.users.Create(ctx, user); err != nil {
		return nil, domain.NewError("internal_error", "Failed to create user", 500)
	}

	return user, nil
}

func (s *AdminService) ListUserSessions(ctx context.Context, input AdminListUserSessionsInput) ([]domain.Session, *domain.AuthError) {
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil || user == nil {
		return nil, domain.ErrUserNotFound
	}

	limit := input.Limit
	if limit <= 0 || limit > 100 {
		limit = 20
	}

	sessions, err := s.sessions.ListByUserID(ctx, input.UserID)
	if err != nil {
		return nil, domain.NewError("internal_error", "Failed to list sessions", 500)
	}

	if sessions == nil {
		sessions = []domain.Session{}
	}

	// Apply offset/limit
	offset := input.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= len(sessions) {
		return []domain.Session{}, nil
	}
	end := offset + limit
	if end > len(sessions) {
		end = len(sessions)
	}

	return sessions[offset:end], nil
}

func (s *AdminService) RevokeUserSession(ctx context.Context, userID, sessionID string) *domain.AuthError {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	sessions, err := s.sessions.ListByUserID(ctx, userID)
	if err != nil {
		return domain.NewError("internal_error", "Failed to list sessions", 500)
	}

	found := false
	for _, sess := range sessions {
		if sess.ID == sessionID {
			found = true
			break
		}
	}
	if !found {
		return domain.NewError("session_not_found", "Session not found for this user", 404)
	}

	if err := s.sessions.DeleteByID(ctx, sessionID); err != nil {
		return domain.NewError("internal_error", "Failed to revoke session", 500)
	}

	return nil
}
