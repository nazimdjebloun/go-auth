package service

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type AdminService struct {
	users      port.UserRepository
	sessions   port.SessionRepository
	providers  port.ProviderAccountRepository
	hasher     port.Hasher
	config     Config
	sessionSvc *SessionService
	log        *slog.Logger
	audit      AuditPublisher
}

func NewAdminService(
	users port.UserRepository,
	sessions port.SessionRepository,
	providers port.ProviderAccountRepository,
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
		providers:  providers,
		hasher:     hasher,
		config:     config,
		sessionSvc: sessionSvc,
		log:        config.Logger,
		audit:      config.Audit,
	}
}

// requireAdmin verifies actorID is a current, non-banned admin. Every other
// exported AdminService method calls this first — the HTTP layer's
// RequireRole(domain.RoleAdmin) middleware pre-checks the same thing, but
// this is the real authority: it also protects the "call it without HTTP"
// path the root package advertises (auth.Services.Admin.BanUser(ctx, ...)),
// which has no middleware in front of it at all.
func (s *AdminService) requireAdmin(ctx context.Context, actorID string) error {
	if actorID == "" {
		return domain.ErrForbidden
	}
	actor, err := s.users.GetByID(ctx, actorID)
	if err != nil {
		return err
	}
	if actor == nil || actor.Role != domain.RoleAdmin {
		return domain.ErrForbidden
	}
	return nil
}

func (s *AdminService) ListUsers(ctx context.Context, input AdminListUsersInput) (*AdminListUsersResult, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, err
	}
	limit := input.Limit
	if limit <= 0 {
		limit = 20
	} else if limit > 100 {
		limit = 100
	}
	filter := port.UserFilter{
		Email:          input.Email,
		Role:           input.Role,
		Offset:         input.Offset,
		Limit:          limit,
		Search:         input.Search,
		OrderBy:        input.OrderBy,
		OrderDirection: input.OrderDirection,
	}

	users, total, err := s.users.List(ctx, filter)
	if err != nil {
		s.log.Error("failed to list users", "err", err)
		return nil, domain.ErrInternal
	}

	if users == nil {
		users = []domain.User{}
	}

	return &AdminListUsersResult{
		Users:  users,
		Total:  total,
		Limit:  limit,
		Offset: input.Offset,
	}, nil
}

type BanUserInput struct {
	UserID  string
	ActorID string
}

func (s *AdminService) BanUser(ctx context.Context, input BanUserInput) error {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return err
	}
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if user.IsBanned {
		return domain.NewError("already_banned", "User is already banned")
	}

	// Prevent banning the last admin.
	if user.Role == domain.RoleAdmin {
		adminRole := domain.RoleAdmin
		_, total, err := s.users.List(ctx, port.UserFilter{Role: &adminRole, Limit: 1})
		if err != nil {
			s.log.Error("failed to check admin count", "err", err)
			return domain.ErrInternal
		}
		if total <= 1 {
			s.log.Warn("last admin ban blocked", "user_id", input.UserID)
			return domain.NewError("last_admin", "Cannot ban the last admin")
		}
	}

	now := time.Now().UTC()
	if err := s.users.SetBanStatus(ctx, input.UserID, true, &now, now); err != nil {
		s.log.Error("failed to ban user", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	if err := s.sessionSvc.RevokeAll(ctx, input.UserID); err != nil {
		s.log.Error("failed to revoke sessions after ban", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	s.log.Info("user banned", "user_id", input.UserID)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewAdminEvent(audit.EventAdminUserBanned, "", input.UserID))
	}

	return nil
}

type UnbanUserInput struct {
	UserID  string
	ActorID string
}

func (s *AdminService) UnbanUser(ctx context.Context, input UnbanUserInput) error {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return err
	}
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if !user.IsBanned {
		return domain.NewError("not_banned", "User is not banned")
	}

	now := time.Now().UTC()
	if err := s.users.SetBanStatus(ctx, input.UserID, false, nil, now); err != nil {
		s.log.Error("failed to unban user", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	s.log.Info("user unbanned", "user_id", input.UserID)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewAdminEvent(audit.EventAdminUserUnbanned, "", input.UserID))
	}

	return nil
}

type UpdateUserRoleInput struct {
	UserID  string
	Role    string
	ActorID string
}

func (s *AdminService) UpdateUserRole(ctx context.Context, input UpdateUserRoleInput) error {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return err
	}
	if input.Role != "user" && input.Role != "admin" {
		return domain.NewError("invalid_role", "Role must be 'user' or 'admin'")
	}

	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	// Prevent demoting the last admin.
	if user.Role == domain.RoleAdmin && input.Role == "user" {
		adminRole := domain.RoleAdmin
		_, total, err := s.users.List(ctx, port.UserFilter{Role: &adminRole, Limit: 1})
		if err != nil {
			s.log.Error("failed to check admin count", "err", err)
			return domain.ErrInternal
		}
		if total <= 1 {
			s.log.Warn("last admin demotion blocked", "user_id", input.UserID)
			return domain.NewError("last_admin", "Cannot demote the last admin")
		}
	}

	user.Role = domain.Role(input.Role)
	user.UpdatedAt = time.Now().UTC()

	if err := s.users.Update(ctx, user); err != nil {
		s.log.Error("failed to update role", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	s.log.Info("user role updated", "user_id", input.UserID, "new_role", input.Role)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewRoleChangedEvent("", input.UserID, string(user.Role), input.Role))
	}

	return nil
}

type DeleteUserInput struct {
	UserID  string
	ActorID string
}

func (s *AdminService) DeleteUser(ctx context.Context, input DeleteUserInput) error {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return err
	}
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	// Prevent deleting the last admin.
	if user.Role == domain.RoleAdmin {
		adminRole := domain.RoleAdmin
		_, total, err := s.users.List(ctx, port.UserFilter{Role: &adminRole, Limit: 1})
		if err != nil {
			s.log.Error("failed to check admin count", "err", err)
			return domain.ErrInternal
		}
		if total <= 1 {
			s.log.Warn("last admin deletion blocked", "user_id", input.UserID)
			return domain.NewError("last_admin", "Cannot delete the last admin")
		}
	}

	if err := s.sessionSvc.RevokeAll(ctx, input.UserID); err != nil {
		s.log.Error("failed to revoke sessions", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	if err := s.users.Delete(ctx, input.UserID); err != nil {
		s.log.Error("failed to delete user", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	s.log.Info("user deleted by admin", "user_id", input.UserID)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewAdminEvent(audit.EventAdminUserDeleted, "", input.UserID))
	}

	return nil
}

type RevokeUserSessionsInput struct {
	UserID  string
	ActorID string
}

func (s *AdminService) RevokeUserSessions(ctx context.Context, input RevokeUserSessionsInput) error {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return err
	}
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if err := s.sessionSvc.RevokeAll(ctx, input.UserID); err != nil {
		s.log.Error("failed to revoke sessions", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	s.log.Info("user sessions revoked by admin", "user_id", input.UserID)
	return nil
}

func (s *AdminService) CreateUser(ctx context.Context, input CreateUserInput) (*domain.User, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, err
	}
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))
	if err := validateEmail(input.Email); err != nil {
		return nil, err
	}
	if err := s.config.PasswordPolicy.Validate(input.Password); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.Name) == "" {
		return nil, domain.NewError("name_required", "Name is required")
	}
	input.Name = strings.TrimSpace(input.Name)

	role := domain.RoleUser
	if input.Role == "admin" {
		role = domain.RoleAdmin
	}

	hash, err := s.hasher.Hash(input.Password)
	if err != nil {
		s.log.Error("failed to hash password", "err", err)
		return nil, domain.ErrInternal
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
		var authErr *domain.AuthError
		if errors.As(err, &authErr) && authErr.Code == "email_already_exists" {
			return nil, authErr
		}
		s.log.Error("failed to create user", "err", err, "email", input.Email)
		return nil, domain.ErrInternal
	}

	s.log.Info("user created by admin", "user_id", user.ID, "email", user.Email, "role", role)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewAdminEvent(audit.EventAdminUserCreated, "", user.ID))
	}

	return user, nil
}

func (s *AdminService) ListUserSessions(ctx context.Context, input AdminListUserSessionsInput) ([]domain.Session, int, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, 0, err
	}
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil || user == nil {
		return nil, 0, domain.ErrUserNotFound
	}

	sessions, total, err := s.sessions.ListByUserID(ctx, input.UserID, input.Offset, input.Limit)
	if err != nil {
		s.log.Error("failed to list user sessions", "err", err, "user_id", input.UserID)
		return nil, 0, domain.ErrInternal
	}

	return sessions, total, nil
}

type RevokeUserSessionInput struct {
	UserID    string
	SessionID string
	ActorID   string
}

func (s *AdminService) RevokeUserSession(ctx context.Context, input RevokeUserSessionInput) error {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return err
	}
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	revoked, err := s.sessions.RevokeByIDForUser(ctx, input.SessionID, input.UserID)
	if err != nil {
		s.log.Error("failed to revoke session", "err", err, "user_id", input.UserID, "session_id", input.SessionID)
		return domain.ErrInternal
	}
	if !revoked {
		return domain.NewError("session_not_found", "Session not found")
	}

	s.log.Info("user session revoked by admin", "user_id", input.UserID, "session_id", input.SessionID)
	return nil
}

type AdminUserDetail struct {
	User               domain.User              `json:"user"`
	ActiveSessionCount int                      `json:"activeSessionCount"`
	Providers          []domain.ProviderAccount `json:"providers"`
}

type GetUserDetailInput struct {
	UserID  string
	ActorID string
}

func (s *AdminService) GetUserDetail(ctx context.Context, input GetUserDetailInput) (*AdminUserDetail, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, err
	}
	user, err := s.users.GetByID(ctx, input.UserID)
	if err != nil || user == nil {
		return nil, domain.ErrUserNotFound
	}

	_, activeSessionCount, err := s.sessions.ListByUserID(ctx, input.UserID, 0, 1)
	if err != nil {
		s.log.Error("failed to count sessions", "err", err, "user_id", input.UserID)
		return nil, domain.ErrInternal
	}

	providers, err := s.providers.ListByUserID(ctx, input.UserID)
	if err != nil {
		s.log.Error("failed to list providers", "err", err, "user_id", input.UserID)
		return nil, domain.ErrInternal
	}

	return &AdminUserDetail{
		User:               *user,
		ActiveSessionCount: activeSessionCount,
		Providers:          providers,
	}, nil
}
