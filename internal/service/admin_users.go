package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

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
		Email:            input.Email,
		Role:             input.Role,
		IsBanned:         input.IsBanned,
		IsVerified:       input.IsVerified,
		TwoFactorEnabled: input.TwoFactorEnabled,
		NeverLoggedIn:    input.NeverLoggedIn,
		LastLoginBefore:  input.LastLoginBefore,
		Offset:           input.Offset,
		Limit:            limit,
		Search:           input.Search,
		OrderBy:          input.OrderBy,
		OrderDirection:   input.OrderDirection,
	}

	users, err := s.users.List(ctx, filter)
	if err != nil {
		s.log.Error("failed to list users", "err", err)
		return nil, domain.ErrInternal
	}

	return &AdminListUsersResult{
		Users:  users,
		Limit:  limit,
		Offset: input.Offset,
	}, nil
}

// CountUsers returns how many users match the input's filters (pagination and
// ordering are ignored). Split from ListUsers so a paginated UI doesn't pay
// for a COUNT(*) on every page.
func (s *AdminService) CountUsers(ctx context.Context, input AdminListUsersInput) (int, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return 0, err
	}
	n, err := s.users.Count(ctx, port.UserFilter{
		Email:            input.Email,
		Role:             input.Role,
		IsBanned:         input.IsBanned,
		IsVerified:       input.IsVerified,
		TwoFactorEnabled: input.TwoFactorEnabled,
		NeverLoggedIn:    input.NeverLoggedIn,
		LastLoginBefore:  input.LastLoginBefore,
		Search:           input.Search,
	})
	if err != nil {
		s.log.Error("failed to count users", "err", err)
		return 0, domain.ErrInternal
	}
	return n, nil
}

// maxStatsRangeDays caps every date-range analytics query (registration
// trend, login activity) the same way Limit is capped at 100 elsewhere —
// defense against an admin (or a compromised admin session) requesting an
// unbounded aggregation.
const maxStatsRangeDays = 400

// AdminStats is a snapshot of platform-wide counts for an admin dashboard.
type AdminStats struct {
	TotalUsers            int `json:"totalUsers"`
	VerifiedUsers         int `json:"verifiedUsers"`
	BannedUsers           int `json:"bannedUsers"`
	TwoFactorEnabledUsers int `json:"twoFactorEnabledUsers"`
	NeverLoggedInUsers    int `json:"neverLoggedInUsers"`
	ActiveSessions        int `json:"activeSessions"`
}

type BanUserInput struct {
	UserID  string
	ActorID string
}

func (s *AdminService) BanUser(ctx context.Context, input BanUserInput) error {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return err
	}
	user, err := s.targetUser(ctx, input.UserID)
	if err != nil {
		return err
	}

	if user.IsBanned {
		return domain.NewError("already_banned", "User is already banned")
	}

	now := time.Now().UTC()
	// Ban atomically with the last-usable-admin invariant. The guard is
	// part of the UserRepository contract, so there is no count-then-write
	// path — a count cannot serialize against a concurrent demotion.
	banned, err := s.users.BanWithAdminGuard(ctx, input.UserID, true, &now, now)
	if err != nil {
		s.log.Error("failed to ban user", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}
	if !banned {
		_, gerr := s.targetUser(ctx, input.UserID)
		if gerr != nil {
			return gerr
		}
		s.log.Warn("last usable admin ban blocked", "user_id", input.UserID)
		return domain.NewError("last_admin", "Cannot ban the last admin")
	}

	if err := s.sessionSvc.RevokeAll(ctx, input.UserID); err != nil {
		s.log.Error("failed to revoke sessions after ban", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	s.log.Info("user banned", "user_id", input.UserID)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewAdminEvent(audit.EventAdminUserBanned, input.ActorID, input.UserID))
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
	user, err := s.targetUser(ctx, input.UserID)
	if err != nil {
		return err
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
		s.audit.Publish(ctx, audit.NewAdminEvent(audit.EventAdminUserUnbanned, input.ActorID, input.UserID))
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

	user, err := s.targetUser(ctx, input.UserID)
	if err != nil {
		return err
	}

	// Snapshot the old role before mutating: the event must report the
	// transition, not read the already-updated struct.
	oldRole := string(user.Role)

	// Role change atomically with the last-usable-admin invariant. The guard
	// is part of the UserRepository contract — no count-then-write path.
	updated, err := s.users.DemoteWithAdminGuard(ctx, input.UserID, domain.Role(input.Role), time.Now().UTC())
	if err != nil {
		s.log.Error("failed to update role", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}
	if !updated {
		_, gerr := s.targetUser(ctx, input.UserID)
		if gerr != nil {
			return gerr
		}
		s.log.Warn("last usable admin demotion blocked", "user_id", input.UserID)
		return domain.NewError("last_admin", "Cannot demote the last admin")
	}
	user.Role = domain.Role(input.Role)
	user.UpdatedAt = time.Now().UTC()

	s.log.Info("user role updated", "user_id", input.UserID, "new_role", input.Role)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewRoleChangedEvent(input.ActorID, input.UserID, oldRole, input.Role))
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
	if _, err := s.targetUser(ctx, input.UserID); err != nil {
		return err
	}

	// Account deletion requires the coordinator: one transaction unwinding
	// org memberships with counter upkeep, session revocation, and the
	// last-usable-admin guard. The library wiring always attaches it; a
	// nil coordinator means a miswired service, which fails closed.
	if s.deletion == nil {
		s.log.Error("admin user deletion refused: no deletion coordinator attached", "user_id", input.UserID)
		return domain.ErrInternal
	}
	if err := s.deletion.DeleteUser(ctx, input.UserID); err != nil {
		s.log.Error("failed to delete user", "err", err, "user_id", input.UserID)
		return err
	}

	s.log.Info("user deleted by admin", "user_id", input.UserID)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewAdminEvent(audit.EventAdminUserDeleted, input.ActorID, input.UserID))
	}

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

	hash, pepperVersion, err := hashPassword(s.hasher, input.Password)
	if err != nil {
		s.log.Error("failed to hash password", "err", err)
		return nil, domain.ErrInternal
	}

	now := time.Now().UTC()
	user := &domain.User{
		ID:                    uuid.New().String(),
		Email:                 input.Email,
		PasswordHash:          &hash,
		PasswordPepperVersion: pepperVersion,
		Name:                  input.Name,
		Role:                  role,
		IsVerified:            true,
		VerifiedAt:            &now,
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	if err := s.users.Create(ctx, user); err != nil {
		if errors.Is(err, port.ErrDuplicateKey) {
			return nil, domain.ErrEmailAlreadyExists
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

type AdminUserDetail struct {
	User               domain.User `json:"user"`
	ActiveSessionCount int         `json:"activeSessionCount"`
	// HasPassword is whether the account can sign in with a password at all —
	// false for an OAuth-only account that never set one. The hash itself is
	// never exposed (domain.User.PasswordHash is json:"-").
	HasPassword bool                     `json:"hasPassword"`
	Providers   []domain.ProviderAccount `json:"providers"`
}

type GetUserDetailInput struct {
	UserID  string
	ActorID string
}

func (s *AdminService) GetUserDetail(ctx context.Context, input GetUserDetailInput) (*AdminUserDetail, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, err
	}
	user, err := s.targetUser(ctx, input.UserID)
	if err != nil {
		return nil, err
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
		HasPassword:        user.HasPassword(),
		Providers:          providers,
	}, nil
}
