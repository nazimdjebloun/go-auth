package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// ListUsers returns users matching the input filters.
func (s *AdminService) ListUsers(ctx context.Context, input api.AdminListUsersInput) (*api.AdminListUsersResult, error) {
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

	return &api.AdminListUsersResult{
		Users:  users,
		Limit:  limit,
		Offset: input.Offset,
	}, nil
}

// CountUsers returns how many users match the input's filters (pagination and
// ordering are ignored). Split from ListUsers so a paginated UI doesn't pay
// for a COUNT(*) on every page.
func (s *AdminService) CountUsers(ctx context.Context, input api.AdminListUsersInput) (int, error) {
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

// BanUser bans a user.
func (s *AdminService) BanUser(ctx context.Context, input api.BanUserInput) error {
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
	var banned bool
	err = s.users.WithAdminGuard(ctx, func(txCtx context.Context) error {
		var err error
		banned, err = s.users.BanWithAdminGuard(txCtx, input.UserID, true, &now, now)
		if err != nil || !banned {
			return err
		}
		if err := s.sessionSvc.RevokeAll(txCtx, input.UserID); err != nil {
			return err
		}
		if s.audit != nil {
			return s.audit.Record(txCtx, audit.NewAdminEvent(audit.EventAdminUserBanned, input.ActorID, input.UserID))
		}
		return nil
	})
	if err != nil {
		// The guard reports a target that vanished between the initial lookup
		// and the locking read — a concurrent admin deletion, not a failed
		// read. Re-read through this service's repository so an infrastructure
		// failure keeps its cause instead of being flattened to not-found.
		if errors.Is(err, domain.ErrUserNotFound) {
			if _, gerr := s.targetUser(ctx, input.UserID); gerr != nil {
				return gerr
			}
			return domain.ErrUserNotFound
		}
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

	s.log.Info("user banned", "user_id", input.UserID)
	return nil
}

// UnbanUser unbans a user.
func (s *AdminService) UnbanUser(ctx context.Context, input api.UnbanUserInput) error {
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
	// No admin guard here: unbanning only adds a usable admin, so it cannot
	// break the last-usable-admin invariant BanUser serializes on. The audit
	// record still shares the transaction, so an audit failure under
	// fail-closed leaves the account banned rather than silently unbanned.
	apply := func(txCtx context.Context) error {
		if err := s.users.SetBanStatus(txCtx, input.UserID, false, nil, now); err != nil {
			return err
		}
		if s.audit != nil {
			return s.audit.Record(txCtx, audit.NewAdminEvent(audit.EventAdminUserUnbanned, input.ActorID, input.UserID))
		}
		return nil
	}
	if s.txManager != nil {
		err = s.txManager.WithTx(ctx, apply)
	} else {
		err = apply(ctx)
	}
	if err != nil {
		s.log.Error("failed to unban user", "err", err, "user_id", input.UserID)
		return domain.ErrInternal
	}

	s.log.Info("user unbanned", "user_id", input.UserID)
	return nil
}

// UpdateUserRole changes a user's role.
func (s *AdminService) UpdateUserRole(ctx context.Context, input api.UpdateUserRoleInput) error {
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

	// Role change atomically with both the last-usable-admin invariant and
	// its audit record. The outer guard supplies the transaction; the nested
	// DemoteWithAdminGuard call joins it through the guard context.
	var updated bool
	err = s.users.WithAdminGuard(ctx, func(txCtx context.Context) error {
		var err error
		updated, err = s.users.DemoteWithAdminGuard(txCtx, input.UserID, domain.Role(input.Role), time.Now().UTC())
		if err != nil || !updated || s.audit == nil {
			return err
		}
		return s.audit.Record(txCtx, audit.NewRoleChangedEvent(input.ActorID, input.UserID, oldRole, input.Role))
	})
	if err != nil {
		s.log.Error("failed to update role", "err", err, "user_id", input.UserID)
		return err
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
	return nil
}

// DeleteUser deletes a user account.
func (s *AdminService) DeleteUser(ctx context.Context, input api.DeleteUserInput) error {
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
	record := func(txCtx context.Context) error {
		if s.audit == nil {
			return nil
		}
		return s.audit.Record(txCtx, audit.NewAdminEvent(audit.EventAdminUserDeleted, input.ActorID, input.UserID))
	}
	if err := s.deletion.DeleteUserAndRecord(ctx, input.UserID, record); err != nil {
		// The guarded delete can report a vanished target after our initial
		// lookup. Re-read through this service's repository so infrastructure
		// failures are preserved instead of being flattened to user_not_found.
		if errors.Is(err, domain.ErrUserNotFound) {
			if _, lookupErr := s.targetUser(ctx, input.UserID); lookupErr != nil {
				return lookupErr
			}
		}
		s.log.Error("failed to delete user", "err", err, "user_id", input.UserID)
		return err
	}

	s.log.Info("user deleted by admin", "user_id", input.UserID)
	return nil
}

// CreateUser creates a user.
func (s *AdminService) CreateUser(ctx context.Context, input api.CreateUserInput) (*domain.User, error) {
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
		return nil, domain.ErrNameRequired
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
		if err := s.audit.Record(ctx, audit.NewAdminEvent(audit.EventAdminUserCreated, "", user.ID)); err != nil {
			return nil, err
		}
	}

	return user, nil
}

// GetUserDetail returns a user's administrative details.
func (s *AdminService) GetUserDetail(ctx context.Context, input api.GetUserDetailInput) (*api.AdminUserDetail, error) {
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

	return &api.AdminUserDetail{
		User:               *user,
		ActiveSessionCount: activeSessionCount,
		HasPassword:        user.HasPassword(),
		Providers:          providers,
	}, nil
}
