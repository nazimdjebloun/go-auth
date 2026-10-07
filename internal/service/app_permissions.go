package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// AppPermissionsService owns current-role authorization and transactional management.
type AppPermissionsService struct {
	permissions port.AppPermissionReader
	definitions port.AppPermissionWriter
	roles       port.AppRoleStore
	state       port.AppAuthorizationState
	users       port.UserRepository
	sessions    port.SessionIdentityReader
	sessionSvc  *SessionService
	tx          port.TxManager
	config      AppPermissionsServiceConfig
}

// AppPermissionsServiceConfig retains security policy outside mutable definitions.
type AppPermissionsServiceConfig struct {
	DefaultRoleSlug       string
	RequireAdminTwoFactor bool
	Audit                 AuditPublisher
}

// NewAppPermissionsService reuses SQL transaction, session and audit dependencies.
func NewAppPermissionsService(tx port.TxManager, users port.UserRepository, sessions port.SessionIdentityReader, sessionSvc *SessionService, permissions port.AppPermissionReader, definitions port.AppPermissionWriter, roles port.AppRoleStore, state port.AppAuthorizationState, cfg AppPermissionsServiceConfig) *AppPermissionsService {
	requireTxManager(tx)
	if cfg.DefaultRoleSlug == "" {
		cfg.DefaultRoleSlug = "user"
	}
	return &AppPermissionsService{tx: tx, users: users, sessions: sessions, sessionSvc: sessionSvc, permissions: permissions, definitions: definitions, roles: roles, state: state, config: cfg}
}

var appKeyPattern = regexp.MustCompile(`^(app|goauth\.app)\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
var appSlugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,79}$`)

type appManagementContextKey struct{}

func validateAppKey(key string) error {
	if len(key) > 160 || !appKeyPattern.MatchString(key) {
		return domain.ErrInvalidPermissionKey
	}
	return nil
}

func appInvalid(message string) error { return domain.NewError("invalid_input", message) }

func validateAppID(id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return appInvalid("Expected a UUID identifier")
	}
	return nil
}

func validateAppMetadata(name, description string) error {
	if !utf8.ValidString(name) || !utf8.ValidString(description) || strings.TrimSpace(name) == "" || utf8.RuneCountInString(name) > 120 || len(description) > 4096 {
		return appInvalid("Name is required (maximum 120 characters); description maximum is 4096 bytes")
	}
	return nil
}

func appPage(limit, offset int) (int, error) {
	if limit < 0 || limit > 100 || offset < 0 {
		return 0, appInvalid("Limit must be 0..100 and offset nonnegative")
	}
	if limit == 0 {
		limit = 20
	}
	return limit, nil
}

func (s *AppPermissionsService) current(ctx context.Context, userID string) (*domain.User, *domain.AppRole, error) {
	if userID == "" {
		return nil, nil, domain.ErrForbidden
	}
	var user *domain.User
	var err error
	if ctx.Value(appManagementContextKey{}) != nil {
		user, err = s.users.GetByIDForUpdate(ctx, userID)
	} else {
		user, err = s.users.GetByID(ctx, userID)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("loading permission actor: %w", err)
	}
	if user == nil || user.IsBanned || user.AppRoleID == nil {
		return nil, nil, domain.ErrForbidden
	}
	role, err := s.roles.RoleByID(ctx, *user.AppRoleID)
	if err != nil {
		return nil, nil, fmt.Errorf("loading actor role: %w", err)
	}
	if role == nil || !role.IsEnabled {
		return nil, nil, domain.ErrForbidden
	}
	return user, role, nil
}

func (s *AppPermissionsService) assurance(ctx context.Context, actor api.AppPermissionActor, user *domain.User, privileged bool) error {
	requireSecondFactor := privileged && (s.config.RequireAdminTwoFactor || user.TwoFactorEnabled)
	if actor.SessionID == "" {
		if requireSecondFactor {
			return domain.ErrTwoFactorRequired
		}
		return nil
	}
	if s.sessions == nil || s.sessionSvc == nil {
		return domain.ErrForbidden
	}
	session, err := s.sessions.GetByID(ctx, actor.SessionID)
	if err != nil {
		return fmt.Errorf("loading permission actor session: %w", err)
	}
	if session == nil || session.UserID != user.ID {
		return domain.ErrForbidden
	}
	if err := s.sessionSvc.checkSession(session); err != nil {
		return err
	}
	if requireSecondFactor && (session.TwoFactorVerifiedAt == nil || session.TwoFactorVerifiedAt.IsZero()) {
		return domain.ErrTwoFactorRequired
	}
	return nil
}

// IsProtectedAdmin resolves identity without delegable permission or session checks.
// Runtime privileged operations must additionally verify their session assurance.
func (s *AppPermissionsService) IsProtectedAdmin(ctx context.Context, userID string) (bool, error) {
	_, role, err := s.current(ctx, userID)
	if errors.Is(err, domain.ErrForbidden) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return role.IsAdmin(), nil
}

// HasAdministrativeAccess drives MFA using current installed library grants.
func (s *AppPermissionsService) HasAdministrativeAccess(ctx context.Context, userID string) (bool, error) {
	_, role, err := s.current(ctx, userID)
	if errors.Is(err, domain.ErrForbidden) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if role.IsAdmin() {
		return true, nil
	}
	keys, err := s.permissions.RolePermissionKeys(ctx, role.ID)
	if err != nil {
		return false, err
	}
	for _, key := range keys {
		if _, known := appLibraryDefinition(key); known {
			return true, nil
		}
	}
	return false, nil
}

// CheckPermission distinguishes installed delegation from fixed library admin access.
func (s *AppPermissionsService) CheckPermission(ctx context.Context, input api.CheckAppPermissionInput) (*api.AppPermissionDecision, error) {
	if err := validateAppKey(input.PermissionKey); err != nil {
		return nil, err
	}
	user, role, err := s.current(ctx, input.Actor.UserID)
	if errors.Is(err, domain.ErrForbidden) {
		return &api.AppPermissionDecision{}, nil
	}
	if err != nil {
		return nil, err
	}
	library := strings.HasPrefix(input.PermissionKey, "goauth.app.")
	if err := s.assurance(ctx, input.Actor, user, library); err != nil {
		return nil, err
	}
	if library {
		if _, known := appLibraryDefinition(input.PermissionKey); !known {
			return &api.AppPermissionDecision{}, nil
		}
		if role.IsAdmin() {
			return &api.AppPermissionDecision{Allowed: true}, nil
		}
	}
	p, err := s.permissions.PermissionByKey(ctx, input.PermissionKey)
	if err != nil {
		return nil, fmt.Errorf("loading permission definition: %w", err)
	}
	if p == nil || !p.IsEnabled || p.IsSystem != library {
		return &api.AppPermissionDecision{}, nil
	}
	if role.IsAdmin() {
		return &api.AppPermissionDecision{Allowed: true}, nil
	}
	keys, err := s.permissions.RolePermissionKeys(ctx, role.ID)
	if err != nil {
		return nil, fmt.Errorf("loading role grants: %w", err)
	}
	return &api.AppPermissionDecision{Allowed: slices.Contains(keys, input.PermissionKey)}, nil
}

// RequirePermission returns forbidden on denial and preserves infrastructure failures.
func (s *AppPermissionsService) RequirePermission(ctx context.Context, input api.CheckAppPermissionInput) error {
	decision, err := s.CheckPermission(ctx, input)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return domain.ErrForbidden
	}
	return nil
}

func (s *AppPermissionsService) require(ctx context.Context, actor api.AppPermissionActor, key string) error {
	return s.RequirePermission(ctx, api.CheckAppPermissionInput{Actor: actor, PermissionKey: key})
}

func (s *AppPermissionsService) requireProtectedAdmin(ctx context.Context, actor api.AppPermissionActor, checkAssurance bool) error {
	user, role, err := s.current(ctx, actor.UserID)
	if err != nil {
		return err
	}
	if !role.IsAdmin() {
		return domain.ErrForbidden
	}
	if checkAssurance {
		return s.assurance(ctx, actor, user, true)
	}
	return nil
}

// withMutation shares the existing all-user admin guard before taking app state.
// This also serializes demotion/ban/deletion with actor authorization rechecks.
func (s *AppPermissionsService) withMutation(ctx context.Context, actor api.AppPermissionActor, key string, fn func(context.Context) error) error {
	return s.users.WithAdminGuard(ctx, func(ctx context.Context) error {
		if err := s.state.LockAppState(ctx); err != nil {
			return err
		}
		ctx = context.WithValue(ctx, appManagementContextKey{}, true)
		if err := s.require(ctx, actor, key); err != nil {
			return err
		}
		if err := fn(ctx); err != nil {
			return err
		}
		return s.state.BumpAppState(ctx)
	})
}

func (s *AppPermissionsService) record(ctx context.Context, actor api.AppPermissionActor, typ audit.EventType, metadata map[string]any) error {
	if s.config.Audit == nil {
		return nil
	}
	e := audit.NewEvent(typ, audit.WithActor(actor.UserID), audit.WithSession(actor.SessionID))
	e.Success = true
	e.Metadata = metadata
	return s.config.Audit.Record(ctx, e)
}

// LibraryPermissionCatalog exposes a defensive copy without accessing storage.
func (s *AppPermissionsService) LibraryPermissionCatalog() []domain.AppLibraryPermissionDefinition {
	return AppLibraryPermissionCatalog()
}

// ListEffectivePermissions is informational; current backend checks remain mandatory.
func (s *AppPermissionsService) ListEffectivePermissions(ctx context.Context, input api.ListAppEffectivePermissionsInput) (*api.AppAccess, error) {
	target := input.UserID
	if target == "" {
		target = input.Actor.UserID
	}
	actor, _, err := s.current(ctx, input.Actor.UserID)
	if err != nil {
		return nil, err
	}
	if err := s.assurance(ctx, input.Actor, actor, false); err != nil {
		return nil, err
	}
	if target != input.Actor.UserID {
		if err := s.require(ctx, input.Actor, "goauth.app.roles.read"); err != nil {
			return nil, err
		}
	}
	user, role, err := s.current(ctx, target)
	if err != nil {
		return nil, err
	}
	keys, err := s.permissions.RolePermissionKeys(ctx, role.ID)
	if err != nil {
		return nil, err
	}
	if role.IsAdmin() {
		keys, err = s.permissions.EnabledBusinessPermissionKeys(ctx)
		if err != nil {
			return nil, err
		}
		for _, d := range appLibraryCatalog {
			keys = append(keys, d.Key)
		}
		slices.Sort(keys)
	}
	revision, err := s.state.AppStateRevision(ctx)
	if err != nil {
		return nil, err
	}
	return &api.AppAccess{Role: *role, IsFullAccess: role.IsAdmin(), PermissionKeys: keys, AssignmentRevision: user.AppRoleAssignmentRevision, Revision: revision}, nil
}
