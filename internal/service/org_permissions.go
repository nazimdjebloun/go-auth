package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// OrgPermissionsService evaluates live, organization-scoped authorization.
type OrgPermissionsService struct {
	permissions port.OrgPermissionReader
	definitions port.OrgPermissionWriter
	roles       port.OrgPermissionRoleStore
	state       port.OrgAuthorizationState
	orgs        port.OrgRepository
	users       port.UserRepository
	sessions    port.SessionIdentityReader
	sessionSvc  *SessionService
	orgSvc      *OrgService
	config      OrgPermissionsServiceConfig
}

// OrgPermissionsServiceConfig preserves authentication policy outside role grants.
type OrgPermissionsServiceConfig struct {
	RequireUserTwoFactor bool
	Audit                AuditPublisher
}

// NewOrgPermissionsService shares existing transaction, membership and session stores.
func NewOrgPermissionsService(users port.UserRepository, orgs port.OrgRepository, sessions port.SessionIdentityReader, sessionSvc *SessionService, permissions port.OrgPermissionReader, definitions port.OrgPermissionWriter, roles port.OrgPermissionRoleStore, state port.OrgAuthorizationState, cfg OrgPermissionsServiceConfig) *OrgPermissionsService {
	return &OrgPermissionsService{users: users, orgs: orgs, sessions: sessions, sessionSvc: sessionSvc, permissions: permissions, definitions: definitions, roles: roles, state: state, config: cfg}
}

var orgKeyPattern = regexp.MustCompile(`^(org|goauth\.org)\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
var orgSlugPattern = appSlugPattern

type orgManagementContextKey struct{}

func validateOrgKey(key string) error {
	if len(key) > 160 || !orgKeyPattern.MatchString(key) {
		return domain.ErrInvalidPermissionKey
	}
	return nil
}
func validateOrgID(id string) error { return validateAppID(id) }
func validateOrgMetadata(name, description string) error {
	return validateAppMetadata(name, description)
}
func orgInvalid(message string) error        { return appInvalid(message) }
func orgPage(limit, offset int) (int, error) { return appPage(limit, offset) }

func (s *OrgPermissionsService) current(ctx context.Context, actor api.OrgPermissionActor) (*domain.User, *domain.OrgPermissionRole, error) {
	if actor.UserID == "" {
		return nil, nil, domain.ErrOrgForbidden
	}
	if err := validateOrgID(actor.OrgID); err != nil {
		return nil, nil, err
	}
	var user *domain.User
	var err error
	if ctx.Value(orgManagementContextKey{}) != nil {
		user, err = s.users.GetByIDForUpdate(ctx, actor.UserID)
	} else {
		user, err = s.users.GetByID(ctx, actor.UserID)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("loading org permission actor: %w", err)
	}
	if user == nil || user.IsBanned {
		return nil, nil, domain.ErrOrgForbidden
	}
	var member *domain.OrgMember
	if ctx.Value(orgManagementContextKey{}) != nil {
		member, err = s.orgs.LockMembership(ctx, actor.OrgID, actor.UserID)
	} else {
		member, err = s.orgs.GetMembership(ctx, actor.OrgID, actor.UserID)
	}
	if err != nil {
		return nil, nil, err
	}
	if member == nil {
		return nil, nil, domain.ErrOrgMemberNotFound
	}
	role, _, err := s.memberRole(ctx, member)
	if err != nil {
		return nil, nil, err
	}
	if !role.IsEnabled {
		return nil, nil, domain.ErrOrgForbidden
	}
	// The fixed classification remains the authority for owner counters and
	// ownership transitions. A custom role cannot masquerade as an owner.
	if !orgRoleMatchesMembership(role, member) {
		return nil, nil, domain.ErrOrgForbidden
	}
	return user, role, nil
}

func (s *OrgPermissionsService) assurance(ctx context.Context, actor api.OrgPermissionActor, user *domain.User) error {
	required := s.config.RequireUserTwoFactor || user.TwoFactorEnabled
	if actor.SessionID == "" {
		if required {
			return domain.ErrTwoFactorRequired
		}
		return nil
	}
	if s.sessions == nil || s.sessionSvc == nil {
		return domain.ErrOrgForbidden
	}
	session, err := s.sessions.GetByID(ctx, actor.SessionID)
	if err != nil {
		return fmt.Errorf("loading org actor session: %w", err)
	}
	if session == nil || session.UserID != user.ID {
		return domain.ErrOrgForbidden
	}
	if err := s.sessionSvc.checkSession(session); err != nil {
		return err
	}
	if required && (session.TwoFactorVerifiedAt == nil || session.TwoFactorVerifiedAt.IsZero()) {
		return domain.ErrTwoFactorRequired
	}
	return nil
}

// CheckPermission separates denial from database and authentication failures.
func (s *OrgPermissionsService) CheckPermission(ctx context.Context, input api.CheckOrgPermissionInput) (*api.OrgPermissionDecision, error) {
	if err := validateOrgKey(input.PermissionKey); err != nil {
		return nil, err
	}
	user, role, err := s.current(ctx, input.Actor)
	if errors.Is(err, domain.ErrOrgForbidden) {
		return &api.OrgPermissionDecision{}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := s.assurance(ctx, input.Actor, user); err != nil {
		return nil, err
	}
	library := strings.HasPrefix(input.PermissionKey, "goauth.org.")
	if library {
		if _, known := orgLibraryDefinition(input.PermissionKey); !known {
			return &api.OrgPermissionDecision{}, nil
		}
		if role.SystemKey != nil {
			return &api.OrgPermissionDecision{Allowed: role.IsOwner() || slices.Contains(orgPreset(*role.SystemKey), input.PermissionKey)}, nil
		}
	}
	p, err := s.permissions.PermissionByKey(ctx, input.Actor.OrgID, input.PermissionKey)
	if err != nil {
		return nil, err
	}
	if p == nil || !p.IsEnabled || p.IsSystem != library {
		return &api.OrgPermissionDecision{}, nil
	}
	if role.IsOwner() {
		return &api.OrgPermissionDecision{Allowed: true}, nil
	}
	keys, err := s.permissions.RolePermissionKeys(ctx, input.Actor.OrgID, role.ID)
	if err != nil {
		return nil, err
	}
	return &api.OrgPermissionDecision{Allowed: slices.Contains(keys, input.PermissionKey)}, nil
}

// RequirePermission fails closed while retaining infrastructure errors.
func (s *OrgPermissionsService) RequirePermission(ctx context.Context, input api.CheckOrgPermissionInput) error {
	decision, err := s.CheckPermission(ctx, input)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return domain.ErrOrgForbidden
	}
	return nil
}
func (s *OrgPermissionsService) require(ctx context.Context, actor api.OrgPermissionActor, key string) error {
	return s.RequirePermission(ctx, api.CheckOrgPermissionInput{Actor: actor, PermissionKey: key})
}

// RequireOwner is non-delegable and never consults the user's application role.
func (s *OrgPermissionsService) RequireOwner(ctx context.Context, actor api.OrgPermissionActor) error {
	user, role, err := s.current(ctx, actor)
	if err != nil {
		return err
	}
	if !role.IsOwner() {
		return domain.ErrOrgForbidden
	}
	return s.assurance(ctx, actor, user)
}

// withMutation follows the existing users-first guard, then serializes all org
// authorization and membership changes before evaluating the actor's grants.
func (s *OrgPermissionsService) withMutation(ctx context.Context, actor api.OrgPermissionActor, key string, fn func(context.Context) error) error {
	if err := validateOrgID(actor.OrgID); err != nil {
		return err
	}
	if scope, ok := ctx.Value(orgManagementContextKey{}).(string); ok && scope == actor.OrgID {
		if err := s.require(ctx, actor, key); err != nil {
			return err
		}
		return fn(ctx)
	}
	return s.users.WithAdminGuard(ctx, func(ctx context.Context) error {
		if err := s.state.LockOrg(ctx, actor.OrgID); err != nil {
			return err
		}
		ctx = context.WithValue(ctx, orgManagementContextKey{}, actor.OrgID)
		if err := s.require(ctx, actor, key); err != nil {
			return err
		}
		if err := fn(ctx); err != nil {
			return err
		}
		return s.state.BumpOrgState(ctx, actor.OrgID)
	})
}

func (s *OrgPermissionsService) record(ctx context.Context, actor api.OrgPermissionActor, typ audit.EventType, metadata map[string]any) error {
	if s.config.Audit == nil {
		return nil
	}
	e := audit.NewOrgEvent(typ, actor.UserID, actor.OrgID, nil)
	if actor.SessionID != "" {
		e.SessionID = &actor.SessionID
	}
	e.Metadata = metadata
	return s.config.Audit.Record(ctx, e)
}

func (s *OrgPermissionsService) explicitKeys(ctx context.Context, orgID string, role *domain.OrgPermissionRole) ([]string, error) {
	if role.SystemKey != nil {
		return orgPreset(*role.SystemKey), nil
	}
	return s.permissions.RoleGrantKeys(ctx, orgID, role.ID)
}
func (s *OrgPermissionsService) effectiveKeys(ctx context.Context, orgID string, role *domain.OrgPermissionRole, includeBusiness bool) ([]string, error) {
	if !role.IsEnabled {
		return []string{}, nil
	}
	if role.SystemKey == nil {
		return s.permissions.RolePermissionKeys(ctx, orgID, role.ID)
	}
	keys := orgPreset(*role.SystemKey)
	if role.IsOwner() && includeBusiness {
		business, err := s.permissions.EnabledBusinessPermissionKeys(ctx, orgID)
		if err != nil {
			return nil, err
		}
		keys = append(keys, business...)
		slices.Sort(keys)
	}
	return keys, nil
}

// Initialize preserves existing memberships and creates immutable built-in roles.
// Startup never writes authorization data; new-org creation calls initializeNew.
func (s *OrgPermissionsService) Initialize(ctx context.Context, input api.InitializeOrgPermissionsInput) error {
	if err := validateOrgID(input.Actor.OrgID); err != nil {
		return err
	}
	return s.users.WithAdminGuard(ctx, func(ctx context.Context) error {
		if err := s.state.LockOrg(ctx, input.Actor.OrgID); err != nil {
			return err
		}
		user, err := s.users.GetByIDForUpdate(ctx, input.Actor.UserID)
		if err != nil {
			return err
		}
		if user == nil || user.IsBanned {
			return domain.ErrOrgForbidden
		}
		member, err := s.orgs.LockMembership(ctx, input.Actor.OrgID, input.Actor.UserID)
		if err != nil {
			return err
		}
		if member == nil {
			return domain.ErrOrgMemberNotFound
		}
		if member.Role != domain.OrgRoleOwner {
			return domain.ErrOrgForbidden
		}
		if err := s.assurance(ctx, input.Actor, user); err != nil {
			return err
		}
		return s.initializeNew(ctx, input.Actor)
	})
}
func (s *OrgPermissionsService) initializeNew(ctx context.Context, actor api.OrgPermissionActor) error {
	revision, err := s.state.OrgStateRevision(ctx, actor.OrgID)
	if err != nil {
		return err
	}
	if revision > 0 {
		return domain.ErrOrgPermissionsInitialized
	}
	now := time.Now().UTC()
	if err := s.state.InitializeOrgState(ctx, actor.OrgID, now); err != nil {
		return err
	}
	for _, identity := range []string{"owner", "admin", "member"} {
		role := &domain.OrgPermissionRole{ID: uuid.NewString(), OrgID: actor.OrgID, Slug: identity, Name: strings.ToUpper(identity[:1]) + identity[1:], SystemKey: &identity, IsEnabled: true, Revision: 1, CreatedAt: now, UpdatedAt: now}
		if err := s.roles.InsertOrgRole(ctx, role); err != nil {
			return err
		}
	}
	return s.record(ctx, actor, audit.EventOrgAuthorizationInitialized, nil)
}

// LibraryPermissionCatalog returns a defensive copy of supported org operations.
func (s *OrgPermissionsService) LibraryPermissionCatalog() []domain.OrgLibraryPermissionDefinition {
	return slices.Clone(orgLibraryCatalog)
}

// ListEffectivePermissions returns informational current access for a member.
func (s *OrgPermissionsService) ListEffectivePermissions(ctx context.Context, input api.ListOrgEffectivePermissionsInput) (*api.OrgAccess, error) {
	if input.UserID != "" {
		if err := validateOrgID(input.UserID); err != nil {
			return nil, err
		}
	}
	user, _, err := s.current(ctx, input.Actor)
	if err != nil {
		return nil, err
	}
	if err := s.assurance(ctx, input.Actor, user); err != nil {
		return nil, err
	}
	target := input.Actor
	if input.UserID != "" && input.UserID != target.UserID {
		if err := s.require(ctx, input.Actor, "goauth.org.roles.read"); err != nil {
			return nil, err
		}
		target.UserID = input.UserID
	}
	member, err := s.orgs.GetMembership(ctx, target.OrgID, target.UserID)
	if err != nil {
		return nil, err
	}
	if member == nil {
		return nil, domain.ErrOrgMemberNotFound
	}
	role, assignment, err := s.memberRole(ctx, member)
	if err != nil {
		return nil, err
	}
	targetUser := user
	if target.UserID != input.Actor.UserID {
		targetUser, err = s.users.GetByID(ctx, target.UserID)
		if err != nil {
			return nil, err
		}
		if targetUser == nil {
			return nil, domain.ErrOrgMemberNotFound
		}
	}
	eligible := !targetUser.IsBanned && role.IsEnabled && orgRoleMatchesMembership(role, member)
	keys := []string{}
	if eligible {
		keys, err = s.effectiveKeys(ctx, target.OrgID, role, true)
		if err != nil {
			return nil, err
		}
	}
	role.PermissionKeys, err = s.explicitKeys(ctx, target.OrgID, role)
	if err != nil {
		return nil, err
	}
	revision, err := s.state.OrgStateRevision(ctx, target.OrgID)
	if err != nil {
		return nil, err
	}
	return &api.OrgAccess{
		Role:               *role,
		IsFullAccess:       eligible && role.IsOwner(),
		PermissionKeys:     keys,
		AssignmentRevision: assignment,
		Revision:           revision,
	}, nil
}
