package service

import (
	"context"
	"log/slog"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// adminSessionStore is AdminService's session dependency: listing a user's
// sessions (AdminListUserSessions) and revoking one by id
// (AdminRevokeUserSession) — SessionReader and SessionRevoker, not the full
// port.SessionRepository.
type adminSessionStore interface {
	port.SessionReader
	port.SessionRevoker
}

type AdminService struct {
	users      port.UserRepository
	sessions   adminSessionStore
	providers  port.ProviderAccountRepository
	auditLogs  port.AuditLogRepository
	hasher     port.Hasher
	config     Config
	sessionSvc *SessionService
	log        *slog.Logger
	audit      AuditPublisher

	// deletion carries the transactional account-deletion invariants. It is
	// attached by the library's wiring; see AccountDeletion for why it can
	// legitimately be nil (mock-built services).
	deletion *AccountDeletion
}

// AttachAccountDeletion wires the shared transactional account-deletion
// coordinator into this service. Called by the library's own construction;
// safe to call once, before the service handles requests.
func (s *AdminService) AttachAccountDeletion(d *AccountDeletion) {
	s.deletion = d
}

func NewAdminService(
	users port.UserRepository,
	sessions adminSessionStore,
	providers port.ProviderAccountRepository,
	auditLogs port.AuditLogRepository,
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
		auditLogs:  auditLogs,
		hasher:     hasher,
		config:     config,
		sessionSvc: sessionSvc,
		log:        config.Logger,
		audit:      config.Audit,
	}
}

// requireAdminRole verifies actorID is a current, non-banned admin. Shared
// by AdminService (every exported method) and OrgService (its AdminX
// methods) — one implementation of a security check used in two services,
// rather than two copies that could drift. The HTTP layer's
// RequireRole(domain.RoleAdmin) middleware pre-checks the same thing, but
// this is the real authority: it also protects the "call it without HTTP"
// path the root package advertises (auth.Services.Admin.BanUser(ctx, ...)),
// which has no middleware in front of it at all.
func requireAdminRole(ctx context.Context, users port.UserRepository, actorID string) error {
	if actorID == "" {
		return domain.ErrForbidden
	}
	actor, err := users.GetByID(ctx, actorID)
	if err != nil {
		return err
	}
	if actor == nil || actor.Role != domain.RoleAdmin || actor.IsBanned {
		return domain.ErrForbidden
	}
	return nil
}

func (s *AdminService) requireAdmin(ctx context.Context, actorID string) error {
	return requireAdminRole(ctx, s.users, actorID)
}
