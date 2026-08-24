package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/audit"
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
	if actor == nil || actor.Role != domain.RoleAdmin {
		return domain.ErrForbidden
	}
	return nil
}

func (s *AdminService) requireAdmin(ctx context.Context, actorID string) error {
	return requireAdminRole(ctx, s.users, actorID)
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
		Email:            input.Email,
		Role:             input.Role,
		TwoFactorEnabled: input.TwoFactorEnabled,
		NeverLoggedIn:    input.NeverLoggedIn,
		LastLoginBefore:  input.LastLoginBefore,
		Offset:           input.Offset,
		Limit:            limit,
		Search:           input.Search,
		OrderBy:          input.OrderBy,
		OrderDirection:   input.OrderDirection,
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

// GetStats returns platform-wide counts for the admin dashboard. Each field
// is a separate List/ListAll call with Limit:1 — List always runs a COUNT(*)
// query regardless of Limit, so the row fetch itself stays trivial while the
// count is exact, not an estimate.
func (s *AdminService) GetStats(ctx context.Context, actorID string) (*AdminStats, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return nil, err
	}

	yes := true
	stats := &AdminStats{}

	_, total, err := s.users.List(ctx, port.UserFilter{Limit: 1})
	if err != nil {
		s.log.Error("failed to count users", "err", err)
		return nil, domain.ErrInternal
	}
	stats.TotalUsers = total

	_, verified, err := s.users.List(ctx, port.UserFilter{IsVerified: &yes, Limit: 1})
	if err != nil {
		s.log.Error("failed to count verified users", "err", err)
		return nil, domain.ErrInternal
	}
	stats.VerifiedUsers = verified

	_, banned, err := s.users.List(ctx, port.UserFilter{IsBanned: &yes, Limit: 1})
	if err != nil {
		s.log.Error("failed to count banned users", "err", err)
		return nil, domain.ErrInternal
	}
	stats.BannedUsers = banned

	_, twoFactor, err := s.users.List(ctx, port.UserFilter{TwoFactorEnabled: &yes, Limit: 1})
	if err != nil {
		s.log.Error("failed to count two-factor users", "err", err)
		return nil, domain.ErrInternal
	}
	stats.TwoFactorEnabledUsers = twoFactor

	_, neverLoggedIn, err := s.users.List(ctx, port.UserFilter{NeverLoggedIn: &yes, Limit: 1})
	if err != nil {
		s.log.Error("failed to count never-logged-in users", "err", err)
		return nil, domain.ErrInternal
	}
	stats.NeverLoggedInUsers = neverLoggedIn

	_, activeSessions, err := s.sessions.ListAll(ctx, port.SessionFilter{Limit: 1})
	if err != nil {
		s.log.Error("failed to count active sessions", "err", err)
		return nil, domain.ErrInternal
	}
	stats.ActiveSessions = activeSessions

	return stats, nil
}

// StatsRangeInput scopes a day-bucketed analytics query to [From, To].
type StatsRangeInput struct {
	ActorID string
	From    time.Time
	To      time.Time
}

func (input StatsRangeInput) validate() error {
	if input.From.IsZero() || input.To.IsZero() {
		return domain.NewError("invalid_input", "from and to are required")
	}
	if input.To.Before(input.From) {
		return domain.NewError("invalid_input", "to must not be before from")
	}
	if input.To.Sub(input.From) > maxStatsRangeDays*24*time.Hour {
		return domain.NewError("invalid_input", fmt.Sprintf("date range must not exceed %d days", maxStatsRangeDays))
	}
	return nil
}

// GetRegistrationTrend returns registrations per day over [From, To], for a
// registrations-over-time chart.
func (s *AdminService) GetRegistrationTrend(ctx context.Context, input StatsRangeInput) ([]port.DailyCount, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, err
	}
	if err := input.validate(); err != nil {
		return nil, err
	}
	counts, err := s.users.CountByDay(ctx, port.UserFilter{CreatedAfter: &input.From, CreatedBefore: &input.To})
	if err != nil {
		s.log.Error("failed to count registrations by day", "err", err)
		return nil, domain.ErrInternal
	}
	return counts, nil
}

// LoginActivityInput scopes a login-activity heatmap query. UserID nil means
// a global heatmap (every user's successful logins); set, it's one user's.
type LoginActivityInput struct {
	ActorID string
	UserID  *string
	From    time.Time
	To      time.Time
}

// GetLoginActivity returns successful-login counts per day over [From, To] —
// the data behind a GitHub-commit-style login heatmap, global or per-user.
// Counts domain.EventLoginSuccess only (email/password logins); OAuth and
// admin logins are a separate audit event type and aren't folded in here.
func (s *AdminService) GetLoginActivity(ctx context.Context, input LoginActivityInput) ([]port.DailyCount, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, err
	}
	rangeInput := StatsRangeInput{ActorID: input.ActorID, From: input.From, To: input.To}
	if err := rangeInput.validate(); err != nil {
		return nil, err
	}
	counts, err := s.auditLogs.CountByDay(ctx, port.AuditLogFilter{
		Types:    []string{string(audit.EventLoginSuccess)},
		ActorID:  input.UserID,
		FromDate: &input.From,
		ToDate:   &input.To,
	})
	if err != nil {
		s.log.Error("failed to count login activity by day", "err", err)
		return nil, domain.ErrInternal
	}
	return counts, nil
}

// AdminListAuditLogsInput scopes an audit-log query. ActorID is the calling
// admin (for requireAdmin), distinct from EventActorID/EventActorEmail,
// which filter the logged events themselves.
type AdminListAuditLogsInput struct {
	ActorID string

	EventTypes []string
	// EventActorID/EventActorEmail filter by who performed the logged
	// action. If both are set, EventActorEmail wins — it's resolved to a
	// user ID first and that replaces EventActorID.
	EventActorID    *string
	EventActorEmail *string
	// TargetUserID/TargetEmail filter by who the logged action was done
	// to, same email-wins-if-both rule as the actor pair above.
	TargetUserID *string
	TargetEmail  *string
	SessionID    *string
	OrgID        *string
	DeviceType   *string
	IP           *string
	Success      *bool
	Search       *string
	FromDate     *time.Time
	ToDate       *time.Time
	Offset       int
	Limit        int
}

// AdminAuditLogEntry adds resolved actor/target emails to a raw audit row —
// the row itself only stores IDs, and an admin reading a log wants to know
// *who*, not just a UUID. Both are nil if the corresponding *_id is nil, or
// if that user no longer exists (deleted since the event was recorded) —
// the row's IDs are the durable record either way.
type AdminAuditLogEntry struct {
	port.AuditLogEntry
	ActorEmail  *string `json:"actorEmail,omitempty"`
	TargetEmail *string `json:"targetEmail,omitempty"`
}

type AdminListAuditLogsResult struct {
	Events []AdminAuditLogEntry `json:"events"`
	Total  int                  `json:"total"`
	Limit  int                  `json:"limit"`
	Offset int                  `json:"offset"`
}

// resolveEmailsForEntries batch-looks-up every distinct actor/target ID
// across a page of audit entries in one query, rather than one query per
// row — a page can reference up to 2*len(entries) distinct users.
func (s *AdminService) resolveEmailsForEntries(ctx context.Context, entries []port.AuditLogEntry) ([]AdminAuditLogEntry, error) {
	idSet := make(map[string]struct{})
	for _, e := range entries {
		if e.ActorID != nil {
			idSet[*e.ActorID] = struct{}{}
		}
		if e.TargetUserID != nil {
			idSet[*e.TargetUserID] = struct{}{}
		}
	}

	emailByID := make(map[string]string, len(idSet))
	if len(idSet) > 0 {
		ids := make([]string, 0, len(idSet))
		for id := range idSet {
			ids = append(ids, id)
		}
		users, _, err := s.users.List(ctx, port.UserFilter{IDs: ids})
		if err != nil {
			s.log.Error("failed to resolve audit log actor/target emails", "err", err)
			return nil, domain.ErrInternal
		}
		for _, u := range users {
			emailByID[u.ID] = u.Email
		}
	}

	enriched := make([]AdminAuditLogEntry, len(entries))
	for i, e := range entries {
		enriched[i] = AdminAuditLogEntry{AuditLogEntry: e}
		if e.ActorID != nil {
			if email, ok := emailByID[*e.ActorID]; ok {
				enriched[i].ActorEmail = &email
			}
		}
		if e.TargetUserID != nil {
			if email, ok := emailByID[*e.TargetUserID]; ok {
				enriched[i].TargetEmail = &email
			}
		}
	}
	return enriched, nil
}

// resolveUserEmail turns an email into a user ID for an identity-based audit
// filter — "which events did alice@example.com cause" instead of requiring
// the admin to already know her UUID. Returns (nil, nil) for an empty/nil
// email (no filter), or a "user_not_found" AuthError if no user has it.
func (s *AdminService) resolveUserEmail(ctx context.Context, email *string) (*string, error) {
	if email == nil || strings.TrimSpace(*email) == "" {
		return nil, nil
	}
	user, err := s.users.GetByEmail(ctx, strings.ToLower(strings.TrimSpace(*email)))
	if err != nil {
		s.log.Error("failed to resolve email for audit log filter", "err", err)
		return nil, domain.ErrInternal
	}
	if user == nil {
		return nil, domain.ErrUserNotFound
	}
	return &user.ID, nil
}

// ListAuditLogs returns audit events matching the given filter — the
// backend for both GET /admin/audit-logs and GET /admin/users/{id}/audit-logs
// (the latter just pre-sets TargetUserID). Empty results, not an error, if
// audit logging was never turned on (WithAudit(Enabled: true)) — the table
// simply has no rows in that case.
func (s *AdminService) ListAuditLogs(ctx context.Context, input AdminListAuditLogsInput) (*AdminListAuditLogsResult, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, err
	}

	eventActorID := input.EventActorID
	if input.EventActorEmail != nil {
		resolved, err := s.resolveUserEmail(ctx, input.EventActorEmail)
		if err != nil {
			return nil, err
		}
		eventActorID = resolved
	}

	targetUserID := input.TargetUserID
	if input.TargetEmail != nil {
		resolved, err := s.resolveUserEmail(ctx, input.TargetEmail)
		if err != nil {
			return nil, err
		}
		targetUserID = resolved
	}

	limit := input.Limit
	if limit <= 0 {
		limit = 50
	} else if limit > 200 {
		limit = 200
	}

	events, total, err := s.auditLogs.List(ctx, port.AuditLogFilter{
		Types:        input.EventTypes,
		ActorID:      eventActorID,
		TargetUserID: targetUserID,
		SessionID:    input.SessionID,
		OrgID:        input.OrgID,
		DeviceType:   input.DeviceType,
		IP:           input.IP,
		Success:      input.Success,
		Search:       input.Search,
		FromDate:     input.FromDate,
		ToDate:       input.ToDate,
		Offset:       input.Offset,
		Limit:        limit,
	})
	if err != nil {
		s.log.Error("failed to list audit logs", "err", err)
		return nil, domain.ErrInternal
	}
	enriched, err := s.resolveEmailsForEntries(ctx, events)
	if err != nil {
		return nil, err
	}

	return &AdminListAuditLogsResult{Events: enriched, Total: total, Limit: limit, Offset: input.Offset}, nil
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

// AdminListSessionsInput scopes an admin-wide session search — every filter
// beyond ActorID is optional and composable (e.g. UserID + IP together).
type AdminListSessionsInput struct {
	ActorID          string
	UserID           *string
	IP               *string
	Search           *string
	CreatedAfter     *time.Time
	CreatedBefore    *time.Time
	ExpiresAfter     *time.Time
	ExpiresBefore    *time.Time
	LastActiveAfter  *time.Time
	LastActiveBefore *time.Time
	OrderBy          string
	OrderDirection   string
	Offset           int
	Limit            int
}

type AdminListSessionsResult struct {
	Sessions []domain.Session `json:"sessions"`
	Total    int              `json:"total"`
	Limit    int              `json:"limit"`
	Offset   int              `json:"offset"`
}

// ListSessions returns active sessions across every user — the
// incident-response view ("who's logged in right now", "every session from
// this IP"), as opposed to ListUserSessions which is scoped to one user.
func (s *AdminService) ListSessions(ctx context.Context, input AdminListSessionsInput) (*AdminListSessionsResult, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, err
	}
	limit := input.Limit
	if limit <= 0 {
		limit = 20
	} else if limit > 100 {
		limit = 100
	}

	sessions, total, err := s.sessions.ListAll(ctx, port.SessionFilter{
		UserID:           input.UserID,
		IP:               input.IP,
		Search:           input.Search,
		CreatedAfter:     input.CreatedAfter,
		CreatedBefore:    input.CreatedBefore,
		ExpiresAfter:     input.ExpiresAfter,
		ExpiresBefore:    input.ExpiresBefore,
		LastActiveAfter:  input.LastActiveAfter,
		LastActiveBefore: input.LastActiveBefore,
		OrderBy:          input.OrderBy,
		OrderDirection:   input.OrderDirection,
		Offset:           input.Offset,
		Limit:            limit,
	})
	if err != nil {
		s.log.Error("failed to list sessions", "err", err)
		return nil, domain.ErrInternal
	}
	if sessions == nil {
		sessions = []domain.Session{}
	}

	return &AdminListSessionsResult{Sessions: sessions, Total: total, Limit: limit, Offset: input.Offset}, nil
}

// maxBulkUserIDs caps a bulk request the same way Limit is capped elsewhere
// — go-auth has no atomic batch primitive, so a bulk call is N sequential
// single-user calls; an unbounded list would mean an unbounded number of
// queries per request.
const maxBulkUserIDs = 100

// BulkUserActionInput is the shared input shape for every Bulk*Users method.
type BulkUserActionInput struct {
	UserIDs []string
	ActorID string
}

func (input BulkUserActionInput) validate() error {
	if len(input.UserIDs) == 0 {
		return domain.NewError("invalid_input", "userIds must not be empty")
	}
	if len(input.UserIDs) > maxBulkUserIDs {
		return domain.NewError("invalid_input", fmt.Sprintf("at most %d userIds per bulk request", maxBulkUserIDs))
	}
	return nil
}

// BulkActionFailure reports why one user in a bulk request didn't succeed —
// Code is the same stable AuthError code a single-user call would return
// (e.g. "last_admin", "already_banned"), safe to match on.
type BulkActionFailure struct {
	UserID  string `json:"userId"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// BulkUserActionResult reports per-user outcome, not overall success — a
// bulk request is not transactional. Some users can succeed while others
// fail (already banned, last admin, not found); the caller must read both
// slices rather than treating a nil error as "all succeeded."
type BulkUserActionResult struct {
	Succeeded []string            `json:"succeeded"`
	Failed    []BulkActionFailure `json:"failed"`
}

func bulkFailure(userID string, err error) BulkActionFailure {
	var ae *domain.AuthError
	if errors.As(err, &ae) {
		return BulkActionFailure{UserID: userID, Code: ae.Code, Message: ae.Message}
	}
	return BulkActionFailure{UserID: userID, Code: "internal_error", Message: "Internal error"}
}

// BulkBanUsers bans each user independently by calling BanUser in a loop —
// not one atomic operation. A failure on one user (already banned, last
// admin) doesn't stop or roll back the rest.
func (s *AdminService) BulkBanUsers(ctx context.Context, input BulkUserActionInput) (*BulkUserActionResult, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, err
	}
	if err := input.validate(); err != nil {
		return nil, err
	}
	result := &BulkUserActionResult{Succeeded: []string{}, Failed: []BulkActionFailure{}}
	for _, id := range input.UserIDs {
		if err := s.BanUser(ctx, BanUserInput{UserID: id, ActorID: input.ActorID}); err != nil {
			result.Failed = append(result.Failed, bulkFailure(id, err))
			continue
		}
		result.Succeeded = append(result.Succeeded, id)
	}
	return result, nil
}

// BulkUnbanUsers is BulkBanUsers's counterpart — see its comment for the
// partial-failure contract.
func (s *AdminService) BulkUnbanUsers(ctx context.Context, input BulkUserActionInput) (*BulkUserActionResult, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, err
	}
	if err := input.validate(); err != nil {
		return nil, err
	}
	result := &BulkUserActionResult{Succeeded: []string{}, Failed: []BulkActionFailure{}}
	for _, id := range input.UserIDs {
		if err := s.UnbanUser(ctx, UnbanUserInput{UserID: id, ActorID: input.ActorID}); err != nil {
			result.Failed = append(result.Failed, bulkFailure(id, err))
			continue
		}
		result.Succeeded = append(result.Succeeded, id)
	}
	return result, nil
}

// BulkDeleteUsers is BulkBanUsers's counterpart for deletion — see its
// comment for the partial-failure contract.
func (s *AdminService) BulkDeleteUsers(ctx context.Context, input BulkUserActionInput) (*BulkUserActionResult, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, err
	}
	if err := input.validate(); err != nil {
		return nil, err
	}
	result := &BulkUserActionResult{Succeeded: []string{}, Failed: []BulkActionFailure{}}
	for _, id := range input.UserIDs {
		if err := s.DeleteUser(ctx, DeleteUserInput{UserID: id, ActorID: input.ActorID}); err != nil {
			result.Failed = append(result.Failed, bulkFailure(id, err))
			continue
		}
		result.Succeeded = append(result.Succeeded, id)
	}
	return result, nil
}

// BulkRevokeUserSessions is BulkBanUsers's counterpart for a mass
// "sign everyone out" action — see its comment for the partial-failure
// contract.
func (s *AdminService) BulkRevokeUserSessions(ctx context.Context, input BulkUserActionInput) (*BulkUserActionResult, error) {
	if err := s.requireAdmin(ctx, input.ActorID); err != nil {
		return nil, err
	}
	if err := input.validate(); err != nil {
		return nil, err
	}
	result := &BulkUserActionResult{Succeeded: []string{}, Failed: []BulkActionFailure{}}
	for _, id := range input.UserIDs {
		if err := s.RevokeUserSessions(ctx, RevokeUserSessionsInput{UserID: id, ActorID: input.ActorID}); err != nil {
			result.Failed = append(result.Failed, bulkFailure(id, err))
			continue
		}
		result.Succeeded = append(result.Succeeded, id)
	}
	return result, nil
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
