package service

import (
	"context"
	"fmt"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// GetStats returns platform-wide counts for the admin dashboard — one Count
// call per field, each an exact COUNT(*), not an estimate.
func (s *AdminService) GetStats(ctx context.Context, actorID string) (*AdminStats, error) {
	if err := s.requireAdmin(ctx, actorID); err != nil {
		return nil, err
	}

	yes := true
	stats := &AdminStats{}

	total, err := s.users.Count(ctx, port.UserFilter{})
	if err != nil {
		s.log.Error("failed to count users", "err", err)
		return nil, domain.ErrInternal
	}
	stats.TotalUsers = total

	verified, err := s.users.Count(ctx, port.UserFilter{IsVerified: &yes})
	if err != nil {
		s.log.Error("failed to count verified users", "err", err)
		return nil, domain.ErrInternal
	}
	stats.VerifiedUsers = verified

	banned, err := s.users.Count(ctx, port.UserFilter{IsBanned: &yes})
	if err != nil {
		s.log.Error("failed to count banned users", "err", err)
		return nil, domain.ErrInternal
	}
	stats.BannedUsers = banned

	twoFactor, err := s.users.Count(ctx, port.UserFilter{TwoFactorEnabled: &yes})
	if err != nil {
		s.log.Error("failed to count two-factor users", "err", err)
		return nil, domain.ErrInternal
	}
	stats.TwoFactorEnabledUsers = twoFactor

	neverLoggedIn, err := s.users.Count(ctx, port.UserFilter{NeverLoggedIn: &yes})
	if err != nil {
		s.log.Error("failed to count never-logged-in users", "err", err)
		return nil, domain.ErrInternal
	}
	stats.NeverLoggedInUsers = neverLoggedIn

	activeSessions, err := s.sessions.CountAll(ctx, port.SessionFilter{})
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

// AdminListAuditLogsResult contains audit entries and the matching total.
type AdminListAuditLogsResult struct {
	Events []AdminAuditLogEntry `json:"events"`
	Limit  int                  `json:"limit"`
	Offset int                  `json:"offset"`
}
