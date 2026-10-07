package service

import (
	"context"
	"fmt"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// GetStats returns exact platform-wide counts after authorization and required
// session assurance. Direct callers supply the same trusted IDs as HTTP.
func (s *AdminService) GetStats(ctx context.Context, input api.GetAdminStatsInput) (*api.AdminStats, error) {
	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.stats.read"); err != nil {
		return nil, err
	}

	yes := true
	stats := &api.AdminStats{}

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

func validateStatsRangeInput(input api.StatsRangeInput) error {
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
func (s *AdminService) GetRegistrationTrend(ctx context.Context, input api.StatsRangeInput) ([]api.DailyCount, error) {
	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.stats.read"); err != nil {
		return nil, err
	}
	if err := validateStatsRangeInput(input); err != nil {
		return nil, err
	}
	counts, err := s.users.CountByDay(ctx, port.UserFilter{CreatedAfter: &input.From, CreatedBefore: &input.To})
	if err != nil {
		s.log.Error("failed to count registrations by day", "err", err)
		return nil, domain.ErrInternal
	}
	return counts, nil
}

// GetLoginActivity returns successful-login counts per day over [From, To] —
// the data behind a GitHub-commit-style login heatmap, global or per-user.
// Counts domain.EventLoginSuccess only (email/password logins); OAuth and
// admin logins are a separate audit event type and aren't folded in here.
func (s *AdminService) GetLoginActivity(ctx context.Context, input api.LoginActivityInput) ([]api.DailyCount, error) {
	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.stats.read"); err != nil {
		return nil, err
	}
	rangeInput := api.StatsRangeInput{ActorID: input.ActorID, From: input.From, To: input.To}
	if err := validateStatsRangeInput(rangeInput); err != nil {
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
