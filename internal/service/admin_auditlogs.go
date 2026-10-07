package service

import (
	"context"
	"strings"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// resolveEmailsForEntries batch-looks-up every distinct actor/target ID
// across a page of audit entries in one query, rather than one query per
// row — a page can reference up to 2*len(entries) distinct users.
func (s *AdminService) resolveEmailsForEntries(ctx context.Context, entries []api.AuditLogEntry) ([]api.AdminAuditLogEntry, error) {
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
		users, err := s.users.List(ctx, port.UserFilter{IDs: ids})
		if err != nil {
			s.log.Error("failed to resolve audit log actor/target emails", "err", err)
			return nil, domain.ErrInternal
		}
		for _, u := range users {
			emailByID[u.ID] = u.Email
		}
	}

	enriched := make([]api.AdminAuditLogEntry, len(entries))
	for i, e := range entries {
		enriched[i] = api.AdminAuditLogEntry{AuditLogEntry: e}
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
func (s *AdminService) ListAuditLogs(ctx context.Context, input api.AdminListAuditLogsInput) (*api.AdminListAuditLogsResult, error) {
	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.audit.read"); err != nil {
		return nil, err
	}

	filter, err := s.auditFilterFromInput(ctx, input)
	if err != nil {
		return nil, err
	}

	limit := input.Limit
	if limit <= 0 {
		limit = 50
	} else if limit > 200 {
		limit = 200
	}
	filter.Offset = input.Offset
	filter.Limit = limit

	events, err := s.auditLogs.List(ctx, filter)
	if err != nil {
		s.log.Error("failed to list audit logs", "err", err)
		return nil, domain.ErrInternal
	}
	enriched, err := s.resolveEmailsForEntries(ctx, events)
	if err != nil {
		return nil, err
	}

	return &api.AdminListAuditLogsResult{Events: enriched, Limit: limit, Offset: input.Offset}, nil
}

// auditFilterFromInput resolves any actor/target emails to IDs and builds the
// repository filter (without Offset/Limit) shared by ListAuditLogs and
// CountAuditLogs.
func (s *AdminService) auditFilterFromInput(ctx context.Context, input api.AdminListAuditLogsInput) (port.AuditLogFilter, error) {
	eventActorID := input.EventActorID
	if input.EventActorEmail != nil {
		resolved, err := s.resolveUserEmail(ctx, input.EventActorEmail)
		if err != nil {
			return port.AuditLogFilter{}, err
		}
		eventActorID = resolved
	}

	targetUserID := input.TargetUserID
	if input.TargetEmail != nil {
		resolved, err := s.resolveUserEmail(ctx, input.TargetEmail)
		if err != nil {
			return port.AuditLogFilter{}, err
		}
		targetUserID = resolved
	}

	return port.AuditLogFilter{
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
	}, nil
}

// CountAuditLogs returns how many audit entries match the input's filters
// (pagination ignored).
func (s *AdminService) CountAuditLogs(ctx context.Context, input api.AdminListAuditLogsInput) (int, error) {
	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.audit.read"); err != nil {
		return 0, err
	}
	filter, err := s.auditFilterFromInput(ctx, input)
	if err != nil {
		return 0, err
	}
	n, err := s.auditLogs.Count(ctx, filter)
	if err != nil {
		s.log.Error("failed to count audit logs", "err", err)
		return 0, domain.ErrInternal
	}
	return n, nil
}
