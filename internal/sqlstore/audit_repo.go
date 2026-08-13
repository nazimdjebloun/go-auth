package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/nazimdjebloun/go-auth/port"
)

type AuditLogRepository struct {
	db *DB
}

func NewAuditLogRepository(db *DB) *AuditLogRepository {
	return &AuditLogRepository{db: db}
}

func (r *AuditLogRepository) List(ctx context.Context, filter port.AuditLogFilter) ([]port.AuditLogEntry, int, error) {
	where, args := r.buildWhere(filter)

	var total int
	countQuery := auditLogCountQuery
	if where != "" {
		countQuery += " WHERE " + where
	}
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	argIdx := len(args) + 1
	query := auditLogListQuery
	if where != "" {
		query += " WHERE " + where
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, filter.Limit, filter.Offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []port.AuditLogEntry
	for rows.Next() {
		var e port.AuditLogEntry
		var parsedUA, metadata sql.NullString
		if err := rows.Scan(
			&e.ID, &e.Type, &e.Severity, &e.Success,
			&e.ActorID, &e.TargetUserID, &e.SessionID, &e.OrgID,
			&e.IP, &e.UserAgent, &parsedUA, &e.RequestID, &e.CorrelationID,
			&metadata, &e.CreatedAt,
		); err != nil {
			return nil, 0, err
		}
		e.ParsedUA = json.RawMessage(parsedUA.String)
		e.Metadata = json.RawMessage(metadata.String)
		if len(e.ParsedUA) == 0 {
			e.ParsedUA = json.RawMessage("null")
		}
		if len(e.Metadata) == 0 {
			e.Metadata = json.RawMessage("null")
		}
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []port.AuditLogEntry{}
	}
	return entries, total, rows.Err()
}

func (r *AuditLogRepository) GetByID(ctx context.Context, id string) (*port.AuditLogEntry, error) {
	var e port.AuditLogEntry
	var parsedUA, metadata sql.NullString
	err := r.db.QueryRowContext(ctx, auditLogByIDQuery, id).Scan(
		&e.ID, &e.Type, &e.Severity, &e.Success,
		&e.ActorID, &e.TargetUserID, &e.SessionID, &e.OrgID,
		&e.IP, &e.UserAgent, &parsedUA, &e.RequestID, &e.CorrelationID,
		&metadata, &e.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err == nil {
		e.ParsedUA = json.RawMessage(parsedUA.String)
		e.Metadata = json.RawMessage(metadata.String)
		if len(e.ParsedUA) == 0 {
			e.ParsedUA = json.RawMessage("null")
		}
		if len(e.Metadata) == 0 {
			e.Metadata = json.RawMessage("null")
		}
	}
	return &e, err
}

func (r *AuditLogRepository) buildWhere(filter port.AuditLogFilter) (string, []any) {
	var conditions []string
	var args []any
	argIdx := 1

	if filter.Type != nil {
		conditions = append(conditions, fmt.Sprintf("event_type = $%d", argIdx))
		args = append(args, *filter.Type)
		argIdx++
	}
	if filter.ActorID != nil {
		conditions = append(conditions, fmt.Sprintf("actor_id = $%d", argIdx))
		args = append(args, *filter.ActorID)
		argIdx++
	}
	if filter.TargetUserID != nil {
		conditions = append(conditions, fmt.Sprintf("target_id = $%d", argIdx))
		args = append(args, *filter.TargetUserID)
		argIdx++
	}
	if filter.SessionID != nil {
		conditions = append(conditions, fmt.Sprintf("session_id = $%d", argIdx))
		args = append(args, *filter.SessionID)
		argIdx++
	}
	if filter.OrgID != nil {
		conditions = append(conditions, fmt.Sprintf("org_id = $%d", argIdx))
		args = append(args, *filter.OrgID)
		argIdx++
	}
	if filter.Success != nil {
		conditions = append(conditions, fmt.Sprintf("success = $%d", argIdx))
		args = append(args, *filter.Success)
		argIdx++
	}
	if filter.Search != nil {
		searchPattern := "%" + *filter.Search + "%"
		switch r.db.Driver() {
		case "mysql":
			conditions = append(conditions, fmt.Sprintf("(JSON_UNQUOTE(JSON_EXTRACT(metadata, '$')) LIKE $%d OR user_agent LIKE $%d)", argIdx, argIdx+1))
		case "sqlite", "sqlite3":
			conditions = append(conditions, fmt.Sprintf("(metadata LIKE $%d OR user_agent LIKE $%d)", argIdx, argIdx+1))
		default:
			conditions = append(conditions, fmt.Sprintf("(metadata::text ILIKE $%d OR user_agent ILIKE $%d)", argIdx, argIdx+1))
		}
		args = append(args, searchPattern, searchPattern)
		argIdx += 2
	}
	if filter.FromDate != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argIdx))
		args = append(args, *filter.FromDate)
		argIdx++
	}
	if filter.ToDate != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argIdx))
		args = append(args, *filter.ToDate)
		argIdx++
	}

	return strings.Join(conditions, " AND "), args
}
