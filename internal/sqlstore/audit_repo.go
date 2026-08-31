package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/port"
)

type AuditLogRepository struct {
	db *DB
}

func NewAuditLogRepository(db *DB) *AuditLogRepository {
	return &AuditLogRepository{db: db}
}

func (r *AuditLogRepository) List(ctx context.Context, filter port.AuditLogFilter) ([]port.AuditLogEntry, error) {
	where, args := r.buildWhere(filter)

	argIdx := len(args) + 1
	query := auditLogListQuery
	if where != "" {
		query += " WHERE " + where
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, filter.Limit, filter.Offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := []port.AuditLogEntry{}
	for rows.Next() {
		var e port.AuditLogEntry
		var parsedUA, metadata sql.NullString
		if err := rows.Scan(
			&e.ID, &e.Type, &e.Severity, &e.Success,
			&e.ActorID, &e.TargetUserID, &e.SessionID, &e.OrgID,
			&e.IP, &e.UserAgent, &parsedUA, &e.RequestID, &e.CorrelationID,
			&metadata, &e.CreatedAt,
		); err != nil {
			return nil, err
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
	return entries, rows.Err()
}

// Count returns how many audit entries match filter (Offset/Limit ignored).
func (r *AuditLogRepository) Count(ctx context.Context, filter port.AuditLogFilter) (int, error) {
	where, args := r.buildWhere(filter)
	q := auditLogCountQuery
	if where != "" {
		q += " WHERE " + where
	}
	var total int
	if err := r.db.QueryRowContext(ctx, q, args...).Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// CountByDay returns event counts per day matching filter — Offset/Limit on
// filter are ignored, the result is naturally bounded by filter.FromDate/ToDate.
func (r *AuditLogRepository) CountByDay(ctx context.Context, filter port.AuditLogFilter) ([]port.DailyCount, error) {
	where, args := r.buildWhere(filter)

	var dayExpr string
	switch r.db.Driver() {
	case "mysql":
		dayExpr = "DATE(created_at)"
	case "sqlite", "sqlite3":
		// Not date(created_at): modernc.org/sqlite stores time.Time as
		// RFC3339Nano text ("...2026-08-19T19:21:36.275883607Z"), and
		// SQLite's date() can't parse 9-digit fractional seconds — it
		// silently returns NULL. The stored format's first 10 characters
		// are always the ISO date, so substr sidesteps date() entirely.
		dayExpr = "substr(created_at, 1, 10)"
	default: // postgres
		dayExpr = "date_trunc('day', created_at)"
	}

	query := "SELECT " + dayExpr + " AS day, COUNT(*) FROM audit_log"
	if where != "" {
		query += " WHERE " + where
	}
	query += " GROUP BY day ORDER BY day"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var counts []port.DailyCount
	for rows.Next() {
		var c port.DailyCount
		var day time.Time
		if r.db.Driver() == "sqlite" || r.db.Driver() == "sqlite3" {
			// modernc.org/sqlite returns date() as a string, not a time.Time.
			var dayStr string
			if err := rows.Scan(&dayStr, &c.Count); err != nil {
				return nil, err
			}
			day, err = time.Parse("2006-01-02", dayStr)
			if err != nil {
				return nil, err
			}
		} else {
			if err := rows.Scan(&day, &c.Count); err != nil {
				return nil, err
			}
		}
		c.Date = day
		counts = append(counts, c)
	}
	if counts == nil {
		counts = []port.DailyCount{}
	}
	return counts, rows.Err()
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

// deviceTypeExpr is the driver-conditional JSON path into parsed_ua's
// deviceType field — the same three-way branch used for day-bucketing in
// UserRepository.CountByDay, applied to a different column.
func (r *AuditLogRepository) deviceTypeExpr() string {
	switch r.db.Driver() {
	case "mysql":
		return "JSON_UNQUOTE(JSON_EXTRACT(parsed_ua, '$.deviceType'))"
	case "sqlite", "sqlite3":
		return "json_extract(parsed_ua, '$.deviceType')"
	default: // postgres
		return "parsed_ua->>'deviceType'"
	}
}

func (r *AuditLogRepository) buildWhere(filter port.AuditLogFilter) (string, []any) {
	var conditions []string
	var args []any
	argIdx := 1

	if len(filter.Types) > 0 {
		placeholders := make([]string, len(filter.Types))
		for i, t := range filter.Types {
			placeholders[i] = fmt.Sprintf("$%d", argIdx)
			args = append(args, t)
			argIdx++
		}
		conditions = append(conditions, fmt.Sprintf("event_type IN (%s)", strings.Join(placeholders, ", ")))
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
	if filter.DeviceType != nil && *filter.DeviceType != "" {
		conditions = append(conditions, fmt.Sprintf("%s = $%d", r.deviceTypeExpr(), argIdx))
		args = append(args, *filter.DeviceType)
		argIdx++
	}
	if filter.IP != nil && *filter.IP != "" {
		conditions = append(conditions, fmt.Sprintf("ip = $%d", argIdx))
		args = append(args, *filter.IP)
		argIdx++
	}
	if filter.Success != nil {
		conditions = append(conditions, fmt.Sprintf("success = $%d", argIdx))
		args = append(args, *filter.Success)
		argIdx++
	}
	if filter.Search != nil && *filter.Search != "" {
		searchPattern := "%" + *filter.Search + "%"
		switch r.db.Driver() {
		case "mysql":
			conditions = append(conditions, fmt.Sprintf(
				"(JSON_UNQUOTE(JSON_EXTRACT(metadata, '$')) LIKE $%d OR user_agent LIKE $%d OR ip LIKE $%d OR event_type LIKE $%d)",
				argIdx, argIdx+1, argIdx+2, argIdx+3))
		case "sqlite", "sqlite3":
			conditions = append(conditions, fmt.Sprintf(
				"(metadata LIKE $%d OR user_agent LIKE $%d OR ip LIKE $%d OR event_type LIKE $%d)",
				argIdx, argIdx+1, argIdx+2, argIdx+3))
		default:
			conditions = append(conditions, fmt.Sprintf(
				"(metadata::text ILIKE $%d OR user_agent ILIKE $%d OR ip ILIKE $%d OR event_type ILIKE $%d)",
				argIdx, argIdx+1, argIdx+2, argIdx+3))
		}
		// Four distinct placeholders, not one reused: DB.Rebind rewrites
		// every textual "$N" positionally for mysql/sqlite, so each textual
		// occurrence needs its own (equal-valued) args entry.
		args = append(args, searchPattern, searchPattern, searchPattern, searchPattern)
		argIdx += 4
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
