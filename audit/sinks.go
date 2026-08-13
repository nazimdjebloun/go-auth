package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
)

type SQLAuditSink struct {
	db *sqlstore.DB
}

// NewSQLAuditSink builds an audit sink writing to the audit_log table over
// db. driver identifies the SQL dialect ("postgres", "mysql", "sqlite3", ...)
// and controls placeholder rebinding ($1 vs ?) the same way it does for
// goauth.New's own database connection.
func NewSQLAuditSink(db *sql.DB, driver string) *SQLAuditSink {
	return &SQLAuditSink{db: sqlstore.NewDB(db, driver)}
}

// storedUserAgent is the audit_log.parsed_ua on-disk shape. Audit rows are
// retained (see AuditServiceConfig.RetentionDays), not replaced the way a
// session row is on its next refresh, so unlike Session.ParsedUA this can't
// just be re-derived from the raw user agent on every read — a stored row is
// a permanent historical record of what was understood at write time. It's
// deliberately its own type with its own frozen tags, not domain.UserAgentInfo
// directly, so a future change to that struct's wire-facing JSON tags (it's
// also the shape of Session.ParsedUA in API responses) can never silently
// change what's already on disk in this column. Add fields here explicitly
// if domain.UserAgentInfo grows one worth persisting — don't switch this back
// to embedding/aliasing that type.
type storedUserAgent struct {
	Browser        string `json:"browser"`
	BrowserVersion string `json:"browserVersion,omitempty"`
	OS             string `json:"os"`
	OSVersion      string `json:"osVersion,omitempty"`
	DeviceType     string `json:"deviceType"`
}

func newStoredUserAgent(u *domain.UserAgentInfo) *storedUserAgent {
	if u == nil {
		return nil
	}
	return &storedUserAgent{
		Browser:        u.BrowserName,
		BrowserVersion: u.BrowserVersion,
		OS:             u.OS,
		OSVersion:      u.OSVersion,
		DeviceType:     u.DeviceType,
	}
}

func (s *SQLAuditSink) Handle(ctx context.Context, event Event) error {
	return s.HandleBatch(ctx, []Event{event})
}

func (s *SQLAuditSink) HandleBatch(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}

	cols := `id, event_type, severity, success, actor_id, target_id,
		session_id, org_id, ip, user_agent, parsed_ua, request_id, correlation_id, metadata, created_at`

	var rows []string
	for i := 0; i < len(events); i++ {
		offset := i * 15
		placeholders := make([]string, 15)
		for j := 0; j < 15; j++ {
			placeholders[j] = fmt.Sprintf("$%d", offset+j+1)
		}
		rows = append(rows, "("+fmt.Sprintf("%s", joinPlaceholders(placeholders))+")")
	}

	query := fmt.Sprintf("INSERT INTO audit_log (%s) VALUES %s", cols, joinRows(rows))
	query = s.db.Rebind(query)

	var args []any
	for _, e := range events {
		var metaJSON []byte
		if e.Metadata != nil {
			var err error
			metaJSON, err = json.Marshal(e.Metadata)
			if err != nil {
				return fmt.Errorf("marshal metadata: %w", err)
			}
		}

		var parsedUARaw []byte
		if stored := newStoredUserAgent(e.ParsedUA); stored != nil {
			var err error
			parsedUARaw, err = json.Marshal(stored)
			if err != nil {
				return fmt.Errorf("marshal parsed_ua: %w", err)
			}
		}

		ipStr := ""
		if e.IP != nil {
			ipStr = e.IP.String()
		}

		args = append(args,
			e.ID, string(e.Type), string(e.Severity), e.Success,
			e.ActorID, e.TargetUserID, e.SessionID, e.OrgID,
			ipStr, e.UserAgent, parsedUARaw, e.RequestID, e.CorrelationID,
			metaJSON, e.CreatedAt.UTC(),
		)
	}

	tx, err := s.db.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("batch insert: %w", err)
	}

	return tx.Commit()
}

func (s *SQLAuditSink) Cleanup(ctx context.Context, retentionDays int) (int, error) {
	if retentionDays <= 0 {
		return 0, nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	query := s.db.Rebind(`DELETE FROM audit_log WHERE created_at < $1`)
	result, err := s.db.DB.ExecContext(ctx, query, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	return int(n), nil
}

func joinPlaceholders(ps []string) string {
	result := ""
	for i, p := range ps {
		if i > 0 {
			result += ", "
		}
		result += p
	}
	return result
}

func joinRows(rows []string) string {
	result := ""
	for i, r := range rows {
		if i > 0 {
			result += ", "
		}
		result += r
	}
	return result
}

type LoggerSink struct {
	log *slog.Logger
}

func NewLoggerSink(log *slog.Logger) *LoggerSink {
	if log == nil {
		log = slog.Default()
	}
	return &LoggerSink{log: log}
}

func (s *LoggerSink) Handle(ctx context.Context, event Event) error {
	attrs := []any{
		"event_id", event.ID,
		"event_type", string(event.Type),
		"severity", string(event.Severity),
		"success", event.Success,
		"created_at", event.CreatedAt.Format(time.RFC3339Nano),
	}
	if event.ActorID != nil {
		attrs = append(attrs, "actor_id", *event.ActorID)
	}
	if event.TargetUserID != nil {
		attrs = append(attrs, "target_user_id", *event.TargetUserID)
	}
	if event.SessionID != nil {
		attrs = append(attrs, "session_id", *event.SessionID)
	}
	if event.OrgID != nil {
		attrs = append(attrs, "org_id", *event.OrgID)
	}
	if event.IP != nil {
		attrs = append(attrs, "ip", event.IP.String())
	}
	if event.UserAgent != "" {
		attrs = append(attrs, "user_agent", event.UserAgent)
	}
	if event.RequestID != "" {
		attrs = append(attrs, "request_id", event.RequestID)
	}
	if event.CorrelationID != "" {
		attrs = append(attrs, "correlation_id", event.CorrelationID)
	}
	if event.Metadata != nil {
		attrs = append(attrs, "metadata", event.Metadata)
	}

	s.log.InfoContext(ctx, "audit_event", attrs...)
	return nil
}

func (s *LoggerSink) HandleBatch(ctx context.Context, events []Event) error {
	for _, e := range events {
		if err := s.Handle(ctx, e); err != nil {
			return err
		}
	}
	return nil
}
