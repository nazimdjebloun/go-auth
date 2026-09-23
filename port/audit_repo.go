package port

import (
	"context"
	"encoding/json"
	"time"
)

// AuditLogFilter narrows audit-log queries.
type AuditLogFilter struct {
	// Types matches any of the listed event types ("IN (...)"); nil/empty
	// means no filter. A single-element slice is the old single-Type filter.
	Types        []string
	ActorID      *string
	TargetUserID *string
	SessionID    *string
	OrgID        *string
	// DeviceType matches parsed_ua's deviceType field exactly — "mobile",
	// "desktop", "tablet", or "bot" (see domain.ParseUserAgent).
	DeviceType *string
	// IP matches the ip column exactly. Search below still substring-matches
	// it too, for a fuzzy "which of these events came from that address"
	// lookup without knowing the exact stored value.
	IP      *string
	Success *bool
	// Search substring-matches metadata, user_agent, ip, and event_type —
	// broader than any single field filter, for a general free-text box.
	Search   *string
	FromDate *time.Time
	ToDate   *time.Time
	Offset   int
	Limit    int
}

// AuditLogEntry had no JSON tags until this comment's change — every field
// marshaled under its bare Go name ("ActorID", "CreatedAt", ...), not the
// camelCase the docs and the dashboard client always assumed. Pre-release,
// so fixing the mismatch outright rather than carrying it forward.
type AuditLogEntry struct {
	ID            string          `json:"id"`
	Type          string          `json:"type"`
	Severity      string          `json:"severity"`
	Success       bool            `json:"success"`
	ActorID       *string         `json:"actorId,omitempty"`
	TargetUserID  *string         `json:"targetUserId,omitempty"`
	SessionID     *string         `json:"sessionId,omitempty"`
	OrgID         *string         `json:"orgId,omitempty"`
	IP            string          `json:"ip,omitempty"`
	UserAgent     string          `json:"userAgent,omitempty"`
	ParsedUA      json.RawMessage `json:"parsedUA,omitempty"`
	RequestID     string          `json:"requestId,omitempty"`
	CorrelationID string          `json:"correlationId,omitempty"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
	CreatedAt     time.Time       `json:"createdAt"`
}

// AuditLogRepository reads persisted audit events.
type AuditLogRepository interface {
	// List returns a page of audit entries; use Count for the total.
	List(ctx context.Context, filter AuditLogFilter) ([]AuditLogEntry, error)
	// Count returns how many audit entries match filter (Offset/Limit ignored).
	Count(ctx context.Context, filter AuditLogFilter) (int, error)
	GetByID(ctx context.Context, id string) (*AuditLogEntry, error)
	// CountByDay returns event counts per day matching filter (Offset/Limit
	// on filter are ignored, same reasoning as UserRepository.CountByDay).
	CountByDay(ctx context.Context, filter AuditLogFilter) ([]DailyCount, error)
}
