package api

import (
	"encoding/json"
	"time"
)

// AuditLogEntry is a persisted audit event returned by audit queries.
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

// DailyCount is one bucket of a day-by-day aggregate — the shape both
// UserRepository.CountByDay and AuditLogRepository.CountByDay return, for
// building a registrations-over-time chart or a GitHub-style login heatmap
// without pulling raw rows client-side.
type DailyCount struct {
	Date  time.Time `json:"date"` // truncated to day, UTC
	Count int       `json:"count"`
}
