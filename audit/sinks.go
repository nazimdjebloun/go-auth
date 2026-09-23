package audit

import (
	"context"
	"log/slog"
	"time"
)

// LoggerSink writes audit events to a structured logger.
type LoggerSink struct {
	log *slog.Logger
}

// NewLoggerSink returns an audit sink backed by a logger.
func NewLoggerSink(log *slog.Logger) *LoggerSink {
	if log == nil {
		log = slog.Default()
	}
	return &LoggerSink{log: log}
}

// Handle logs one audit event.
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

// HandleBatch logs each audit event in order.
func (s *LoggerSink) HandleBatch(ctx context.Context, events []Event) error {
	for _, e := range events {
		if err := s.Handle(ctx, e); err != nil {
			return err
		}
	}
	return nil
}
