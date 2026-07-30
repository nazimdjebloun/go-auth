package audit

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

type AuditService struct {
	sinks []EventSink
	log   *slog.Logger
	mu    sync.RWMutex
}

func NewAuditService(log *slog.Logger) *AuditService {
	if log == nil {
		log = slog.Default()
	}
	return &AuditService{log: log}
}

func (s *AuditService) AddSink(sink EventSink) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sinks = append(s.sinks, sink)
}

func (s *AuditService) Publish(ctx context.Context, event Event) {
	if event.ID == "" {
		event.ID = generateID()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}

	s.mu.RLock()
	sinks := make([]EventSink, len(s.sinks))
	copy(sinks, s.sinks)
	s.mu.RUnlock()

	for _, sink := range sinks {
		if err := sink.Handle(ctx, event); err != nil {
			s.log.ErrorContext(ctx, "audit sink error",
				"event_type", event.Type,
				"event_id", event.ID,
				"error", err,
			)
		}
	}
}

func generateID() string {
	return uuid.New().String()
}
