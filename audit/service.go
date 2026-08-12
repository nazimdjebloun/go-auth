package audit

import (
	"context"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/domain"
)

type AuditFailureMode int

const (
	AuditFailureOpen AuditFailureMode = iota
	AuditFailureClosed
)

type AuditServiceConfig struct {
	FailureMode   AuditFailureMode
	QueueSize     int
	Workers       int
	BatchSize     int
	FlushInterval time.Duration
	RetentionDays int
}

func defaultConfig(cfg AuditServiceConfig) AuditServiceConfig {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 1000
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 3
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 50
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 100 * time.Millisecond
	}
	if cfg.RetentionDays < 0 {
		cfg.RetentionDays = 0
	}
	return cfg
}

type AuditService struct {
	queue         chan Event
	sinks         []EventSink
	failureMode   AuditFailureMode
	enabled       bool
	queueSize     int
	workers       int
	batchSize     int
	flushInterval time.Duration
	retentionDays int
	log           *slog.Logger
	mu            sync.RWMutex
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	queueOnce     sync.Once
}

func NewAuditService(cfg AuditServiceConfig, log *slog.Logger) *AuditService {
	if log == nil {
		log = slog.Default()
	}
	cfg = defaultConfig(cfg)
	return &AuditService{
		queue:         make(chan Event, cfg.QueueSize),
		failureMode:   cfg.FailureMode,
		enabled:       true,
		queueSize:     cfg.QueueSize,
		workers:       cfg.Workers,
		batchSize:     cfg.BatchSize,
		flushInterval: cfg.FlushInterval,
		retentionDays: cfg.RetentionDays,
		log:           log,
	}
}

func (s *AuditService) AddSink(sink EventSink) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sinks = append(s.sinks, sink)
}

func (s *AuditService) Publish(ctx context.Context, event Event) {
	if !s.enabled {
		return
	}
	if event.UserAgent != "" && event.ParsedUA == nil {
		event.ParsedUA = domain.ParseUserAgent(event.UserAgent)
	}
	select {
	case s.queue <- event:
	default:
		s.log.WarnContext(ctx, "audit queue full, event dropped",
			"event_type", event.Type,
		)
	}
}

func (s *AuditService) Start(ctx context.Context) {
	ctx, s.cancel = context.WithCancel(ctx)

	for i := 0; i < s.workers; i++ {
		s.wg.Add(1)
		go s.worker(ctx, i)
	}

	if s.retentionDays > 0 && s.hasCleaner() {
		go s.startRetentionCleanup(ctx)
	}
}

func (s *AuditService) Stop(ctx context.Context) error {
	if s.cancel != nil {
		s.cancel()
	}
	s.queueOnce.Do(func() { close(s.queue) })
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *AuditService) hasCleaner() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sink := range s.sinks {
		if _, ok := sink.(Cleaner); ok {
			return true
		}
	}
	return false
}

func (s *AuditService) worker(ctx context.Context, id int) {
	defer s.wg.Done()

	batch := make([]Event, 0, s.batchSize)
	timer := time.NewTimer(s.flushInterval)
	defer timer.Stop()

	for {
		select {
		case event, ok := <-s.queue:
			if !ok {
				s.flushBatch(ctx, batch)
				return
			}
			batch = append(batch, event)
			if len(batch) >= s.batchSize {
				s.flushBatch(ctx, batch)
				batch = batch[:0]
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(s.flushInterval)
			}
		case <-timer.C:
			if len(batch) > 0 {
				s.flushBatch(ctx, batch)
				batch = batch[:0]
			}
			timer.Reset(s.flushInterval)
		case <-ctx.Done():
			// Stop() cancels ctx and closes the queue at roughly the same
			// time, so this case and the queue-read case above can both be
			// ready together: an event already sitting in the queue's
			// buffer hasn't necessarily been read into batch yet. Drain
			// whatever's left, non-blocking, before flushing — otherwise a
			// published-then-immediately-stopped event is silently lost
			// depending on which ready case the scheduler happens to pick.
		drain:
			for {
				select {
				case event, ok := <-s.queue:
					if !ok {
						break drain
					}
					batch = append(batch, event)
				default:
					break drain
				}
			}
			if len(batch) > 0 {
				s.flushBatch(ctx, batch)
			}
			return
		}
	}
}

func (s *AuditService) flushBatch(ctx context.Context, batch []Event) {
	if len(batch) == 0 {
		return
	}
	s.mu.RLock()
	sinks := make([]EventSink, len(s.sinks))
	copy(sinks, s.sinks)
	s.mu.RUnlock()

	for _, sink := range sinks {
		if err := sink.HandleBatch(ctx, batch); err != nil {
			if s.failureMode == AuditFailureClosed {
				s.log.ErrorContext(ctx, "audit sink batch error (fail-closed)",
					"sink", reflect.TypeOf(sink), "error", err, "batch_size", len(batch))
				return
			}
			s.log.ErrorContext(ctx, "audit sink batch error (fail-open)",
				"sink", reflect.TypeOf(sink), "error", err, "batch_size", len(batch))
		}
	}
}

func (s *AuditService) startRetentionCleanup(ctx context.Context) {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.RLock()
			sinks := make([]EventSink, len(s.sinks))
			copy(sinks, s.sinks)
			s.mu.RUnlock()

			for _, sink := range sinks {
				if cleaner, ok := sink.(Cleaner); ok {
					deleted, err := cleaner.Cleanup(ctx, s.retentionDays)
					if err != nil {
						s.log.ErrorContext(ctx, "audit retention cleanup failed",
							"sink", reflect.TypeOf(sink), "error", err)
					} else if deleted > 0 {
						s.log.InfoContext(ctx, "audit retention cleanup completed",
							"sink", reflect.TypeOf(sink), "deleted", deleted)
					}
				}
			}
		}
	}
}

func generateID() string {
	return uuid.New().String()
}
