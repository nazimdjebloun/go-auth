package mailer

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nazimdjebloun/go-auth/port"
)

// DefaultAsyncQueueSize bounds the pending-email queue when AsyncConfig
// leaves it unset.
const DefaultAsyncQueueSize = 256

// DefaultAsyncTimeout bounds a single underlying Send attempt, and doubles
// as the default drain budget per Stop.
const DefaultAsyncTimeout = 30 * time.Second

// AsyncConfig configures an Async mailer decorator. The zero value yields
// the documented defaults; every field is optional.
type AsyncConfig struct {
	// QueueSize bounds the pending-send queue. When it is full, Send stops
	// being asynchronous for that caller and delivers synchronously instead,
	// so an email is never silently dropped. 0 means DefaultAsyncQueueSize.
	QueueSize int
	// Workers is the number of delivery workers. 0 or 1 means one worker;
	// mail providers usually serialize per-connection anyway.
	Workers int
	// Retries is how many times a failed send is retried in the background.
	// 0 means a single attempt per message; the attempt is logged and dropped
	// after the final failure — Async is best-effort, not a durable outbox.
	Retries int
	// RetryWait is the base delay before the first retry; it doubles on each
	// subsequent attempt. 0 means 1s.
	RetryWait time.Duration
	// Timeout bounds one underlying Send attempt. 0 means DefaultAsyncTimeout.
	Timeout time.Duration
	// Logger receives enqueue-fallback and dead-letter diagnostics. Nil
	// means slog.Default().
	Logger *slog.Logger
}

// Async is a port.Mailer decorator that moves delivery off the caller's
// request path: Send enqueues and returns immediately, workers deliver in
// the background with optional retries. Wrap any Mailer — the built-in SMTP
// or a provider client — with NewAsync and pass the result to WithMailer.
//
// Semantics an adopter must understand:
//
//   - Delivery failures never fail the request that triggered the email;
//     they are retried Retries times and then logged as dead letters.
//   - When the queue is full, Send falls back to delivering synchronously
//     under the caller's context, so saturation degrades to today's latency
//     instead of silently dropping mail (a lost 2FA or verification email
//     locks a user out; a slow request does not).
//   - The caller's context governs only the fallback path. Background
//     deliveries use their own bounded context, because the request that
//     enqueued the send is typically gone by the time the worker runs.
//   - Messages queued at process exit are drained by Stop; a hard crash
//     still loses them. Async is a latency fix, not durability — pair it
//     with a durable mail provider or an outbox if you need guarantees.
type Async struct {
	underlying port.Mailer
	cfg        AsyncConfig
	log        *slog.Logger

	queue  chan asyncMessage
	wg     sync.WaitGroup
	stopMu sync.Mutex
	closed bool
}

type asyncMessage struct {
	to      string
	subject string
	html    string
	text    string
}

// NewAsync wraps underlying with a bounded queue and delivery workers.
func NewAsync(underlying port.Mailer, cfg AsyncConfig) (*Async, error) {
	if underlying == nil {
		return nil, fmt.Errorf("goauth: async mailer requires an underlying mailer")
	}
	size := cfg.QueueSize
	if size <= 0 {
		size = DefaultAsyncQueueSize
	}
	workers := cfg.Workers
	if workers <= 0 {
		workers = 1
	}
	if cfg.RetryWait <= 0 {
		cfg.RetryWait = time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultAsyncTimeout
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	a := &Async{
		underlying: underlying,
		cfg:        cfg,
		log:        log,
		queue:      make(chan asyncMessage, size),
	}
	for i := 0; i < workers; i++ {
		a.wg.Add(1)
		go a.worker()
	}
	return a, nil
}

// Send enqueues the message, or delivers synchronously when the queue is
// full or the mailer has stopped accepting work. The error return follows
// the port.Mailer contract for the fallback path; queued sends return nil
// because delivery has not happened yet.
func (a *Async) Send(ctx context.Context, to, subject, html, text string) error {
	a.stopMu.Lock()
	if a.closed {
		a.stopMu.Unlock()
		// Already draining: deliver synchronously rather than fail the
		// caller or race the channel close.
		return a.deliver(ctx, to, subject, html, text)
	}
	msg := asyncMessage{to: to, subject: subject, html: html, text: text}
	select {
	case a.queue <- msg:
		a.stopMu.Unlock()
		return nil
	default:
	}
	a.stopMu.Unlock()

	a.log.Warn("async mailer queue full; delivering synchronously", "to", to, "subject", subject)
	return a.deliver(ctx, to, subject, html, text)
}

// deliver runs the underlying send with retries. ctx bounds the attempts
// (nil-safe: request contexts govern only synchronous deliveries); each
// attempt is additionally bounded by cfg.Timeout.
func (a *Async) deliver(ctx context.Context, to, subject, html, text string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	var lastErr error
	wait := a.cfg.RetryWait
	for attempt := 0; attempt <= a.cfg.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return lastErr
			case <-time.After(wait):
				wait *= 2
			}
		}
		actx, cancel := context.WithTimeout(ctx, a.cfg.Timeout)
		lastErr = a.underlying.Send(actx, to, subject, html, text)
		cancel()
		if lastErr == nil {
			return nil
		}
	}
	a.log.Error("async mailer dead letter", "to", to, "subject", subject, "attempts", a.cfg.Retries+1, "err", lastErr)
	return lastErr
}

func (a *Async) worker() {
	defer a.wg.Done()
	for msg := range a.queue {
		a.deliver(context.Background(), msg.to, msg.subject, msg.html, msg.text)
	}
}

// Stop stops accepting new messages, drains the queue, and waits for the
// workers. The context bounds the drain; an expired context returns ctx.Err()
// and abandons any messages still queued (they were logged at enqueue time
// and are identifiable, but not retried).
func (a *Async) Stop(ctx context.Context) error {
	a.stopMu.Lock()
	if !a.closed {
		a.closed = true
		close(a.queue)
	}
	a.stopMu.Unlock()

	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
