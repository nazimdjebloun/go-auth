package service

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// RecoveryWorker owns delivery after the account-independent public enqueue.
// Requests survive shutdown; unfinished claims become eligible after the lease.
type RecoveryWorker struct {
	store    port.RecoveryStore
	password *PasswordService
	verify   *VerificationService
	log      *slog.Logger
	cancel   context.CancelFunc
	done     chan struct{}
	stop     sync.Once
}

// NewRecoveryWorker attaches durable enqueueing to both public recovery
// operations. Start it only after application construction succeeds.
func NewRecoveryWorker(store port.RecoveryStore, password *PasswordService, verify *VerificationService, log *slog.Logger) *RecoveryWorker {
	if log == nil {
		log = slog.Default()
	}
	password.recovery = store
	verify.recovery = store
	return &RecoveryWorker{store: store, password: password, verify: verify, log: log}
}

func enqueueRecovery(ctx context.Context, queue port.RecoveryEnqueuer, kind port.RecoveryKind, email string, log *slog.Logger) error {
	email = strings.TrimSpace(strings.ToLower(email))
	// Invalid input is rejected without consulting account state. Bound both the
	// persistent payload and the work caused by unauthenticated callers.
	if len(email) > 254 || validateEmail(email) != nil {
		return nil
	}
	if err := queue.Enqueue(ctx, kind, email); err != nil {
		log.Error("failed to enqueue recovery request", "err", err)
		return domain.ErrInternal
	}
	return nil
}

// Start begins delivery and retention cleanup. Call it once before Stop.
func (w *RecoveryWorker) Start(ctx context.Context) {
	workerCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.done = make(chan struct{})
	go func() {
		defer close(w.done)
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		pruneTicker := time.NewTicker(time.Minute)
		defer pruneTicker.Stop()
		var nextErrorLog time.Time
		for {
			select {
			case <-workerCtx.Done():
				return
			case <-pruneTicker.C:
				pruneCtx, cancel := context.WithTimeout(workerCtx, 5*time.Second)
				err := w.store.Prune(pruneCtx, time.Now())
				cancel()
				if err != nil && workerCtx.Err() == nil {
					w.log.Error("recovery request pruning failed", "err", err)
				}
			case <-ticker.C:
				_, err := w.ProcessOne(workerCtx)
				if err != nil && workerCtx.Err() == nil && time.Now().After(nextErrorLog) {
					w.log.Error("recovery request processing failed", "err", err)
					nextErrorLog = time.Now().Add(5 * time.Second)
				}
			}
		}
	}()
}

// Stop cancels processing and waits for delivery to exit. Unfinished claims
// remain durable and can be reclaimed after their lease expires.
func (w *RecoveryWorker) Stop() {
	w.stop.Do(func() {
		if w.cancel != nil {
			w.cancel()
			<-w.done
		}
	})
}

// ProcessOne claims and processes one request, with no database transaction
// held during rendering or delivery. It is also useful for deterministic tests.
func (w *RecoveryWorker) ProcessOne(ctx context.Context) (bool, error) {
	claimCtx, cancelClaim := context.WithTimeout(ctx, 5*time.Second)
	request, err := w.store.Claim(claimCtx, time.Now(), 2*time.Minute)
	cancelClaim()
	if err != nil || request == nil {
		return false, err
	}
	if request.Attempts > 5 {
		err = errors.New("recovery request attempt budget exhausted")
	} else {
		deliveryCtx, cancelDelivery := context.WithTimeout(ctx, 30*time.Second)
		switch request.Kind {
		case port.RecoveryPasswordReset:
			err = w.password.sendPasswordReset(deliveryCtx, api.ForgotPasswordInput{Email: request.Email})
		case port.RecoveryVerification:
			err = w.verify.sendVerificationByEmail(deliveryCtx, request.Email, request.Attempts > 1)
		default:
			err = errors.New("unsupported recovery request kind")
		}
		cancelDelivery()
	}
	completeCtx, cancelComplete := context.WithTimeout(ctx, 5*time.Second)
	completeErr := w.store.Complete(completeCtx, *request, err == nil, time.Now())
	cancelComplete()
	return true, errors.Join(err, completeErr)
}
