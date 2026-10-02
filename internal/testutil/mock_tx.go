package testutil

import (
	"context"
	"sync"
)

// MockTxManager models callback commit/rollback for the repositories in this
// package. Operations must use the callback context to participate. It does not
// model SQL isolation, constraints, savepoints, or durable audit writes; use
// real SQL fixtures for those guarantees and races with nontransactional writes.
type MockTxManager struct{}

type mockTxKey struct{}

type mockSnapshotter interface {
	mockSnapshot() func()
}

type mockTransaction struct {
	mu       sync.Mutex
	seen     map[mockSnapshotter]bool
	rollback []func()
}

// Serialize mock transactions across managers sharing the same repositories.
// Repository methods still lock normally; callbacks must join their goroutines
// and must not let the transaction context escape.
var mockTxGate = make(chan struct{}, 1)

func recordMockTx(ctx context.Context, repo mockSnapshotter) {
	tx, _ := ctx.Value(mockTxKey{}).(*mockTransaction)
	if tx == nil {
		return
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if !tx.seen[repo] {
		tx.rollback = append(tx.rollback, repo.mockSnapshot())
		tx.seen[repo] = true
	}
}

// WithTx snapshots each repository on first use and restores its rows after a
// callback failure, cancellation, or panic. Nested calls reuse the parent.
func (m *MockTxManager) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ctx.Value(mockTxKey{}) != nil {
		return fn(ctx)
	}
	select {
	case mockTxGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	tx := &mockTransaction{seen: make(map[mockSnapshotter]bool)}
	committed := false
	defer func() {
		if !committed {
			for i := len(tx.rollback) - 1; i >= 0; i-- {
				tx.rollback[i]()
			}
		}
		<-mockTxGate
	}()
	if err := fn(context.WithValue(ctx, mockTxKey{}, tx)); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	committed = true
	return nil
}
