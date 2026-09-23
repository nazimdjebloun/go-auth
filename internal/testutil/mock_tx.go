package testutil

import (
	"context"
)

// MockTxManager runs transaction callbacks inline.
type MockTxManager struct{}

// WithTx runs fn with the provided context.
func (m *MockTxManager) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}
