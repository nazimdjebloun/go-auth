package testutil

import (
	"context"
)

type MockTxManager struct{}

func (m *MockTxManager) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}
