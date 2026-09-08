package testutil

import (
	"context"
)

type MockTxManager struct{}

func (m *MockTxManager) WithTx(_ context.Context, fn func(ctx context.Context) error) error {
	return fn(context.Background())
}
