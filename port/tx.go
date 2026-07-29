package port

import "context"

// TxManager executes a function within a database transaction boundary.
// If fn returns an error, the transaction is rolled back; otherwise it is committed.
type TxManager interface {
	WithTx(ctx context.Context, fn func(ctx context.Context) error) error
}
