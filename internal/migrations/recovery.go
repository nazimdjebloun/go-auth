package migrations

import (
	"context"
	"fmt"
)

func checkPreconditions(ctx context.Context, q queryer, step Step, options Options) error {
	ctx, cancel := context.WithTimeout(ctx, options.StatementTimeout)
	defer cancel()
	if err := checkQueries(ctx, q, step.Preconditions, "data precondition"); err != nil {
		return fmt.Errorf("%w: %w", ErrPrecondition, err)
	}
	if step.Retry != nil {
		if err := checkQueries(ctx, q, step.Retry.Checks, "retry precondition"); err != nil {
			return fmt.Errorf("%w: %w", ErrPrecondition, err)
		}
	}
	return ctx.Err()
}

// The caller holds the dedicated migration lease from inspection to completion.
// Reconciliation is an operator procedure; this function never rolls data back,
// skips statements or infers that partial DDL is safe to replay.
func retryStep(ctx context.Context, q queryer, catalog Catalog, status Status, id int64, options Options) (Status, error) {
	fail := func(phase string, cause error) (Status, error) {
		return status, &Error{Dialect: catalog.Dialect, MigrationID: id, Phase: phase, Dirty: status.Dirty, Cause: cause}
	}
	index := len(status.History) - 1
	if !status.Dirty || index < 0 || status.History[index].ID != id {
		return fail("retry identity", fmt.Errorf("%w: retry requires the exact incomplete migration ID", ErrDirty))
	}
	step := catalog.Migrations[index]
	if index == 0 || step.Transactional || step.Retry == nil {
		return fail("retry policy", ErrRetryUnsupported)
	}
	if err := verifyStep(ctx, q, catalog, catalog.Migrations[index-1]); err != nil {
		return fail("retry starting schema", err)
	}
	if err := checkPreconditions(ctx, q, step, options); err != nil {
		return fail("retry preconditions", err)
	}
	if err := executeStep(ctx, q, catalog, step, options); err != nil {
		return status, err
	}
	return readHistory(ctx, q, catalog)
}
