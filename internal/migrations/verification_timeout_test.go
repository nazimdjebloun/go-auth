package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"
)

type verificationProbe struct {
	queryer
	contexts []context.Context
	block    string
	cancel   context.CancelFunc
	reached  bool
}

func (p *verificationProbe) observe(ctx context.Context, query string) bool {
	p.contexts = append(p.contexts, ctx)
	if p.block == "*" || query == p.block {
		p.reached = true
		if p.cancel != nil {
			p.cancel()
		}
		<-ctx.Done()
		return true
	}
	return false
}

func (p *verificationProbe) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	if p.observe(ctx, query) {
		return nil, ctx.Err()
	}
	return p.queryer.QueryContext(ctx, query, args...)
}

func (p *verificationProbe) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	if p.observe(ctx, query) {
		return p.queryer.QueryRowContext(ctx, "SELECT 1")
	}
	return p.queryer.QueryRowContext(ctx, query, args...)
}

func TestVerificationPostconditionCancellationRollsBackAndRestoresConnection(t *testing.T) {
	db := migrationDB(t)
	upgradeExec(t, db, "sqlite", "PRAGMA busy_timeout=217")
	applyOwnershipBaseline(t, db, "sqlite")
	catalog := ownershipBaselineCatalog(t, "sqlite")
	ddl := "CREATE TABLE verification_marker (\n    id INTEGER PRIMARY KEY\n);\n"
	catalog = appendOwnershipStep(t, catalog, catalog.Migrations[0].schemaSQL+"\n"+ddl, ddl)
	catalog.Migrations[1].Checks = []string{"SELECT 42=42"}
	catalog = validateFixture(t, catalog)
	options, err := (Options{Driver: "sqlite", StatementTimeout: 5 * time.Second}).defaults()
	if err != nil {
		t.Fatal(err)
	}
	l, err := acquire(t.Context(), db, catalog, options)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = l.close(t.Context(), false)
		}
	})
	step := catalog.Migrations[1]
	if err := startRecord(t.Context(), l.conn, catalog, step, "executed"); err != nil {
		t.Fatal(err)
	}
	caller, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	probe := &verificationProbe{queryer: l.conn, block: "SELECT 42=42", cancel: cancel}
	err = executeStep(caller, probe, catalog, step, options)
	var failure *Error
	if !errors.Is(err, context.Canceled) || !errors.As(err, &failure) || failure.Phase != "postconditions" || failure.Dirty {
		t.Fatalf("postcondition cancellation lost its cause or transaction state: %v", err)
	}
	if !probe.reached {
		t.Fatal("cancellation did not reach the intended data postcondition")
	}
	state, err := readHistory(t.Context(), l.conn, catalog)
	if err != nil || !state.Dirty || state.Revision != 1 || len(state.History) != 2 || state.History[1].CompletedAt != nil {
		t.Fatalf("canceled postcondition completed its journal: %+v, %v", state, err)
	}
	// Cleanup must work independently even after the caller is canceled.
	cancel()
	err = l.close(caller, false)
	closed = true
	if err != nil {
		t.Fatal("timeout cleanup failed", err)
	}
	state, err = readHistory(t.Context(), db, catalog)
	if err != nil || state.Dirty || state.Revision != 1 || len(state.History) != 1 {
		t.Fatalf("timeout cleanup did not roll back history: %+v, %v", state, err)
	}
	if exists, err := objectExists(t.Context(), db, "sqlite", "verification_marker"); err != nil || exists {
		t.Fatal("timeout cleanup did not roll back DDL", err)
	}
	var busy, foreignKeys int
	if err := db.QueryRowContext(t.Context(), "PRAGMA busy_timeout").Scan(&busy); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(t.Context(), "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatal(err)
	}
	if busy != 217 || foreignKeys != 0 {
		t.Fatalf("caller settings changed after timeout: busy_timeout=%d foreign_keys=%d", busy, foreignKeys)
	}
	if err := db.PingContext(t.Context()); err != nil {
		t.Fatal("borrowed pool cannot be reused after timeout", err)
	}
}

func TestVerificationDeadlineAllDialects(t *testing.T) {
	for _, dialect := range []string{"sqlite", "postgres", "mysql"} {
		t.Run(dialect, func(t *testing.T) {
			catalog := ownershipBaselineCatalog(t, dialect)
			probe := &verificationProbe{queryer: migrationDB(t), block: "*"}
			caller, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			// Block before any engine-specific SQL. This checks context
			// propagation without external servers or CPU-intensive queries.
			err := verifyStep(caller, probe, catalog, catalog.Migrations[0], 20*time.Millisecond)
			if !errors.Is(err, context.DeadlineExceeded) || caller.Err() != nil || !probe.reached {
				t.Fatalf("verification did not enforce its own deadline: %v (caller: %v)", err, caller.Err())
			}
		})
	}
}

func TestVerificationPhaseSharesDeadlineAndPreservesCaller(t *testing.T) {
	db := migrationDB(t)
	applyOwnershipBaseline(t, db, "sqlite")
	catalog := ownershipBaselineCatalog(t, "sqlite")
	ddl := "CREATE TABLE future_verification_table (\n    id INTEGER PRIMARY KEY\n);\n"
	catalog = appendOwnershipStep(t, catalog, catalog.Migrations[0].schemaSQL+"\n"+ddl, ddl)
	step := catalog.Migrations[0]
	step.Checks = []string{"SELECT TRUE"}
	for _, earlierCaller := range []bool{false, true} {
		t.Run(fmt.Sprintf("earlier caller=%t", earlierCaller), func(t *testing.T) {
			budget := time.Hour
			callerDeadline := time.Now().Add(2 * time.Hour)
			if earlierCaller {
				callerDeadline = time.Now().Add(30 * time.Minute)
			}
			caller, cancel := context.WithDeadline(t.Context(), callerDeadline)
			defer cancel()
			probe := &verificationProbe{queryer: db}
			before := time.Now()
			if err := verifyStep(caller, probe, catalog, step, budget); err != nil {
				t.Fatal(err)
			}
			after := time.Now()
			if len(probe.contexts) < 4 {
				t.Fatal("did not exercise owned-name, schema, data and foreign-key verification")
			}
			deadline, ok := probe.contexts[0].Deadline()
			if !ok {
				t.Fatal("verification context has no deadline")
			}
			if earlierCaller {
				if !deadline.Equal(callerDeadline) {
					t.Fatal("verification extended the caller deadline")
				}
			} else if deadline.Before(before.Add(budget)) || deadline.After(after.Add(budget)) {
				t.Fatal("verification did not use the configured phase budget")
			}
			for _, observed := range probe.contexts {
				got, ok := observed.Deadline()
				if !ok || !got.Equal(deadline) || !errors.Is(observed.Err(), context.Canceled) {
					t.Fatal("verification queries did not share one canceled phase context")
				}
			}
			if caller.Err() != nil {
				t.Fatal("verification canceled the caller context")
			}
		})
	}
}

func TestVerificationPhasePreservesDriverAndContextCauses(t *testing.T) {
	driverErr := errors.New("driver interrupted while reading rows")
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			caller, cancel := context.WithCancel(t.Context())
			if errors.Is(cause, context.DeadlineExceeded) {
				cancel()
				caller, cancel = context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
			} else {
				cancel()
			}
			defer cancel()
			err := verifyPhase(caller, time.Hour, func(context.Context) error {
				return fmt.Errorf("iterate verification rows: %w", driverErr)
			})
			if !errors.Is(err, cause) || !errors.Is(err, driverErr) {
				t.Fatal("verification lost the driver or context cause", err)
			}
		})
	}
}
