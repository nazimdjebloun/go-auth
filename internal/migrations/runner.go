package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Options configures explicit, standalone execution on a borrowed database.
type Options struct {
	Driver           string
	LockTimeout      time.Duration // Zero selects 30 seconds.
	StatementTimeout time.Duration // Zero selects 5 minutes per statement.
}

func (o Options) defaults() (Options, error) {
	if o.LockTimeout < 0 || o.StatementTimeout < 0 {
		return o, fmt.Errorf("goauth: migration timeouts must not be negative")
	}
	if o.LockTimeout == 0 {
		o.LockTimeout = 30 * time.Second
	}
	if o.StatementTimeout == 0 {
		o.StatementTimeout = 5 * time.Minute
	}
	return o, nil
}

// Apply installs a published baseline or applies every pending upgrade.
func Apply(ctx context.Context, db *sql.DB, options Options) (Status, error) {
	return run(ctx, db, options, "apply", 0)
}

// Adopt validates the published bootstrap schema and records adoption without
// executing its creation SQL. Only the explicitly requested baseline is accepted.
func Adopt(ctx context.Context, db *sql.DB, options Options, baseline int64) (Status, error) {
	return run(ctx, db, options, "adopt", baseline)
}

// RepairComplete marks the last incomplete step complete only after structural
// and data verification. It cannot suppress a failure or retry arbitrary SQL.
func RepairComplete(ctx context.Context, db *sql.DB, options Options, id int64) (Status, error) {
	return run(ctx, db, options, "repair", id)
}

// Retry replays only the specified incomplete nontransactional upgrade after
// verifying its published starting schema and data conditions. No journal row
// is deleted or replaced, and later pending steps are not executed.
func Retry(ctx context.Context, db *sql.DB, options Options, id int64) (Status, error) {
	return run(ctx, db, options, "retry", id)
}

func run(ctx context.Context, db *sql.DB, options Options, operation string, id int64) (status Status, err error) {
	if db == nil {
		return status, fmt.Errorf("goauth: migration database is nil")
	}
	catalog, err := Load(options.Driver)
	if err != nil {
		return status, err
	}
	return runCatalog(ctx, db, options, catalog, operation, id)
}

// Only validated, library-owned catalogs enter here. Keeping loading separate
// lets upgrade fixtures exercise the same executor without mutable global state.
func runCatalog(ctx context.Context, db *sql.DB, options Options, catalog Catalog, operation string, id int64) (status Status, err error) {
	if db == nil {
		return status, fmt.Errorf("goauth: migration database is nil")
	}
	options, err = options.defaults()
	if err != nil {
		return status, err
	}
	if operation == "adopt" && id != catalog.BootstrapRevision {
		return status, fmt.Errorf("%w: supported adoption baseline is %d", ErrUnknownHistory, catalog.BootstrapRevision)
	}
	l, err := acquire(ctx, db, catalog, options)
	if err != nil {
		return status, &Error{Dialect: catalog.Dialect, Phase: "lock", Cause: err}
	}
	status = Status{
		Dialect: catalog.Dialect, Release: catalog.Release, TargetRevision: catalog.TargetRevision,
		History: []Record{}, Pending: []int64{},
	}
	for _, step := range catalog.Migrations {
		status.Pending = append(status.Pending, step.ID)
	}
	initialStatus := status
	phase := "history inspection"
	activeID := id
	defer func() {
		if err == nil && ctx.Err() != nil {
			err = ctx.Err()
		}
		if cleanupErr := l.close(ctx, err == nil); cleanupErr != nil {
			err = errors.Join(err, &Error{Dialect: catalog.Dialect, Phase: "release/commit", Uncertain: true, Cause: cleanupErr})
		}
		var migrationError *Error
		if err != nil && !errors.As(err, &migrationError) {
			err = &Error{Dialect: catalog.Dialect, MigrationID: activeID, Phase: phase, Dirty: status.Dirty, Cause: err}
		}
		if err != nil && catalog.Dialect == "sqlite" {
			status = initialStatus
		}
	}()
	q := queryer(l.conn)
	exists, err := objectExists(ctx, q, catalog.Dialect, "goauth_migrations")
	if err != nil {
		return status, err
	}
	if exists {
		if err := verify(ctx, q, catalog.Dialect, journalSQL(catalog.Dialect), nil); err != nil {
			return status, &Error{Dialect: catalog.Dialect, Phase: "journal validation", Cause: err}
		}
		status, err = readHistory(ctx, q, catalog)
		if err != nil {
			return status, err
		}
		initialStatus = status
	}
	if operation == "verify" {
		phase = "verification"
		activeID = catalog.TargetRevision
		if !exists || len(status.History) == 0 {
			return status, ErrUntracked
		}
		if status.Dirty {
			return status, ErrDirty
		}
		if status.Revision != catalog.TargetRevision {
			return status, ErrIncompatible
		}
		return status, verifyStep(ctx, q, catalog, catalog.Migrations[len(catalog.Migrations)-1])
	}
	if operation == "repair" {
		phase = "repair"
		if !status.Dirty || len(status.History) == 0 || status.History[len(status.History)-1].ID != id {
			return status, fmt.Errorf("%w: repair requires the exact incomplete migration ID", ErrDirty)
		}
		step := catalog.Migrations[len(status.History)-1]
		if err := verifyStep(ctx, q, catalog, step); err != nil {
			return status, &Error{Dialect: catalog.Dialect, MigrationID: id, Phase: "repair verification", Dirty: true, Cause: err}
		}
		if err := completeRecord(ctx, q, catalog.Dialect, step); err != nil {
			return status, &Error{Dialect: catalog.Dialect, MigrationID: id, Phase: "repair completion", Dirty: true, Uncertain: true, Cause: err}
		}
		return readHistory(ctx, q, catalog)
	}
	if operation == "retry" {
		phase = "retry"
		return retryStep(ctx, q, catalog, status, id, options)
	}
	if status.Dirty {
		return status, &Error{
			Dialect: catalog.Dialect, MigrationID: status.History[len(status.History)-1].ID,
			Phase: "history", Dirty: true, Cause: ErrDirty,
		}
	}
	if operation == "adopt" && len(status.History) != 0 {
		return status, fmt.Errorf("goauth: baseline adoption requires an untracked installation")
	}
	if len(status.History) == 0 {
		baseline := catalog.Migrations[0]
		phase = "baseline preflight"
		activeID = baseline.ID
		if operation == "adopt" {
			phase = "adoption"
			if err := verifyStep(ctx, q, catalog, baseline); err != nil {
				return status, &Error{Dialect: catalog.Dialect, MigrationID: id, Phase: "adoption validation", Cause: err}
			}
		} else {
			// Future steps can reserve names absent from the bootstrap snapshot.
			// Reject those collisions before any auth DDL or history initialization.
			for _, step := range catalog.Migrations {
				if err := requireUnused(ctx, q, catalog.Dialect, step.schemaSQL); err != nil {
					return status, err
				}
			}
		}
		if !exists {
			if _, err := q.ExecContext(ctx, journalSQL(catalog.Dialect)); err != nil {
				return status, &Error{Dialect: catalog.Dialect, Phase: "journal creation", Cause: err}
			}
		}
		if operation == "adopt" {
			if err := recordAdoption(ctx, l, catalog, baseline); err != nil {
				return status, err
			}
			return readHistory(ctx, q, catalog)
		}
	} else {
		previous := catalog.Migrations[len(status.History)-1]
		if err := verifyStep(ctx, q, catalog, previous); err != nil {
			return status, &Error{Dialect: catalog.Dialect, MigrationID: previous.ID, Phase: "preflight", Cause: err}
		}
	}
	for _, step := range catalog.Migrations {
		if step.ID <= status.Revision {
			continue
		}
		phase = "execution"
		activeID = step.ID
		if err := applyStep(ctx, l, catalog, step, options); err != nil {
			var failure *Error
			if errors.As(err, &failure) {
				status.Dirty = failure.Dirty
			}
			return status, err
		}
		status, err = readHistory(ctx, q, catalog)
		if err != nil {
			return status, err
		}
	}
	return status, nil
}

func recordAdoption(ctx context.Context, l *lease, catalog Catalog, step Step) error {
	q := queryer(l.conn)
	if l.dialect == "sqlite" {
		if err := startRecord(ctx, q, catalog, step, "adopted"); err != nil {
			return err
		}
		return completeRecord(ctx, q, l.dialect, step)
	}
	tx, err := l.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := startRecord(ctx, tx, catalog, step, "adopted"); err != nil {
		return err
	}
	if err := completeRecord(ctx, tx, l.dialect, step); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return &Error{Dialect: l.dialect, MigrationID: step.ID, Phase: "adoption commit", Uncertain: true, Cause: err}
	}
	return nil
}

func applyStep(ctx context.Context, l *lease, catalog Catalog, step Step, options Options) error {
	q := queryer(l.conn)
	var tx *sql.Tx
	if step.Transactional && l.dialect != "sqlite" {
		var err error
		tx, err = l.conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback() }()
		q = tx
	}
	if err := checkPreconditions(ctx, q, step, options); err != nil {
		return &Error{Dialect: l.dialect, MigrationID: step.ID, Phase: "preconditions", Cause: err}
	}
	dirty := !step.Transactional
	fail := func(phase string, cause error) error {
		return &Error{Dialect: l.dialect, MigrationID: step.ID, Phase: phase, Dirty: dirty, Uncertain: dirty, Cause: cause}
	}
	if err := startRecord(ctx, q, catalog, step, "executed"); err != nil {
		return fail("start journal", err)
	}
	if err := executeStep(ctx, q, catalog, step, options); err != nil {
		return err
	}
	if tx != nil {
		if err := tx.Commit(); err != nil {
			return &Error{Dialect: l.dialect, MigrationID: step.ID, Phase: "commit", Uncertain: true, Cause: err}
		}
	}
	return nil
}

func executeStep(ctx context.Context, q queryer, catalog Catalog, step Step, options Options) error {
	dialect := catalog.Dialect
	fail := func(phase string, cause error) error {
		return &Error{Dialect: dialect, MigrationID: step.ID, Phase: phase,
			Dirty: !step.Transactional, Uncertain: !step.Transactional, Cause: cause}
	}
	for i, statement := range step.statements {
		statementCtx, cancel := context.WithTimeout(ctx, options.StatementTimeout)
		_, err := q.ExecContext(statementCtx, statement)
		cancel()
		if err != nil {
			return fail(fmt.Sprintf("statement %d", i+1), err)
		}
	}
	if err := verifyStep(ctx, q, catalog, step); err != nil {
		return fail("postconditions", err)
	}
	if err := completeRecord(ctx, q, dialect, step); err != nil {
		return fail("completion journal", err)
	}
	return nil
}

func verifyStep(ctx context.Context, q queryer, catalog Catalog, step Step) error {
	dialect := catalog.Dialect
	if dialect == "postgres" {
		var extensions int
		if err := q.QueryRowContext(ctx, "SELECT COUNT(*) FROM pg_extension WHERE extname IN ('pgcrypto','pg_trgm')").Scan(&extensions); err != nil {
			return err
		}
		if extensions != 2 {
			return fmt.Errorf("%w: provision pgcrypto and pg_trgm before migration/adoption", ErrDrift)
		}
	}
	if err := verify(ctx, q, dialect, step.schemaSQL, catalog.ownedNames); err != nil {
		return err
	}
	if err := checkQueries(ctx, q, step.Checks, "data postcondition"); err != nil {
		return err
	}
	if dialect == "sqlite" {
		rows, err := q.QueryContext(ctx, "PRAGMA foreign_key_check")
		if err != nil {
			return err
		}
		hasViolation := rows.Next()
		err = errors.Join(rows.Err(), rows.Close())
		if err != nil {
			return err
		}
		if hasViolation {
			return fmt.Errorf("%w: SQLite foreign_key_check found an integrity violation", ErrDrift)
		}
	}
	return nil
}

func checkQueries(ctx context.Context, q queryer, checks []string, label string) error {
	for i, check := range checks {
		rows, err := q.QueryContext(ctx, check)
		if err != nil {
			return fmt.Errorf("%s %d: %w", label, i+1, err)
		}
		var valid bool
		if !rows.Next() {
			if err := errors.Join(rows.Err(), rows.Close()); err != nil {
				return fmt.Errorf("%s %d: %w", label, i+1, err)
			}
			return fmt.Errorf("%s %d returned no result", label, i+1)
		}
		err = rows.Scan(&valid)
		extra := rows.Next()
		err = errors.Join(err, rows.Err(), rows.Close())
		if err != nil {
			return fmt.Errorf("%s %d: %w", label, i+1, err)
		}
		if !valid || extra {
			return fmt.Errorf("%s %d must return exactly one true value", label, i+1)
		}
	}
	return nil
}

// Inspect reads existing history without initializing metadata or executing DDL.
func Inspect(ctx context.Context, db *sql.DB, driver string) (status Status, err error) {
	if db == nil {
		return Status{}, fmt.Errorf("goauth: migration database is nil")
	}
	catalog, err := Load(driver)
	if err != nil {
		return Status{}, err
	}
	defer func() {
		var failure *Error
		if err != nil && !errors.As(err, &failure) {
			err = &Error{Dialect: catalog.Dialect, Phase: "history read", Cause: err}
		}
	}()
	conn, err := db.Conn(ctx)
	if err != nil {
		return Status{}, err
	}
	defer func() { _ = conn.Close() }()
	exists, err := objectExists(ctx, conn, catalog.Dialect, "goauth_migrations")
	if err != nil {
		return Status{}, err
	}
	if !exists {
		return Status{}, ErrUntracked
	}
	status, err = readHistory(ctx, conn, catalog)
	if err == nil && len(status.History) == 0 {
		return status, ErrUntracked
	}
	return status, err
}

// Check accepts exactly the release's completed target revision.
func Check(ctx context.Context, db *sql.DB, driver string) error {
	status, err := Inspect(ctx, db, driver)
	if err != nil {
		return err
	}
	if status.Dirty {
		return ErrDirty
	}
	if status.Revision != status.TargetRevision {
		return fmt.Errorf("%w: revision %d; %s requires %d",
			ErrIncompatible, status.Revision, status.Release, status.TargetRevision)
	}
	return nil
}

// Verify checks the tracked target schema under migration serialization.
func Verify(ctx context.Context, db *sql.DB, options Options) error {
	_, err := run(ctx, db, options, "verify", 0)
	return err
}
