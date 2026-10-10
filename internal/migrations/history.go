package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Sentinel errors describe deployment failures, not HTTP authentication errors.
var (
	ErrUntracked      = errors.New("auth schema has no migration history; explicitly adopt a validated baseline")
	ErrDirty          = errors.New("auth migration is incomplete; inspect and verify recovery before continuing")
	ErrIncompatible   = errors.New("auth schema revision is incompatible with this library")
	ErrDrift          = errors.New("auth schema differs from the published definition")
	ErrLockTimeout    = errors.New("timed out acquiring auth migration serialization")
	ErrUnknownHistory = errors.New("auth migration history is not a prefix of the published catalog")
	ErrChecksum       = errors.New("auth migration checksum does not match the published catalog")
)

// Error identifies the failed phase without including a DSN or SQL statement.
type Error struct {
	Dialect     string
	MigrationID int64
	Phase       string
	Dirty       bool
	Uncertain   bool
	Cause       error
}

func (e *Error) Error() string {
	return fmt.Sprintf("goauth: %s migration %06d, phase %s (dirty=%t, uncertain=%t): %v",
		e.Dialect, e.MigrationID, e.Phase, e.Dirty, e.Uncertain, e.Cause)
}

// Unwrap retains the infrastructure cause and supports errors.Is/As.
func (e *Error) Unwrap() error { return e.Cause }

type queryer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Record distinguishes executed SQL from explicit baseline adoption.
type Record struct {
	ID             int64  `json:"id"`
	BaselineID     int64  `json:"baselineId"`
	Dialect        string `json:"dialect"`
	File           string `json:"file"`
	Checksum       string `json:"checksum"`
	SchemaChecksum string `json:"schemaChecksum"`
	Kind           string `json:"kind"`
	Mode           string `json:"mode"`
	State          string `json:"state"`
	StartedAt      int64  `json:"startedAt"`
	CompletedAt    *int64 `json:"completedAt,omitempty"`
}

// Status is a compatibility report. It does not certify absence of live drift.
type Status struct {
	Dialect        string   `json:"dialect"`
	Release        string   `json:"release"`
	Revision       int64    `json:"revision"`
	TargetRevision int64    `json:"targetRevision"`
	Dirty          bool     `json:"dirty"`
	Pending        []int64  `json:"pending"`
	History        []Record `json:"history"`
}

func journalSQL(dialect string) string {
	ddl := `CREATE TABLE goauth_migrations (
    migration_id BIGINT PRIMARY KEY,
    baseline_id BIGINT NOT NULL,
    dialect VARCHAR(16) NOT NULL,
    file VARCHAR(128) NOT NULL,
    checksum VARCHAR(64) NOT NULL,
    schema_checksum VARCHAR(64) NOT NULL,
    kind VARCHAR(16) NOT NULL,
    mode VARCHAR(16) NOT NULL,
    state VARCHAR(16) NOT NULL,
    started_at BIGINT NOT NULL,
    completed_at BIGINT
)`
	if dialect == "mysql" {
		ddl += " ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
	}
	return ddl + ";"
}

func bind(dialect, query string) string {
	if dialect != "postgres" {
		return query
	}
	var b strings.Builder
	position := 1
	for _, c := range query {
		if c == '?' {
			fmt.Fprintf(&b, "$%d", position)
			position++
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func readHistory(ctx context.Context, q queryer, catalog Catalog) (Status, error) {
	status := Status{
		Dialect: catalog.Dialect, Release: catalog.Release, TargetRevision: catalog.TargetRevision,
		Pending: []int64{}, History: []Record{},
	}
	rows, err := q.QueryContext(ctx, `SELECT migration_id, baseline_id, dialect, file, checksum,
		schema_checksum, kind, mode, state, started_at, completed_at
		FROM goauth_migrations ORDER BY migration_id`)
	if err != nil {
		return status, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var r Record
		var completed sql.NullInt64
		if err := rows.Scan(&r.ID, &r.BaselineID, &r.Dialect, &r.File, &r.Checksum,
			&r.SchemaChecksum, &r.Kind, &r.Mode, &r.State, &r.StartedAt, &completed); err != nil {
			return status, err
		}
		if completed.Valid {
			r.CompletedAt = &completed.Int64
		}
		status.History = append(status.History, r)
	}
	if err := rows.Err(); err != nil {
		return status, err
	}
	failure := func(id int64, cause error) error {
		return &Error{Dialect: catalog.Dialect, MigrationID: id, Phase: "history validation", Dirty: status.Dirty, Cause: cause}
	}
	for i, record := range status.History {
		if i >= len(catalog.Migrations) || record.ID != catalog.Migrations[i].ID {
			return status, failure(record.ID, ErrUnknownHistory)
		}
		step := catalog.Migrations[i]
		if record.Checksum != step.Checksum || record.SchemaChecksum != step.SchemaChecksum {
			return status, failure(record.ID, ErrChecksum)
		}
		validIdentity := record.BaselineID == catalog.BootstrapRevision && record.Dialect == catalog.Dialect
		validIdentity = validIdentity && record.File == step.File && record.Kind == step.Kind
		validMode := record.Mode == "executed" || (i == 0 && record.Mode == "adopted")
		if !validIdentity || !validMode || record.StartedAt <= 0 || status.Dirty {
			return status, failure(record.ID, ErrUnknownHistory)
		}
		switch record.State {
		case "complete":
			// Wall clocks may move backward; IDs and states establish ordering.
			if record.CompletedAt == nil || *record.CompletedAt <= 0 {
				return status, failure(record.ID, fmt.Errorf("%w: invalid completion", ErrUnknownHistory))
			}
			status.Revision = record.ID
		case "started":
			if record.CompletedAt != nil {
				return status, failure(record.ID, fmt.Errorf("%w: invalid incomplete record", ErrUnknownHistory))
			}
			status.Dirty = true
		default:
			return status, failure(record.ID, fmt.Errorf("%w: invalid state", ErrUnknownHistory))
		}
	}
	for _, step := range catalog.Migrations {
		if step.ID > status.Revision {
			status.Pending = append(status.Pending, step.ID)
		}
	}
	return status, nil
}

func startRecord(ctx context.Context, q queryer, catalog Catalog, step Step, mode string) error {
	query := bind(catalog.Dialect, `INSERT INTO goauth_migrations
		(migration_id, baseline_id, dialect, file, checksum, schema_checksum, kind, mode, state, started_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'started', ?)`)
	_, err := q.ExecContext(ctx, query,
		step.ID, catalog.BootstrapRevision, catalog.Dialect, step.File, step.Checksum,
		step.SchemaChecksum, step.Kind, mode, time.Now().UTC().Unix(),
	)
	return err
}

func completeRecord(ctx context.Context, q queryer, dialect string, step Step) error {
	query := bind(dialect, `UPDATE goauth_migrations SET state='complete', completed_at=?
		WHERE migration_id=? AND checksum=? AND state='started'`)
	result, err := q.ExecContext(ctx, query, time.Now().UTC().Unix(), step.ID, step.Checksum)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("%w: completion did not update exactly one record", ErrUnknownHistory)
	}
	return nil
}
