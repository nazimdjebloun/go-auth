package goauth

import (
	"context"
	"database/sql"

	"github.com/nazimdjebloun/go-auth/internal/migrations"
)

// MigrationCatalog describes the immutable published auth migrations.
type MigrationCatalog = migrations.Catalog

// Migration describes one published migration and its verification metadata.
type Migration = migrations.Step

// MigrationRetryPolicy describes published data checks and recovery instructions.
type MigrationRetryPolicy = migrations.RetryPolicy

// MigrationOptions configures the separate runner. Database ownership stays
// with the caller; zero timeouts select the documented execution defaults.
type MigrationOptions = migrations.Options

// MigrationStatus reports recorded history, pending steps and incomplete state.
type MigrationStatus = migrations.Status

// MigrationRecord distinguishes executed migrations and adopted baselines.
type MigrationRecord = migrations.Record

// MigrationError identifies a dialect, migration, phase and uncertain outcome.
type MigrationError = migrations.Error

// BaselineAdoptionOptions requests adoption of one supported, verified schema.
type BaselineAdoptionOptions struct {
	MigrationOptions
	BaselineRevision int64
}

// MigrationRepairOptions identifies the incomplete step whose complete
// postconditions must be verified before updating the journal.
type MigrationRepairOptions struct {
	MigrationOptions
	MigrationID int64
}

// MigrationRetryOptions identifies one incomplete upgrade to replay after
// verifying its published retry policy and the previous completed schema.
type MigrationRetryOptions struct {
	MigrationOptions
	MigrationID int64
}

// Deployment sentinels support errors.Is; they are separate from AuthError.
var (
	ErrUntrackedSchema           = migrations.ErrUntracked
	ErrDirtyMigration            = migrations.ErrDirty
	ErrIncompatibleSchema        = migrations.ErrIncompatible
	ErrSchemaDrift               = migrations.ErrDrift
	ErrMigrationLockTimeout      = migrations.ErrLockTimeout
	ErrUnknownMigrationHistory   = migrations.ErrUnknownHistory
	ErrMigrationChecksum         = migrations.ErrChecksum
	ErrMigrationPrecondition     = migrations.ErrPrecondition
	ErrMigrationRetryUnsupported = migrations.ErrRetryUnsupported
)

// GetMigrationCatalog returns a validated, independently owned catalog copy.
func GetMigrationCatalog(driver string) (MigrationCatalog, error) {
	return migrations.Load(driver)
}

// ExportSchema writes auth.schema.sql, reference.md and the published catalog
// under directory. It does not inspect or modify a database.
func ExportSchema(driver, directory string) error {
	return migrations.Export(driver, directory)
}

// Migrate explicitly installs or upgrades auth objects using the embedded
// catalog. Stop auth traffic/workers first. New never calls this function.
func Migrate(ctx context.Context, db *sql.DB, options MigrationOptions) (MigrationStatus, error) {
	return migrations.Apply(ctx, db, options)
}

// AdoptSchema validates a supported untracked baseline without replaying DDL.
func AdoptSchema(ctx context.Context, db *sql.DB, options BaselineAdoptionOptions) (MigrationStatus, error) {
	return migrations.Adopt(ctx, db, options.MigrationOptions, options.BaselineRevision)
}

// RepairMigration verifies all schema and data postconditions before marking
// the specified incomplete step complete. It does not execute migration SQL.
func RepairMigration(ctx context.Context, db *sql.DB, options MigrationRepairOptions) (MigrationStatus, error) {
	return migrations.RepairComplete(ctx, db, options.MigrationOptions, options.MigrationID)
}

// RetryMigration verifies the exact incomplete upgrade's starting conditions,
// then replays its original SQL without replacing history. Later steps remain
// pending. Only published, nontransactional retry policies are supported.
func RetryMigration(ctx context.Context, db *sql.DB, options MigrationRetryOptions) (MigrationStatus, error) {
	return migrations.Retry(ctx, db, options.MigrationOptions, options.MigrationID)
}

// GetMigrationStatus reads history without creating metadata or executing DDL.
func GetMigrationStatus(ctx context.Context, db *sql.DB, driver string) (MigrationStatus, error) {
	return migrations.Inspect(ctx, db, driver)
}

// CheckSchema checks recorded compatibility only. Use VerifySchema at deployment
// to detect structural drift. The supplied context controls the check's timeout.
func CheckSchema(ctx context.Context, db *sql.DB, driver string) error {
	return migrations.Check(ctx, db, driver)
}

// VerifySchema checks the tracked target's columns, constraints, indexes,
// collations and data postconditions under migration serialization.
func VerifySchema(ctx context.Context, db *sql.DB, options MigrationOptions) error {
	return migrations.Verify(ctx, db, options)
}
