package goauth

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nazimdjebloun/go-auth/internal/sqldriver"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
)

// requireDriverSupport defaults the driver to postgres and checks that the
// consumer actually blank-imported the database/sql driver the chosen
// backend needs — go-auth's own go.mod only pulls in pgx. Also enforces
// MySQL's parseTime requirement when go-auth opens the connection itself.
func requireDriverSupport(cfg *Config) error {
	if cfg.app.Database.Driver == "" {
		cfg.app.Database.Driver = DriverPostgres
	}
	switch cfg.app.Database.Driver {
	case DriverPostgres:
		// supported natively
	case DriverSQLite:
		if !sqldriver.IsRegistered("sqlite") && !sqldriver.IsRegistered("sqlite3") {
			return fmt.Errorf(
				"goauth: sqlite driver not registered — add the following import to your main package:\n\n\t_ \"modernc.org/sqlite\"",
			)
		}
	case DriverMySQL:
		if !sqldriver.IsRegistered("mysql") {
			return fmt.Errorf(
				"goauth: mysql driver not registered — add the following import to your main package:\n\n\t_ \"github.com/go-sql-driver/mysql\"",
			)
		}
		// Only checkable when go-auth opens the connection itself — a
		// consumer-provided *sql.DB is already open and its DSN is unknown.
		if cfg.app.Database.URL != "" {
			if err := sqldriver.ValidateMySQLDSN(cfg.app.Database.URL); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("goauth: unsupported driver %q", cfg.app.Database.Driver)
	}
	return nil
}

// openDatabase resolves the three ways a consumer can supply a database --
// an existing pgx pool, an existing *sql.DB, or a DSN for go-auth to open
// itself — into the one pair the rest of New needs. It records on cfg
// whether it opened anything, which is what Close later keys off.
func openDatabase(ctx context.Context, cfg *Config) (*pgxpool.Pool, *sqlstore.DB, error) {
	var pool *pgxpool.Pool
	var sqlDB *sqlstore.DB

	switch {
	case cfg.app.Database.Pool != nil:
		pool = cfg.app.Database.Pool
		rawDB := stdlib.OpenDBFromPool(pool)
		// Closing this adapter releases its resources, not the caller's pool.
		cfg.app.Database.opened = true
		sqlDB = sqlstore.NewDB(rawDB, string(DriverPostgres))
	case cfg.app.Database.DB != nil:
		if cfg.app.Database.Driver == DriverSQLite {
			if err := sqldriver.RequireSQLiteForeignKeys(ctx, cfg.app.Database.DB); err != nil {
				return nil, nil, err
			}
		}
		sqlDB = sqlstore.NewDB(cfg.app.Database.DB, string(cfg.app.Database.Driver))
	case cfg.app.Database.URL != "":
		driverName := sqldriver.SQLName(string(cfg.app.Database.Driver))
		if cfg.app.Database.Driver == DriverSQLite {
			// sqldriver.SQLName assumes modernc.org/sqlite ("sqlite"), but the
			// registration check in requireDriverSupport also accepts mattn/go-sqlite3
			// ("sqlite3") — use whichever is actually registered so sql.Open
			// doesn't fail with "unknown driver" after registration passed.
			driverName = sqldriver.ResolveSQLiteName()
		}
		dsn := cfg.app.Database.URL
		if cfg.app.Database.Driver == DriverSQLite {
			var err error
			dsn, err = sqldriver.SQLiteForeignKeyDSN(driverName, dsn)
			if err != nil {
				return nil, nil, err
			}
		}
		db, err := sql.Open(driverName, dsn)
		if err != nil {
			return nil, nil, fmt.Errorf("goauth: open database: %w", err)
		}
		if err := cfg.app.Database.applyConnectionLimits(db); err != nil {
			_ = db.Close()
			return nil, nil, err
		}
		if err := db.PingContext(ctx); err != nil {
			_ = db.Close()
			return nil, nil, fmt.Errorf("goauth: ping database: %w", err)
		}
		if cfg.app.Database.Driver == DriverSQLite {
			if err := sqldriver.RequireSQLiteForeignKeys(ctx, db); err != nil {
				_ = db.Close()
				return nil, nil, err
			}
		}
		cfg.app.Database.opened = true
		sqlDB = sqlstore.NewDB(db, string(cfg.app.Database.Driver))
	default:
		return nil, nil, fmt.Errorf("goauth: no database pool or DSN provided")
	}

	return pool, sqlDB, nil
}
