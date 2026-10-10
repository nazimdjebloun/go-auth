package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

const advisoryKey int64 = 0x676f61757468

type lease struct {
	conn     *sql.Conn
	dialect  string
	name     string
	acquired bool
	sqliteTx bool
	settings map[string]string
}

func acquire(ctx context.Context, db *sql.DB, catalog Catalog, options Options) (*lease, error) {
	lockCtx, cancel := context.WithTimeout(ctx, options.LockTimeout)
	defer cancel()
	conn, err := db.Conn(lockCtx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLockTimeout, err)
	}
	l := &lease{conn: conn, dialect: catalog.Dialect, settings: map[string]string{}}
	success := false
	defer func() {
		if !success {
			_ = l.close(ctx, false)
		}
	}()
	if catalog.Dialect == "mysql" {
		var name sql.NullString
		if err := conn.QueryRowContext(lockCtx, "SELECT DATABASE()").Scan(&name); err != nil {
			return nil, err
		}
		if !name.Valid || name.String == "" {
			return nil, fmt.Errorf("goauth: select a MySQL database before migrating")
		}
		digest := sha256.Sum256([]byte(name.String))
		l.name = fmt.Sprintf("goauth:migrate:%x", digest[:24])
	}
	if catalog.Dialect == "sqlite" {
		for _, setting := range []string{"foreign_keys", "busy_timeout"} {
			var value int
			if err := conn.QueryRowContext(lockCtx, "PRAGMA "+setting).Scan(&value); err != nil {
				return nil, err
			}
			l.settings[setting] = strconv.Itoa(value)
		}
		foreignKeys := "ON"
		for _, step := range catalog.Migrations {
			if step.SQLiteRebuild {
				foreignKeys = "OFF"
			}
		}
		if _, err := conn.ExecContext(lockCtx, "PRAGMA foreign_keys = "+foreignKeys); err != nil {
			return nil, err
		}
		if _, err := conn.ExecContext(lockCtx, "PRAGMA busy_timeout = 0"); err != nil {
			return nil, err
		}
	}
	for {
		acquired, err := l.try(lockCtx)
		if err != nil {
			if lockCtx.Err() != nil {
				return nil, fmt.Errorf("%w: %w", ErrLockTimeout, lockCtx.Err())
			}
			return nil, err
		}
		if acquired {
			l.acquired = true
			break
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-lockCtx.Done():
			timer.Stop()
			return nil, fmt.Errorf("%w: %w", ErrLockTimeout, lockCtx.Err())
		case <-timer.C:
		}
	}
	if err := l.configure(ctx, options); err != nil {
		return nil, err
	}
	success = true
	return l, nil
}

func (l *lease) try(ctx context.Context) (bool, error) {
	switch l.dialect {
	case "postgres":
		var acquired bool
		err := l.conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", advisoryKey).Scan(&acquired)
		return acquired, err
	case "mysql":
		var acquired sql.NullInt64
		err := l.conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, 0)", l.name).Scan(&acquired)
		if err != nil {
			return false, err
		}
		if !acquired.Valid {
			return false, fmt.Errorf("goauth: MySQL could not acquire the migration lock")
		}
		return acquired.Int64 == 1, nil
	case "sqlite":
		_, err := l.conn.ExecContext(ctx, "BEGIN IMMEDIATE")
		if err != nil {
			var coded interface{ Code() int }
			if errors.As(err, &coded) && (coded.Code()&255 == 5 || coded.Code()&255 == 6) {
				return false, nil
			}
			// mattn/go-sqlite3 exposes a Code field rather than a Code method.
			// Its stable SQLite busy/locked messages cover borrowed sqlite3 pools.
			message := strings.ToLower(err.Error())
			if message == "database is locked" || message == "database table is locked" || message == "database is busy" {
				return false, nil
			}
			return false, err
		}
		l.sqliteTx = true
		return true, nil
	}
	return false, fmt.Errorf("goauth: unsupported migration lock dialect")
}

func (l *lease) configure(ctx context.Context, options Options) error {
	switch l.dialect {
	case "postgres":
		for name, duration := range map[string]time.Duration{
			"lock_timeout": options.LockTimeout, "statement_timeout": options.StatementTimeout,
		} {
			var old string
			if err := l.conn.QueryRowContext(ctx, "SHOW "+name).Scan(&old); err != nil {
				return err
			}
			l.settings[name] = old
			value := strconv.FormatInt(max(1, duration.Milliseconds()), 10) + "ms"
			if _, err := l.conn.ExecContext(ctx, "SELECT set_config($1, $2, false)", name, value); err != nil {
				return err
			}
		}
	case "mysql":
		var foreignKeys int
		if err := l.conn.QueryRowContext(ctx, "SELECT @@SESSION.foreign_key_checks").Scan(&foreignKeys); err != nil {
			return err
		}
		l.settings["foreign_key_checks"] = strconv.Itoa(foreignKeys)
		if _, err := l.conn.ExecContext(ctx, "SET SESSION foreign_key_checks = 1"); err != nil {
			return err
		}
		var old int64
		if err := l.conn.QueryRowContext(ctx, "SELECT @@SESSION.lock_wait_timeout").Scan(&old); err != nil {
			return err
		}
		l.settings["lock_wait_timeout"] = strconv.FormatInt(old, 10)
		seconds := int64(math.Ceil(options.LockTimeout.Seconds()))
		_, err := l.conn.ExecContext(ctx, "SET SESSION lock_wait_timeout = "+strconv.FormatInt(max(1, seconds), 10))
		return err
	}
	return nil
}

// A session lock must never be returned to a pool still held. Cleanup uses a
// bounded independent context; an uncertain session is discarded physically.
func (l *lease) close(ctx context.Context, commit bool) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	var result error
	if l.sqliteTx {
		command := "ROLLBACK"
		if commit {
			command = "COMMIT"
		}
		_, result = l.conn.ExecContext(cleanupCtx, command)
		l.sqliteTx = false
	}
	for name, value := range l.settings {
		var err error
		switch l.dialect {
		case "postgres":
			_, err = l.conn.ExecContext(cleanupCtx, "SELECT set_config($1, $2, false)", name, value)
		case "mysql":
			_, err = l.conn.ExecContext(cleanupCtx, "SET SESSION "+name+" = "+value)
		case "sqlite":
			_, err = l.conn.ExecContext(cleanupCtx, "PRAGMA "+name+" = "+value)
		}
		result = errors.Join(result, err)
	}
	if l.acquired && l.dialect == "postgres" {
		var unlocked bool
		err := l.conn.QueryRowContext(cleanupCtx, "SELECT pg_advisory_unlock($1)", advisoryKey).Scan(&unlocked)
		if err == nil && !unlocked {
			err = fmt.Errorf("goauth: migration lock ownership was lost")
		}
		result = errors.Join(result, err)
	}
	if l.acquired && l.dialect == "mysql" {
		var unlocked sql.NullInt64
		err := l.conn.QueryRowContext(cleanupCtx, "SELECT RELEASE_LOCK(?)", l.name).Scan(&unlocked)
		if err == nil && (!unlocked.Valid || unlocked.Int64 != 1) {
			err = fmt.Errorf("goauth: migration lock ownership was lost")
		}
		result = errors.Join(result, err)
	}
	if result != nil || !l.acquired {
		_ = l.conn.Raw(func(any) error { return driver.ErrBadConn })
	}
	return errors.Join(result, l.conn.Close())
}
