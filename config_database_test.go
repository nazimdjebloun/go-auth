package goauth

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNewConfigDatabaseValidation(t *testing.T) {
	// These handles cannot connect. Configuration validation must inspect only
	// their presence, leaving connectivity and ownership to New.
	db := &sql.DB{}
	pool := &pgxpool.Pool{}
	const dsn = "postgres://fixture:dummy-password@localhost/app"
	const sourceConflict = "database: exactly one of URL, DB, or Pool must be set"
	const poolDriver = "database: Pool requires DriverPostgres"
	for _, tc := range []struct {
		name     string
		database DatabaseConfig
		want     string
	}{
		{name: "postgres URL", database: DatabaseConfig{Driver: DriverPostgres, URL: dsn}},
		{name: "mysql URL", database: DatabaseConfig{Driver: DriverMySQL, URL: "fixture"}},
		{name: "sqlite URL", database: DatabaseConfig{Driver: DriverSQLite, URL: ":memory:"}},
		{name: "postgres DB", database: DatabaseConfig{Driver: DriverPostgres, DB: db}},
		{name: "mysql DB", database: DatabaseConfig{Driver: DriverMySQL, DB: db}},
		{name: "sqlite DB", database: DatabaseConfig{Driver: DriverSQLite, DB: db}},
		{name: "postgres Pool", database: DatabaseConfig{Driver: DriverPostgres, Pool: pool}},
		{
			name:     "no source",
			database: DatabaseConfig{Driver: DriverPostgres},
			want:     "database: one of URL, DB, or Pool is required",
		},
		{
			name:     "URL and DB",
			database: DatabaseConfig{Driver: DriverPostgres, URL: dsn, DB: db},
			want:     sourceConflict,
		},
		{
			name:     "URL and Pool",
			database: DatabaseConfig{Driver: DriverPostgres, URL: dsn, Pool: pool},
			want:     sourceConflict,
		},
		{
			name:     "DB and Pool",
			database: DatabaseConfig{Driver: DriverPostgres, DB: db, Pool: pool},
			want:     sourceConflict,
		},
		{
			name:     "all sources",
			database: DatabaseConfig{Driver: DriverPostgres, URL: dsn, DB: db, Pool: pool},
			want:     sourceConflict,
		},
		{
			name:     "empty driver",
			database: DatabaseConfig{DB: db},
			want:     "database: driver cannot be empty",
		},
		{
			name:     "unsupported driver",
			database: DatabaseConfig{Driver: "mongo", DB: db},
			want:     `database: unsupported driver`,
		},
		{
			name:     "sqlite CLI alias",
			database: DatabaseConfig{Driver: "sqlite", DB: db},
			want:     `database: unsupported driver`,
		},
		{
			name:     "sqlite Pool",
			database: DatabaseConfig{Driver: DriverSQLite, Pool: pool},
			want:     poolDriver,
		},
		{
			name:     "mysql Pool",
			database: DatabaseConfig{Driver: DriverMySQL, Pool: pool},
			want:     poolDriver,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := NewConfig(minimalOpts(WithApp(AppConfig{
				Name: "app", BaseURL: "https://example.com", Database: tc.database,
			}))...)
			if tc.want == "" {
				if err != nil || cfg == nil {
					t.Fatalf("valid database rejected: config present=%v, err=%v", cfg != nil, err)
				}
				return
			}
			if cfg != nil || err == nil {
				t.Fatalf("invalid database: config present=%v, err=%v", cfg != nil, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), dsn) || strings.Contains(err.Error(), "dummy-password") {
				t.Fatal("database configuration error exposed connection credentials")
			}
		})
	}
}

func TestNewRevalidatesDatabaseOptions(t *testing.T) {
	for _, tc := range []struct {
		name     string
		database DatabaseConfig
		want     string
		field    string
		code     ConfigIssueCode
	}{
		{
			name:     "multiple sources",
			database: DatabaseConfig{Driver: DriverPostgres, URL: "fixture", DB: &sql.DB{}},
			want:     "database: exactly one of URL, DB, or Pool must be set",
			field:    "App.Database", code: ConfigConflict,
		},
		{
			name:     "unsupported driver",
			database: DatabaseConfig{Driver: "mongo", DB: &sql.DB{}},
			want:     `database: unsupported driver`,
			field:    "App.Database.Driver", code: ConfigUnsupported,
		},
		{
			name:     "incompatible Pool",
			database: DatabaseConfig{Driver: DriverSQLite, Pool: &pgxpool.Pool{}},
			want:     "database: Pool requires DriverPostgres",
			field:    "App.Database.Pool", code: ConfigConflict,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := NewConfig(minimalOpts()...)
			if err != nil {
				t.Fatal(err)
			}
			WithApp(AppConfig{
				Name: "app", BaseURL: "https://example.com", Database: tc.database,
			})(cfg)
			auth, err := New(cfg)
			if auth != nil {
				auth.Close()
				t.Fatal("New accepted invalid database options applied after NewConfig")
			}
			var issue *ConfigIssue
			if !errors.As(err, &issue) || issue.Field != tc.field || issue.Code != tc.code ||
				!strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want configuration rejection containing %q", err, tc.want)
			}
		})
	}
}
