package sqldriver

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"strings"
	"testing"
)

// fakeDriver satisfies database/sql/driver minimally; only registration is
// tested here, no queries are ever executed against it.
type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) { return nil, errNotImplemented }

var errNotImplemented = errors.New("sqldriver test: not implemented")

func TestMain(m *testing.M) {
	// Register a stand-in for sqlite3 (mattn/go-sqlite3) and one unrelated
	// driver. "sqlite" (modernc.org/sqlite) is deliberately NOT registered,
	// so ResolveSQLiteName's fallback branch is exercised deterministically.
	sql.Register("sqlite3", fakeDriver{})
	sql.Register("sqldriver-test-only", fakeDriver{})
	os.Exit(m.Run())
}

func TestSQLName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"postgres full name", "postgres", "pgx"},
		{"postgres alias", "pg", "pgx"},
		{"sqlite full name", "sqlite", "sqlite"},
		{"sqlite alias", "sqlite3", "sqlite"},
		{"mysql passes through", "mysql", "mysql"},
		{"unknown passes through unchanged", "notadriver", "notadriver"},
		{"empty passes through unchanged", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SQLName(tt.in); got != tt.want {
				t.Fatalf("SQLName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIsRegistered(t *testing.T) {
	if !IsRegistered("sqlite3") {
		t.Fatal("IsRegistered(\"sqlite3\") = false, want true (registered in TestMain)")
	}
	if !IsRegistered("sqldriver-test-only") {
		t.Fatal("IsRegistered(\"sqldriver-test-only\") = false, want true (registered in TestMain)")
	}
	if IsRegistered("sqlite") {
		t.Fatal("IsRegistered(\"sqlite\") = true, want false (deliberately not registered)")
	}
	if IsRegistered("pgx") {
		t.Fatal("IsRegistered(\"pgx\") = true, want false (no driver is registered in this test binary)")
	}
}

func TestResolveSQLiteName(t *testing.T) {
	// "sqlite" is not registered in this test binary, so the fallback must
	// return the mattn/go-sqlite3 driver name.
	if got := ResolveSQLiteName(); got != "sqlite3" {
		t.Fatalf("ResolveSQLiteName() = %q, want %q", got, "sqlite3")
	}
}

func TestValidateMySQLDSN(t *testing.T) {
	tests := []struct {
		name    string
		dsn     string
		wantErr bool
	}{
		{
			name:    "valid parseTime and loc",
			dsn:     "user:pass@tcp(localhost:3306)/goauth?parseTime=true&loc=UTC",
			wantErr: false,
		},
		{
			name:    "parseTime true alone",
			dsn:     "user:pass@tcp(localhost:3306)/goauth?parseTime=true",
			wantErr: false,
		},
		{
			name:    "parseTime 1",
			dsn:     "user:pass@tcp(localhost:3306)/goauth?parseTime=1",
			wantErr: false,
		},
		{
			name:    "parseTime TRUE case-insensitive",
			dsn:     "user:pass@tcp(localhost:3306)/goauth?parseTime=TRUE",
			wantErr: false,
		},
		{
			name:    "missing parseTime entirely",
			dsn:     "user:pass@tcp(localhost:3306)/goauth",
			wantErr: true,
		},
		{
			name:    "parseTime false rejected",
			dsn:     "user:pass@tcp(localhost:3306)/goauth?parseTime=false",
			wantErr: true,
		},
		{
			name:    "parseTime 0 rejected",
			dsn:     "user:pass@tcp(localhost:3306)/goauth?parseTime=0",
			wantErr: true,
		},
		{
			name:    "malformed query string rejected",
			dsn:     "user:pass@tcp(localhost:3306)/goauth?parseTime=%zz",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateMySQLDSN(tt.dsn)
			if got := err != nil; got != tt.wantErr {
				t.Fatalf("ValidateMySQLDSN(%q) error = %v, wantErr %v", tt.dsn, err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), "parseTime=true") {
				t.Fatalf("error should name the fix, got: %v", err)
			}
		})
	}
}
