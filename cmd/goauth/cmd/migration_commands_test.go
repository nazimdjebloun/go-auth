package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	goauth "github.com/nazimdjebloun/go-auth"
)

func executeMigrationCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newMigrateCommand()
	cmd.SilenceErrors, cmd.SilenceUsage = true, true
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(t.Context())
	return output.String(), err
}

func TestMigrationCommandFreshStatusAndVerify(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "auth.db")
	flags := []string{"--driver", "sqlite", "--dsn", dsn}
	if _, err := executeMigrationCommand(t, flags...); err != nil {
		t.Fatal(err)
	}
	output, err := executeMigrationCommand(t, append([]string{"status"}, flags...)...)
	if err != nil {
		t.Fatal(err)
	}
	var status goauth.MigrationStatus
	if err := json.Unmarshal([]byte(output), &status); err != nil || status.Revision != status.TargetRevision || status.Revision < 2 {
		t.Fatalf("invalid status report: %s, %v", output, err)
	}
	if _, err := executeMigrationCommand(t, append([]string{"verify"}, flags...)...); err != nil {
		t.Fatal(err)
	}
}

func TestMigrationCommandsRequireExplicitInputs(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "driver", args: []string{"--dsn", "unused"}},
		{name: "dsn", args: []string{"status", "--driver", "sqlite"}},
		{name: "baseline", args: []string{"adopt", "--driver", "sqlite", "--dsn", "unused"}},
		{name: "repair ID", args: []string{"repair", "--driver", "sqlite", "--dsn", "unused"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := executeMigrationCommand(t, tc.args...); err == nil {
				t.Fatal("missing required input was accepted")
			}
		})
	}
}

func TestMigrationCommandValidatesBeforeOpeningDatabase(t *testing.T) {
	for _, tc := range []struct {
		name  string
		flags []string
	}{
		{name: "driver", flags: []string{"--driver", "oracle"}},
		{name: "timeout", flags: []string{"--driver", "sqlite", "--timeout", "0s"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dsn := filepath.Join(t.TempDir(), "must-not-exist.db")
			if _, err := executeMigrationCommand(t, append(tc.flags, "--dsn", dsn)...); err == nil {
				t.Fatal("invalid input was accepted")
			}
			if _, err := os.Stat(dsn); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid input opened the database", err)
			}
		})
	}
}

func TestMigrationCommandDoesNotExposeDriverData(t *testing.T) {
	cause := &mysql.MySQLError{Number: 1062, Message: "Duplicate entry 'private-auth-data'"}
	err := migrationCommandError(&goauth.MigrationError{
		Dialect: "mysql", MigrationID: 42, Phase: "statement 2", Dirty: true, Uncertain: true, Cause: cause,
	})
	if strings.Contains(err.Error(), "private-auth-data") || !strings.Contains(err.Error(), "000042") {
		t.Fatalf("unsafe or unhelpful command error: %v", err)
	}
	var driverError *mysql.MySQLError
	if !errors.As(err, &driverError) || driverError != cause {
		t.Fatal("wrapped driver cause was lost")
	}
	_, err = executeMigrationCommand(t, "--driver", "postgres", "--dsn", "postgres://user:private-password@localhost/db?sslmode=invalid")
	if err == nil || strings.Contains(err.Error(), "private-password") {
		t.Fatalf("unsafe connection error: %v", err)
	}
}

func TestGenerateCommandExportsSeparateArtifacts(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "auth")
	cmd := newGenerateCommand()
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetArgs([]string{"--driver", "sqlite", "--out", directory})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"auth.schema.sql", "reference.md", "migrations/catalog.json", "migrations/000001_v0.4.0_001.sql"} {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Fatal("missing auth artifact", name, err)
		}
	}
}
