package cmd

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/schema"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
)

func TestPermissionsCatalogNeedsNoDatabase(t *testing.T) {
	command := newPermissionsCommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetArgs([]string{"catalog"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	var catalog []domain.AppLibraryPermissionDefinition
	if err := json.Unmarshal(output.Bytes(), &catalog); err != nil || len(catalog) != 23 {
		t.Fatalf("catalog=%v error=%v", catalog, err)
	}
}

func TestPermissionsCommandSeedAndMixedUpdate(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "command.db")
	raw, err := sql.Open("sqlite", dsn+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := raw.Close(); err != nil {
			t.Errorf("close test database: %v", err)
		}
	})
	ddl, err := schema.For("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range schema.SplitSQL(ddl) {
		if _, err := raw.ExecContext(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	id := uuid.NewString()
	db := sqlstore.NewDB(raw, "sqlite")
	if err := seedAppAdministrator(t.Context(), &domain.User{ID: id, Email: id + "@example.com", Role: domain.RoleAdmin, CreatedAt: now, UpdatedAt: now}, false, db); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (api.UpdateAppLibraryPermissionsResult, error) {
		t.Helper()
		command := newPermissionsCommand()
		var output bytes.Buffer
		command.SetOut(&output)
		command.SetErr(&output)
		command.SetContext(t.Context())
		command.SetArgs(append(args, "--driver", "sqlite", "--dsn", dsn+"?_pragma=foreign_keys(0)", "--actor-id", id))
		var result api.UpdateAppLibraryPermissionsResult
		if err := command.Execute(); err != nil {
			return result, err
		}
		return result, json.Unmarshal(output.Bytes(), &result)
	}
	result, err := run("seed", "--keys", "goauth.app.users.read,goauth.app.sessions.read")
	if err != nil || len(result.Created) != 2 {
		t.Fatalf("seed command: %+v %v", result, err)
	}
	result, err = run("update", "--create", "goauth.app.sessions.revoke", "--delete", "goauth.app.users.read,goauth.app.sessions.read")
	if err != nil || len(result.Created) != 1 || len(result.Deleted) != 2 {
		t.Fatalf("mixed update command: %+v %v", result, err)
	}
	if _, err := run("update", "--create", "goauth.app.users.read", "--delete", "goauth.app.users.read"); err == nil {
		t.Fatal("overlapping CLI batch accepted")
	}
	repo := sqlstore.NewAppPermissionsRepository(db)
	rows, err := repo.ListAppPermissions(t.Context(), 100, 0)
	if err != nil || len(rows) != 1 || rows[0].Key != "goauth.app.sessions.revoke" {
		t.Fatalf("invalid command changed definitions: %+v %v", rows, err)
	}
}

func TestPermissionsCLIProvisioningAndAdministratorBootstrap(t *testing.T) {
	raw := testdb.OpenSelected(t)
	testdb.Apply(t, raw)
	db := sqlstore.NewDB(raw, testdb.Driver(raw))
	now := time.Now().UTC()
	id := uuid.NewString()
	user := &domain.User{ID: id, Email: id + "@example.com", Role: domain.RoleAdmin, IsVerified: true, CreatedAt: now, UpdatedAt: now}
	if err := seedAppAdministrator(t.Context(), user, false, db); err != nil {
		t.Fatal(err)
	}
	if user.AppRoleID == nil || user.AppRoleAssignmentRevision != 1 {
		t.Fatal("bootstrap missing protected assignment")
	}
	s, users, repo := cliAppPermissions(db)
	rows, err := repo.ListAppPermissions(t.Context(), 100, 0)
	if err != nil || len(rows) != 0 {
		t.Fatalf("automatic seeding: %v %v", rows, err)
	}
	sibling := *user
	sibling.ID = uuid.NewString()
	sibling.Email = sibling.ID + "@example.com"
	sibling.AppRoleID = nil
	sibling.AppRoleAssignmentRevision = 0
	if err := seedAppAdministrator(t.Context(), &sibling, false, db); err == nil {
		t.Fatal("second bootstrap did not require force")
	}
	if found, err := users.GetByID(t.Context(), sibling.ID); err != nil || found != nil {
		t.Fatal("failed bootstrap left account")
	}
	if err := seedAppAdministrator(t.Context(), &sibling, true, db); err != nil {
		t.Fatal(err)
	}
	provisioner := service.NewAppLibraryPermissionCLIProvisioner(s)
	input := api.UpdateAppLibraryPermissionsInput{Actor: api.AppPermissionActor{UserID: user.ID}, Create: []string{"goauth.app.sessions.revoke", "goauth.app.users.read"}}
	if _, err := provisioner.Update(t.Context(), input); err != nil {
		t.Fatal(err)
	}
	result, err := provisioner.Update(t.Context(), input)
	if err != nil || len(result.Unchanged) != 2 {
		t.Fatalf("retry: %+v %v", result, err)
	}
	// Ordinary runtime provisioning still requires assurance; only the module's
	// local CLI collaborator can use the database-administration trust boundary.
	sRuntime, _, _ := cliAppPermissions(db)
	// A nonexistent/banned administrator is rejected even for a local command.
	input.Actor.UserID = uuid.NewString()
	if _, err := service.NewAppLibraryPermissionCLIProvisioner(sRuntime).Update(t.Context(), input); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("missing actor accepted: %v", err)
	}
	var count int
	if err := db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM audit_log WHERE actor_id=$1", user.ID).Scan(&count); err != nil || count < 2 {
		t.Fatalf("missing CLI records: %d %v", count, err)
	}
}

func TestPermissionsCLIAuditFailureRollsBackBatch(t *testing.T) {
	raw := testdb.OpenSelected(t)
	testdb.Apply(t, raw)
	db := sqlstore.NewDB(raw, testdb.Driver(raw))
	now := time.Now().UTC()
	id := uuid.NewString()
	u := &domain.User{ID: id, Email: id + "@example.com", Role: domain.RoleAdmin, CreatedAt: now, UpdatedAt: now}
	if err := seedAppAdministrator(t.Context(), u, false, db); err != nil {
		t.Fatal(err)
	}
	s, _, repo := cliAppPermissions(db)
	if _, err := db.ExecContext(t.Context(), "DROP TABLE audit_log"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.NewAppLibraryPermissionCLIProvisioner(s).Update(t.Context(), api.UpdateAppLibraryPermissionsInput{Actor: api.AppPermissionActor{UserID: id}, Create: []string{"goauth.app.users.read"}}); err == nil {
		t.Fatal("fail-closed audit did not abort")
	}
	if p, err := repo.PermissionByKey(t.Context(), "goauth.app.users.read"); err != nil || p != nil {
		t.Fatalf("partial write survived: %+v %v", p, err)
	}
}
