package sqlstore

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/domain"
)

func TestAppAuthorizationSchemaIntegrity(t *testing.T) {
	db := backendDB(t)
	ctx := t.Context()
	now := time.Now().UTC()
	roleID, permissionID := uuid.NewString(), uuid.NewString()
	if _, err := db.ExecContext(ctx, `INSERT INTO app_roles (id,slug,name,description,is_enabled,system_key,created_at,updated_at) VALUES ($1,$2,$3,$4,true,$5,$6,$7)`, roleID, "admin", "Admin", "", domain.AppRoleAdmin, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO app_roles (id,slug,name,description,system_key,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7)`, uuid.NewString(), "other-admin", "Other", "", domain.AppRoleAdmin, now, now); err == nil {
		t.Fatal("duplicate protected identity accepted")
	}
	userID := backendUser(t, db)
	if _, err := db.ExecContext(ctx, `UPDATE users SET app_role_id=$1,app_role_assignment_revision=1 WHERE id=$2`, roleID, userID); err != nil {
		t.Fatal(err)
	}
	u, err := NewUserRepository(db).GetByID(ctx, userID)
	if err != nil || u.AppRoleID == nil || *u.AppRoleID != roleID || u.AppRoleAssignmentRevision != 1 {
		t.Fatalf("role round trip: %+v, %v", u, err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM app_roles WHERE id=$1`, roleID); err == nil {
		t.Fatal("deleted an assigned role")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO app_permissions (id,permission_key,name,description,is_system,created_at,updated_at) VALUES ($1,$2,$3,$4,true,$5,$6)`, permissionID, "goauth.app.sessions.revoke", "Revoke sessions", "", now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE app_permissions SET is_enabled=false WHERE id=$1`, permissionID); err == nil {
		t.Fatal("disabled a library-owned definition")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO app_role_permissions(role_id,permission_id,granted_by,created_at) VALUES ($1,$2,$3,$4)`, roleID, permissionID, userID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM app_permissions WHERE id=$1`, permissionID); err == nil {
		t.Fatal("definition deletion bypassed grant cleanup")
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO app_authorization_state(id,revision,created_at) VALUES (2,1,$1)`, now); err == nil {
		t.Fatal("authorization state accepted non-singleton id")
	}
}
