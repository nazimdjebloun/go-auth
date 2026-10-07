package sqlstore

import (
	"context"
	"strings"
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

func TestAppPermissionNamespaceOwnership(t *testing.T) {
	db := backendDB(t)
	ctx := t.Context()
	now := time.Now().UTC()

	// Direct SQL must enforce ownership even when service validation is bypassed.
	for _, tt := range []struct {
		name     string
		key      string
		isSystem bool
		accepted bool
	}{
		{"business", "app.posts.read", false, true},
		{"library", "goauth.app.users.read", true, true},
		{"library_as_business", "goauth.app.sessions.revoke", false, false},
		{"business_as_library", "app.posts.delete", true, false},
		{"uppercase_prefix", "GOAUTH.APP.users.read", true, false},
		{"missing_delimiter", "goauth.appusers.read", true, false},
		{"longer_namespace", "goauth.applications.read", true, false},
		{"embedded_prefix", "app.goauth.app.read", true, false},
	} {
		t.Run("insert/"+tt.name, func(t *testing.T) {
			id := uuid.NewString()
			_, err := db.ExecContext(ctx, `INSERT INTO app_permissions
				(id,permission_key,name,description,is_system,created_at,updated_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7)`, id, tt.key, "Permission", "", tt.isSystem, now, now)
			if (err == nil) != tt.accepted {
				t.Fatalf("insert accepted=%t, want %t: %v", err == nil, tt.accepted, err)
			}
			if !tt.accepted && !strings.Contains(err.Error(), "app_permissions_namespace_owner") {
				t.Fatalf("insert failed outside the ownership constraint: %v", err)
			}
			var count int
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM app_permissions WHERE id=$1`, id).Scan(&count); err != nil {
				t.Fatal(err)
			}
			wantCount := 0
			if tt.accepted {
				wantCount = 1
			}
			if count != wantCount {
				t.Fatalf("persisted %d rows, want %d", count, wantCount)
			}
		})
	}

	for _, tt := range []struct {
		name         string
		originalKey  string
		originalKind bool
		key          string
		isSystem     bool
	}{
		{"remove_library_ownership", "goauth.app.test.remove", true, "goauth.app.test.remove", false},
		{"add_library_ownership", "app.test.add", false, "app.test.add", true},
		{"rename_to_library", "app.test.rename", false, "goauth.app.test.rename", false},
		{"rename_to_business", "goauth.app.test.business", true, "app.test.business", true},
	} {
		t.Run("update/"+tt.name, func(t *testing.T) {
			id := uuid.NewString()
			if _, err := db.ExecContext(ctx, `INSERT INTO app_permissions
				(id,permission_key,name,description,is_system,created_at,updated_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7)`, id, tt.originalKey, "Permission", "", tt.originalKind, now, now); err != nil {
				t.Fatal(err)
			}
			_, err := db.ExecContext(ctx, `UPDATE app_permissions SET permission_key=$1,is_system=$2 WHERE id=$3`, tt.key, tt.isSystem, id)
			if err == nil {
				t.Fatal("accepted inconsistent permission ownership")
			}
			if !strings.Contains(err.Error(), "app_permissions_namespace_owner") {
				t.Fatalf("update failed outside the ownership constraint: %v", err)
			}
			var key string
			var isSystem bool
			if err := db.QueryRowContext(ctx, `SELECT permission_key,is_system FROM app_permissions WHERE id=$1`, id).Scan(&key, &isSystem); err != nil {
				t.Fatal(err)
			}
			if key != tt.originalKey || isSystem != tt.originalKind {
				t.Fatalf("rejected update changed row: key=%q, is_system=%t", key, isSystem)
			}
			// A valid update on the same row rules out unrelated update failures.
			if _, err := db.ExecContext(ctx, `UPDATE app_permissions SET name=$1 WHERE id=$2`, "Updated", id); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAppDefaultRoleSharedReadRequiresTransaction(t *testing.T) {
	db := backendDB(t)
	repo := NewAppPermissionsRepository(db)
	if _, err := repo.RoleBySlugForShare(t.Context(), "user"); err == nil {
		t.Fatal("shared default-role read accepted autocommit")
	}
	if err := db.WithTx(t.Context(), func(ctx context.Context) error {
		role, err := repo.RoleBySlugForShare(ctx, "missing")
		if err != nil {
			return err
		}
		if role != nil {
			t.Fatalf("missing role returned %+v", role)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
