package sqlstore

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestAppUserRoleRepresentation(t *testing.T) {
	for _, tt := range []struct {
		name    string
		enabled bool
	}{
		{name: "disabled", enabled: false},
		{name: "enabled", enabled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			db := backendDB(t)
			ctx := t.Context()
			now := time.Now().UTC()
			fixedRoles := NewUserRepository(db)
			id, roleID := uuid.NewString(), uuid.NewString()
			user := &domain.User{ID: id, Email: id + "@example.com", Role: domain.RoleAdmin, CreatedAt: now, UpdatedAt: now}
			if err := fixedRoles.Create(ctx, user); err != nil {
				t.Fatal(err)
			}
			if err := NewAppPermissionsRepository(db).InsertAppRole(ctx, &domain.AppRole{ID: roleID, Slug: "support", Name: "Support", IsEnabled: true, Revision: 1, CreatedAt: now, UpdatedAt: now}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, `UPDATE users SET app_role_id=$1,app_role_assignment_revision=1 WHERE id=$2`, roleID, id); err != nil {
				t.Fatal(err)
			}
			repo := NewUserRepository(db)
			sessions := NewSessionRepository(db)
			orgs := NewOrgRepository(db)
			if tt.enabled {
				repo.WithAppPermissions()
				sessions.WithAppPermissions()
				orgs.WithAppPermissions()
			}
			check := func(t *testing.T, user *domain.User) {
				t.Helper()
				if user == nil || user.ID != id || user.AppRoleID == nil || *user.AppRoleID != roleID || user.AppRoleAssignmentRevision != 1 {
					t.Fatalf("lost account or app role data: %+v", user)
				}
				wantRole := domain.RoleAdmin
				if tt.enabled {
					wantRole = ""
				}
				if user.Role != wantRole {
					t.Fatalf("role=%q, want %q", user.Role, wantRole)
				}
				data, err := json.Marshal(user)
				if err != nil {
					t.Fatal(err)
				}
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(data, &fields); err != nil {
					t.Fatal(err)
				}
				if _, present := fields["role"]; present == tt.enabled {
					t.Fatalf("account role JSON presence disagrees with mode: %s", data)
				}
			}
			t.Run("id", func(t *testing.T) {
				u, err := repo.GetByID(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				check(t, u)
			})
			t.Run("email", func(t *testing.T) {
				u, err := repo.GetByEmail(ctx, user.Email)
				if err != nil {
					t.Fatal(err)
				}
				check(t, u)
			})
			t.Run("list", func(t *testing.T) {
				users, err := repo.List(ctx, port.UserFilter{})
				if err != nil || len(users) != 1 {
					t.Fatalf("list=%+v: %v", users, err)
				}
				check(t, &users[0])
			})
			t.Run("locked", func(t *testing.T) {
				if err := db.WithTx(ctx, func(ctx context.Context) error {
					u, err := repo.GetByIDForUpdate(ctx, id)
					if err == nil {
						check(t, u)
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
			})
			t.Run("session_join", func(t *testing.T) {
				s := &domain.Session{ID: uuid.NewString(), UserID: id, TokenHash: "access", RefreshTokenHash: "refresh", ExpiresAt: now.Add(time.Hour), RefreshExpiresAt: now.Add(2 * time.Hour), CreatedAt: now, LastActiveAt: now}
				if err := sessions.Create(ctx, s); err != nil {
					t.Fatal(err)
				}
				_, u, err := sessions.GetByTokenHashWithUser(ctx, s.TokenHash)
				if err != nil {
					t.Fatal(err)
				}
				check(t, u)
			})
			t.Run("org_member", func(t *testing.T) {
				orgID := uuid.NewString()
				if err := orgs.Create(ctx, &domain.Organization{ID: orgID, Name: "Team", Slug: "team", CreatedAt: now, UpdatedAt: now}); err != nil {
					t.Fatal(err)
				}
				if err := orgs.AddMember(ctx, &domain.OrgMember{OrgID: orgID, UserID: id, Role: domain.OrgRoleOwner, JoinedAt: now}); err != nil {
					t.Fatal(err)
				}
				members, err := orgs.ListMembers(ctx, orgID, port.OrgMemberFilter{})
				if err != nil || len(members) != 1 || members[0].Role != domain.OrgRoleOwner {
					t.Fatalf("membership changed: %+v, %v", members, err)
				}
				check(t, members[0].User)
			})
			t.Run("create", func(t *testing.T) {
				db := backendDB(t)
				repo := NewUserRepository(db)
				if tt.enabled {
					repo.WithAppPermissions()
				}
				id := uuid.NewString()
				u := &domain.User{ID: id, Email: id + "@example.com", Role: domain.RoleAdmin, CreatedAt: now, UpdatedAt: now}
				if err := repo.Create(ctx, u); err != nil {
					t.Fatal(err)
				}
				wantReturned, wantStored := domain.RoleAdmin, domain.RoleAdmin
				if tt.enabled {
					wantReturned, wantStored = "", domain.RoleUser
				}
				var stored domain.Role
				if err := db.QueryRowContext(ctx, `SELECT role FROM users WHERE id=$1`, id).Scan(&stored); err != nil {
					t.Fatal(err)
				}
				if u.Role != wantReturned || stored != wantStored {
					t.Fatalf("returned/stored role=%q/%q, want %q/%q", u.Role, stored, wantReturned, wantStored)
				}
			})
			t.Run("mode_isolation", func(t *testing.T) {
				u, err := fixedRoles.GetByID(ctx, id)
				if err != nil || u == nil || u.Role != domain.RoleAdmin {
					t.Fatalf("app mode reads changed the fixed-role instance or stored role: %+v, %v", u, err)
				}
			})
		})
	}
}
