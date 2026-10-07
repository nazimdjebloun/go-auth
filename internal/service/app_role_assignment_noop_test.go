package service

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
)

type appRoleAssignmentAudit struct{ events []audit.Event }

func (a *appRoleAssignmentAudit) Record(_ context.Context, event audit.Event) error {
	a.events = append(a.events, event)
	return nil
}

func TestAppSameRoleAssignmentIsNoOp(t *testing.T) {
	for _, slug := range []string{"user", "admin", "custom"} {
		t.Run(slug, func(t *testing.T) {
			f := newAppFixture(t)
			ctx := t.Context()
			target := f.account(t)
			var role *domain.AppRole
			var err error
			if slug == "custom" {
				permission, err := f.s.CreatePermission(ctx, api.CreateAppPermissionInput{Actor: f.admin, Key: "app.noop.read", Name: "Read"})
				if err != nil {
					t.Fatal(err)
				}
				role = f.role(t, "custom", permission.Key)
				f.assign(t, target, role)
			} else {
				role, err = f.repo.RoleBySlug(ctx, slug)
				if err != nil {
					t.Fatal(err)
				}
				if slug == "admin" {
					target = f.admin
				}
			}
			before, err := f.users.GetByID(ctx, target.UserID)
			if err != nil {
				t.Fatal(err)
			}
			revision, err := f.repo.AppStateRevision(ctx)
			if err != nil {
				t.Fatal(err)
			}
			recorder := &appRoleAssignmentAudit{}
			f.s.config.Audit = recorder
			input := api.SetAppUserRoleInput{Actor: f.admin, UserID: target.UserID, RoleID: role.ID, ExpectedRoleRevision: role.Revision, ExpectedAssignmentRevision: before.AppRoleAssignmentRevision}
			for range 2 {
				result, err := f.s.SetUserRole(ctx, input)
				if err != nil || result.Role.ID != role.ID || result.AssignmentRevision != before.AppRoleAssignmentRevision || !slices.Equal(result.Role.PermissionKeys, role.PermissionKeys) {
					t.Fatalf("same-role result: %+v, %v", result, err)
				}
			}
			after, err := f.users.GetByID(ctx, target.UserID)
			if err != nil {
				t.Fatal(err)
			}
			afterRevision, err := f.repo.AppStateRevision(ctx)
			if err != nil {
				t.Fatal(err)
			}
			afterRole, err := f.repo.RoleByID(ctx, role.ID)
			if err != nil {
				t.Fatal(err)
			}
			keys, err := f.repo.RoleGrantKeys(ctx, role.ID)
			if err != nil || !slices.Equal(keys, role.PermissionKeys) {
				t.Fatalf("no-op changed role grants: %v, %v", keys, err)
			}
			if afterRevision != revision || after.AppRoleAssignmentRevision != before.AppRoleAssignmentRevision || !after.UpdatedAt.Equal(before.UpdatedAt) || afterRole.Revision != role.Revision || len(recorder.events) != 0 {
				t.Fatalf("no-op changed state: app=%d/%d, account=%+v/%+v, role=%d/%d, audit=%d", revision, afterRevision, before, after, role.Revision, afterRole.Revision, len(recorder.events))
			}
			for _, tt := range []struct {
				name  string
				input api.SetAppUserRoleInput
				want  error
			}{
				{name: "stale_assignment", input: api.SetAppUserRoleInput{Actor: f.admin, UserID: target.UserID, RoleID: role.ID, ExpectedRoleRevision: role.Revision}, want: domain.ErrAppAuthorizationConflict},
				{name: "stale_role", input: api.SetAppUserRoleInput{Actor: f.admin, UserID: target.UserID, RoleID: role.ID, ExpectedAssignmentRevision: before.AppRoleAssignmentRevision}, want: domain.ErrAppAuthorizationConflict},
				{name: "unauthorized", input: api.SetAppUserRoleInput{Actor: target, UserID: target.UserID, RoleID: role.ID, ExpectedRoleRevision: role.Revision, ExpectedAssignmentRevision: before.AppRoleAssignmentRevision}, want: domain.ErrForbidden},
			} {
				if slug == "admin" && tt.name == "unauthorized" {
					continue // The protected admin is authorized to retain its own role.
				}
				t.Run(tt.name, func(t *testing.T) {
					if _, err := f.s.SetUserRole(ctx, tt.input); !errors.Is(err, tt.want) {
						t.Fatalf("same-role validation=%v, want %v", err, tt.want)
					}
				})
			}
		})
	}
}

func TestAppSameRoleAssignmentDelegationBoundaries(t *testing.T) {
	f := newAppFixture(t)
	ctx := t.Context()
	f.install(t, "goauth.app.roles.assign")
	managerRole := f.role(t, "manager", "goauth.app.roles.assign")
	manager := f.account(t)
	f.assign(t, manager, managerRole)
	managerUser, err := f.users.GetByID(ctx, manager.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.SetUserRole(ctx, api.SetAppUserRoleInput{Actor: manager, UserID: manager.UserID, RoleID: managerRole.ID, ExpectedRoleRevision: managerRole.Revision, ExpectedAssignmentRevision: managerUser.AppRoleAssignmentRevision}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("same-role bypassed delegated self-assignment restriction: %v", err)
	}
	permission, err := f.s.CreatePermission(ctx, api.CreateAppPermissionInput{Actor: f.admin, Key: "app.restricted.read", Name: "Restricted"})
	if err != nil {
		t.Fatal(err)
	}
	role := f.role(t, "restricted", permission.Key)
	target := f.account(t)
	f.assign(t, target, role)
	user, err := f.users.GetByID(ctx, target.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.SetUserRole(ctx, api.SetAppUserRoleInput{Actor: manager, UserID: target.UserID, RoleID: role.ID, ExpectedRoleRevision: role.Revision, ExpectedAssignmentRevision: user.AppRoleAssignmentRevision}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("same-role bypassed held-permission boundary: %v", err)
	}
}

func TestAppChangedRoleAssignmentAdvancesRevision(t *testing.T) {
	f := newAppFixture(t)
	ctx := t.Context()
	target := f.account(t)
	role := f.role(t, "replacement")
	before, err := f.users.GetByID(ctx, target.UserID)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := f.repo.AppStateRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	recorder := &appRoleAssignmentAudit{}
	f.s.config.Audit = recorder
	result, err := f.s.SetUserRole(ctx, api.SetAppUserRoleInput{Actor: f.admin, UserID: target.UserID, RoleID: role.ID, ExpectedRoleRevision: role.Revision, ExpectedAssignmentRevision: before.AppRoleAssignmentRevision})
	if err != nil || result.AssignmentRevision != before.AppRoleAssignmentRevision+1 {
		t.Fatalf("changed assignment: %+v, %v", result, err)
	}
	afterRevision, err := f.repo.AppStateRevision(ctx)
	if err != nil || afterRevision != revision+1 || len(recorder.events) != 1 || recorder.events[0].Type != audit.EventAppUserRoleChanged {
		t.Fatalf("changed revision/audit: %d/%d, %+v, %v", revision, afterRevision, recorder.events, err)
	}
}

func TestAppRoleAssignmentAuditFailureRollsBack(t *testing.T) {
	f := newAppFixture(t)
	ctx := t.Context()
	target := f.account(t)
	role := f.role(t, "replacement")
	before, err := f.users.GetByID(ctx, target.UserID)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := f.repo.AppStateRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.s.config.Audit = appBlockingAudit{}
	if _, err := f.s.SetUserRole(ctx, api.SetAppUserRoleInput{Actor: f.admin, UserID: target.UserID, RoleID: role.ID, ExpectedRoleRevision: role.Revision, ExpectedAssignmentRevision: before.AppRoleAssignmentRevision}); err == nil {
		t.Fatal("audit failure accepted a changed assignment")
	}
	after, err := f.users.GetByID(ctx, target.UserID)
	if err != nil {
		t.Fatal(err)
	}
	afterRevision, err := f.repo.AppStateRevision(ctx)
	if err != nil || afterRevision != revision || after.AppRoleAssignmentRevision != before.AppRoleAssignmentRevision || *after.AppRoleID != *before.AppRoleID {
		t.Fatalf("audit failure left assignment changes: %+v -> %+v, app=%d/%d: %v", before, after, revision, afterRevision, err)
	}
}

func TestAppConcurrentSameRoleAssignmentsPreserveRevision(t *testing.T) {
	f := newAppFixture(t)
	ctx := t.Context()
	target := f.account(t)
	role := f.role(t, "operator")
	f.assign(t, target, role)
	user, err := f.users.GetByID(ctx, target.UserID)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := f.repo.AppStateRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	otherDB := sqlstore.NewDB(testdb.SecondPool(t, f.db.DB), f.db.Driver())
	otherUsers := sqlstore.NewUserRepository(otherDB).WithAppPermissions()
	otherRepo := sqlstore.NewAppPermissionsRepository(otherDB)
	other := NewAppPermissionsService(otherDB, otherUsers, nil, nil, otherRepo, otherRepo, otherRepo, otherRepo, AppPermissionsServiceConfig{})
	input := api.SetAppUserRoleInput{Actor: f.admin, UserID: target.UserID, RoleID: role.ID, ExpectedRoleRevision: role.Revision, ExpectedAssignmentRevision: user.AppRoleAssignmentRevision}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, service := range []*AppPermissionsService{f.s, other} {
		go func() {
			<-start
			_, err := service.SetUserRole(ctx, input)
			results <- err
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	after, err := f.repo.AppStateRevision(ctx)
	if err != nil || after != revision {
		t.Fatalf("concurrent no-op revision=%d, want %d: %v", after, revision, err)
	}
}
