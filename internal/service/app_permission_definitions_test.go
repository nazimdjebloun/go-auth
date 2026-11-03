package service

import (
	"errors"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

func TestAppPermissionDeletionDelegation(t *testing.T) {
	tests := []struct {
		name     string
		delegate bool
		grant    bool
		disabled bool
		system   bool
		stale    bool
		wantErr  error
	}{
		{name: "unheld unused definition", delegate: true, wantErr: domain.ErrForbidden},
		{name: "held definition remains in use", delegate: true, grant: true, wantErr: domain.ErrAppPermissionInUse},
		{name: "disabled definition is not held", delegate: true, grant: true, disabled: true, wantErr: domain.ErrForbidden},
		{name: "system definition remains protected", delegate: true, system: true, wantErr: domain.ErrProtectedAppPermission},
		{name: "administrator must supply current revision", stale: true, wantErr: domain.ErrAppAuthorizationConflict},
		{name: "administrator can delete unused definition"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newAppFixture(t)
			ctx := t.Context()
			f.install(t, "goauth.app.permissions.delete")
			p, err := f.s.CreatePermission(ctx, api.CreateAppPermissionInput{
				Actor: f.admin, Key: "app.reports.export", Name: "Export reports",
			})
			if err != nil {
				t.Fatal(err)
			}
			actor := f.admin
			if tt.delegate {
				actor = f.account(t)
				keys := []string{"goauth.app.permissions.delete"}
				if tt.grant {
					keys = append(keys, p.Key)
				}
				f.assign(t, actor, f.role(t, "operator", keys...))
			}
			if tt.disabled {
				enabled := false
				p, err = f.s.UpdatePermission(ctx, api.UpdateAppPermissionInput{
					Actor: f.admin, PermissionID: p.ID, ExpectedRevision: p.Revision, IsEnabled: &enabled,
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			if tt.system {
				p, err = f.repo.PermissionByKey(ctx, "goauth.app.permissions.delete")
				if err != nil || p == nil {
					t.Fatalf("load system permission: %v, %v", p, err)
				}
			}
			revision := p.Revision
			if tt.stale {
				revision++
			}
			before, err := f.repo.AppStateRevision(ctx)
			if err != nil {
				t.Fatal(err)
			}
			err = f.s.DeletePermission(ctx, api.DeleteAppPermissionInput{
				Actor: actor, PermissionID: p.ID, ExpectedRevision: revision,
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("delete permission: got %v, want %v", err, tt.wantErr)
			}
			remaining, err := f.repo.PermissionByID(ctx, p.ID)
			if err != nil {
				t.Fatal(err)
			}
			after, err := f.repo.AppStateRevision(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantErr != nil {
				if remaining == nil || remaining.Revision != p.Revision || after != before {
					t.Fatalf("rejected deletion changed definition or authorization revision: permission=%v, revision=%d -> %d", remaining, before, after)
				}
			} else if remaining != nil || after != before+1 {
				t.Fatalf("successful deletion did not remove definition and advance authorization revision: permission=%v, revision=%d -> %d", remaining, before, after)
			}
		})
	}
}
