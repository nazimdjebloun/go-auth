package service

import (
	"errors"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

// Deleting or updating a business definition requires the non-owner to hold
// the target key — never just the operation's management permission.
func TestOrgPermissionsDeletePermissionRequiresTargetGrant(t *testing.T) {
	f := newOrgPermissionFixture(t)
	f.install(t, "goauth.org.permissions.read", "goauth.org.permissions.update", "goauth.org.permissions.delete")
	p, err := f.s.CreatePermission(t.Context(), api.CreateOrgPermissionInput{Actor: f.owner, Key: "org.projects.read", Name: "Projects"})
	if err != nil {
		t.Fatal(err)
	}
	manager := f.role(t, "perm-manager", "goauth.org.permissions.read", "goauth.org.permissions.delete")
	member := f.member(t, domain.OrgRoleMember)
	f.assign(t, member, manager)

	if err := f.s.DeletePermission(t.Context(), api.DeleteOrgPermissionInput{Actor: member, PermissionID: p.ID, ExpectedRevision: p.Revision}); !errors.Is(err, domain.ErrOrgForbidden) {
		t.Fatalf("delete without target grant: %v", err)
	}
	name := "Projects v2"
	if _, err := f.s.UpdatePermission(t.Context(), api.UpdateOrgPermissionInput{Actor: member, PermissionID: p.ID, ExpectedRevision: p.Revision, Name: &name}); !errors.Is(err, domain.ErrOrgForbidden) {
		t.Fatalf("update without target grant: %v", err)
	}

	// A role that grants the target key plus the operation keys authorizes updates.
	elevated := f.role(t, "key-holder", "goauth.org.permissions.read", "goauth.org.permissions.update", "goauth.org.permissions.delete", "org.projects.read")
	holder := f.member(t, domain.OrgRoleMember)
	f.assign(t, holder, elevated)
	updated, err := f.s.UpdatePermission(t.Context(), api.UpdateOrgPermissionInput{Actor: holder, PermissionID: p.ID, ExpectedRevision: p.Revision, Name: &name})
	if err != nil {
		t.Fatalf("update with target grant: %v", err)
	}
	if updated.Revision != p.Revision+1 {
		t.Fatalf("update did not advance the revision: %+v", updated)
	}
	if still, err := f.s.permissions.PermissionByID(t.Context(), f.owner.OrgID, p.ID); err != nil || still == nil {
		t.Fatalf("update lost the definition: %+v error=%v", still, err)
	}
}

// An eligible caller can inspect both endpoints for a banned member or a
// member assigned a disabled custom role: role read and access read both
// stay available while permissionKeys stay empty.
func TestOrgPermissionsAccessInspectDisabledRoleTarget(t *testing.T) {
	f := newOrgPermissionFixture(t)
	member := f.member(t, domain.OrgRoleMember)
	role := f.role(t, "limited")
	f.assign(t, member, role)
	disabled := false
	if _, err := f.s.UpdateRole(t.Context(), api.UpdateOrgRoleInput{Actor: f.owner, RoleID: role.ID, ExpectedRevision: role.Revision, IsEnabled: &disabled}); err != nil {
		t.Fatal(err)
	}

	roleResult, err := f.s.GetMemberRole(t.Context(), api.GetOrgMemberRoleInput{Actor: f.owner, UserID: member.UserID})
	if err != nil {
		t.Fatalf("disabled role not inspectable: %v", err)
	}
	if roleResult.Role.IsEnabled {
		t.Fatalf("expected disabled role: %+v", roleResult.Role)
	}
	access, err := f.s.ListEffectivePermissions(t.Context(), api.ListOrgEffectivePermissionsInput{Actor: f.owner, UserID: member.UserID})
	if err != nil {
		t.Fatalf("disabled target not inspectable on access: %v", err)
	}
	if access.Role.IsEnabled || access.IsFullAccess || len(access.PermissionKeys) != 0 || access.AssignmentRevision != 1 {
		t.Fatalf("ineligible target exposed access: %+v", access)
	}
}
