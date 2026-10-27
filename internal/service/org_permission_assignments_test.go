package service

import (
	"errors"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

func TestOrgPermissionsFixedRoleAssignmentRevision(t *testing.T) {
	for _, mode := range []string{"normal", "admin", "disabled", "admin-disabled"} {
		t.Run(mode, func(t *testing.T) {
			f := newOrgPermissionFixture(t)
			target := f.member(t, domain.OrgRoleMember)
			custom := f.role(t, "custom")
			before, err := f.s.GetMemberRole(t.Context(), api.GetOrgMemberRoleInput{Actor: f.owner, UserID: target.UserID})
			if err != nil || before.AssignmentRevision != 0 {
				t.Fatalf("implicit assignment: %+v %v", before, err)
			}
			platform := f.account(t)
			if _, err := f.db.ExecContext(t.Context(), `UPDATE users SET role='admin' WHERE id=$1`, platform.UserID); err != nil {
				t.Fatal(err)
			}
			if mode == "disabled" || mode == "admin-disabled" {
				f.org.orgPermissions = nil
			}
			update := func(role domain.OrgRole) error {
				if mode == "admin" || mode == "admin-disabled" {
					return f.org.AdminUpdateMemberRole(t.Context(), api.AdminUpdateMemberRoleInput{OrgID: f.owner.OrgID, ActorID: platform.UserID, UserID: target.UserID, NewRole: role})
				}
				return f.org.UpdateMemberRole(t.Context(), api.UpdateMemberRoleInput{OrgID: f.owner.OrgID, ActorID: f.owner.UserID, UserID: target.UserID, NewRole: role})
			}
			assertAssignment := func(base domain.OrgRole, revision uint64) {
				t.Helper()
				got, err := f.s.GetMemberRole(t.Context(), api.GetOrgMemberRoleInput{Actor: f.owner, UserID: target.UserID})
				if err != nil || got.Role.SystemKey == nil || *got.Role.SystemKey != string(base) || got.AssignmentRevision != revision {
					t.Fatalf("assignment: %+v %v; want %s revision %d", got, err, base, revision)
				}
				member, err := f.org.orgs.GetMembership(t.Context(), target.OrgID, target.UserID)
				if err != nil || member.Role != base {
					t.Fatalf("classification: %+v %v; want %s", member, err, base)
				}
				wantOwners, wantUserOwners := 1, 0
				if base == domain.OrgRoleOwner {
					wantOwners, wantUserOwners = 2, 1
				}
				org, err := f.org.orgs.GetByID(t.Context(), target.OrgID)
				if err != nil || org.OwnerCount != wantOwners {
					t.Fatalf("org owner count: %+v %v; want %d", org, err, wantOwners)
				}
				var userOwners int
				if err := f.db.QueryRowContext(t.Context(), `SELECT org_owner_count FROM users WHERE id=$1`, target.UserID).Scan(&userOwners); err != nil || userOwners != wantUserOwners {
					t.Fatalf("user owner count: %d %v; want %d", userOwners, err, wantUserOwners)
				}
			}
			capture := &orgAuditCapture{}
			f.org.audit = capture
			if err := update(domain.OrgRoleMember); err != nil {
				t.Fatal(err)
			}
			assertAssignment(domain.OrgRoleMember, 0)
			if len(capture.events) != 0 {
				t.Fatalf("implicit no-op recorded audit: %+v", capture.events)
			}
			f.org.audit = rejectingOrgAudit{}
			if err := update(domain.OrgRoleOwner); err == nil {
				t.Fatal("expected audit failure")
			}
			assertAssignment(domain.OrgRoleMember, 0)
			f.org.audit = capture
			if err := update(domain.OrgRoleOwner); err != nil {
				t.Fatal(err)
			}
			assertAssignment(domain.OrgRoleOwner, 1)
			if len(capture.events) != 1 || capture.events[0].Metadata["oldRoleId"] != before.Role.ID || capture.events[0].Metadata["assignmentRevision"] != uint64(1) {
				t.Fatalf("implicit assignment audit: %+v", capture.events)
			}
			_, err = f.s.SetMemberRole(t.Context(), api.SetOrgMemberRoleInput{Actor: f.owner, UserID: target.UserID, RoleID: custom.ID, ExpectedRoleRevision: custom.Revision, ExpectedAssignmentRevision: before.AssignmentRevision})
			if !errors.Is(err, domain.ErrOrgAuthorizationConflict) {
				t.Fatalf("stale assignment overwrote ownership: %v", err)
			}
			assertAssignment(domain.OrgRoleOwner, 1)
			if err := update(domain.OrgRoleOwner); err != nil {
				t.Fatal(err)
			}
			assertAssignment(domain.OrgRoleOwner, 1)
			if err := update(domain.OrgRoleAdmin); err != nil {
				t.Fatal(err)
			}
			assertAssignment(domain.OrgRoleAdmin, 2)
			if len(capture.events) != 2 {
				t.Fatalf("no-op or stale write recorded audit: %+v", capture.events)
			}
		})
	}
}

func TestOrgPermissionsUninitializedFixedRoleChange(t *testing.T) {
	for _, retainStore := range []bool{false, true} {
		name := "feature-disabled"
		if retainStore {
			name = "retained-store"
		}
		t.Run(name, func(t *testing.T) {
			f := newOrgPermissionFixture(t)
			f.org.orgPermissions = nil
			if !retainStore {
				f.org.roleAssignments = nil
			}
			owner := f.account(t)
			org, err := f.org.CreateOrg(t.Context(), api.CreateOrgInput{OwnerID: owner.UserID, Name: "Legacy", Slug: owner.UserID})
			if err != nil {
				t.Fatal(err)
			}
			target := f.account(t)
			if err := f.org.AddMember(t.Context(), api.AddMemberInput{OrgID: org.ID, ActorID: owner.UserID, UserID: target.UserID, Role: domain.OrgRoleMember}); err != nil {
				t.Fatal(err)
			}
			if err := f.org.UpdateMemberRole(t.Context(), api.UpdateMemberRoleInput{OrgID: org.ID, ActorID: owner.UserID, UserID: target.UserID, NewRole: domain.OrgRoleOwner}); err != nil {
				t.Fatal(err)
			}
			member, err := f.org.orgs.GetMembership(t.Context(), org.ID, target.UserID)
			if err != nil || member.Role != domain.OrgRoleOwner {
				t.Fatalf("fixed-role change: %+v %v", member, err)
			}
			role, revision, err := f.repo.MemberRole(t.Context(), org.ID, target.UserID)
			if err != nil || role != nil || revision != 0 {
				t.Fatalf("uninitialized org created assignment: %+v revision=%d error=%v", role, revision, err)
			}
		})
	}
}
