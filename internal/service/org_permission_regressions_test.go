package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"github.com/nazimdjebloun/go-auth/port"
)

type orgTargetReadFailure struct {
	port.UserRepository
	userID string
	err    error
}

func (r orgTargetReadFailure) GetByID(ctx context.Context, id string) (*domain.User, error) {
	if id == r.userID {
		return nil, r.err
	}
	return r.UserRepository.GetByID(ctx, id)
}

func TestOrgPermissionsTargetInspectionPreservesFailures(t *testing.T) {
	f := newOrgPermissionFixture(t)
	member := f.member(t, domain.OrgRoleMember)
	cause := errors.New("target account read failed")
	f.s.users = orgTargetReadFailure{UserRepository: f.s.users, userID: member.UserID, err: cause}
	_, err := f.s.ListEffectivePermissions(t.Context(), api.ListOrgEffectivePermissionsInput{
		Actor: f.owner, UserID: member.UserID,
	})
	if !errors.Is(err, cause) {
		t.Fatalf("target read failure became an authorization decision: %v", err)
	}
}

func TestOrgPermissionsTargetInspectionRejectsIneligibleActor(t *testing.T) {
	f := newOrgPermissionFixture(t)
	member := f.member(t, domain.OrgRoleMember)
	if _, err := f.db.ExecContext(t.Context(), `UPDATE users SET is_banned=true WHERE id=$1`, f.owner.UserID); err != nil {
		t.Fatal(err)
	}
	_, err := f.s.ListEffectivePermissions(t.Context(), api.ListOrgEffectivePermissionsInput{
		Actor: f.owner, UserID: member.UserID,
	})
	if !errors.Is(err, domain.ErrOrgForbidden) {
		t.Fatalf("banned caller inspected target: %v", err)
	}
}

func TestOrgPermissionsMismatchedTargetHasNoEffectiveAccess(t *testing.T) {
	f := newOrgPermissionFixture(t)
	member := f.member(t, domain.OrgRoleMember)
	owner, err := f.repo.RoleBySlug(t.Context(), f.owner.OrgID, "owner")
	if err != nil {
		t.Fatal(err)
	}
	f.assign(t, member, owner)
	// Simulate inconsistent persisted data: inspection must agree with the
	// authoritative check rather than report owner access from the role alone.
	if _, err := f.db.ExecContext(t.Context(),
		`UPDATE organization_members SET role='member' WHERE org_id=$1 AND user_id=$2`, member.OrgID, member.UserID,
	); err != nil {
		t.Fatal(err)
	}
	f.allowed(t, member, "goauth.org.organization.read", false)
	access, err := f.s.ListEffectivePermissions(t.Context(), api.ListOrgEffectivePermissionsInput{
		Actor: f.owner, UserID: member.UserID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if access.IsFullAccess || len(access.PermissionKeys) != 0 || access.Role.ID != owner.ID {
		t.Fatalf("mismatched classification gained effective access: %+v", access)
	}
}

func TestOrgPermissionsDisabledRoleResetAuditRollback(t *testing.T) {
	for _, admin := range []bool{false, true} {
		for _, next := range []domain.OrgRole{domain.OrgRoleMember, domain.OrgRoleOwner} {
			name := string(next)
			if admin {
				name = "admin/" + name
			}
			t.Run(name, func(t *testing.T) {
				f := newOrgPermissionFixture(t)
				member := f.member(t, domain.OrgRoleMember)
				role := f.role(t, "custom")
				f.assign(t, member, role)
				if admin {
					if _, err := f.db.ExecContext(t.Context(), `UPDATE users SET role='admin' WHERE id=$1`, f.owner.UserID); err != nil {
						t.Fatal(err)
					}
				}
				legacy := NewOrgService(
					f.org.orgs, f.s.users, sqlstore.NewSessionRepository(f.db), f.db,
					OrgServiceConfig{RoleAssignments: f.repo, Audit: rejectingOrgAudit{}},
				)
				update := func() error {
					if admin {
						return legacy.AdminUpdateMemberRole(t.Context(), api.AdminUpdateMemberRoleInput{
							OrgID: f.owner.OrgID, ActorID: f.owner.UserID, UserID: member.UserID, NewRole: next,
						})
					}
					return legacy.UpdateMemberRole(t.Context(), api.UpdateMemberRoleInput{
						OrgID: f.owner.OrgID, ActorID: f.owner.UserID, UserID: member.UserID, NewRole: next,
					})
				}
				if err := update(); err == nil {
					t.Fatal("failed audit did not block fixed-role change")
				}
				assignment, revision, err := f.repo.MemberRole(t.Context(), f.owner.OrgID, member.UserID)
				if err != nil || assignment.ID != role.ID || revision != 1 {
					t.Fatalf("failed audit changed assignment: %+v revision=%d error=%v", assignment, revision, err)
				}
				membership, err := f.org.orgs.GetMembership(t.Context(), f.owner.OrgID, member.UserID)
				if err != nil || membership.Role != domain.OrgRoleMember {
					t.Fatalf("failed audit changed classification: %+v error=%v", membership, err)
				}
				org, err := f.org.orgs.GetByID(t.Context(), f.owner.OrgID)
				if err != nil || org.OwnerCount != 1 {
					t.Fatalf("failed audit changed owner count: %+v error=%v", org, err)
				}
				capture := &orgAuditCapture{}
				legacy.audit = capture
				if err := update(); err != nil {
					t.Fatal(err)
				}
				assignment, revision, err = f.repo.MemberRole(t.Context(), f.owner.OrgID, member.UserID)
				if err != nil || assignment.Slug != string(next) || revision != 2 {
					t.Fatalf("fixed-role change retained custom assignment: %+v revision=%d error=%v", assignment, revision, err)
				}
				if len(capture.events) != 1 || capture.events[0].Metadata["oldRoleId"] != role.ID {
					t.Fatalf("fixed-role change lost audit metadata: %+v", capture.events)
				}
			})
		}
	}
}

func TestOrgPermissionsConcurrentDisabledFixedRoleAndGranularAssignment(t *testing.T) {
	f := newOrgPermissionFixture(t)
	member := f.member(t, domain.OrgRoleMember)
	first := f.role(t, "first")
	second := f.role(t, "second")
	f.assign(t, member, first)
	legacy := NewOrgService(
		f.org.orgs, f.s.users, sqlstore.NewSessionRepository(f.db), f.db,
		OrgServiceConfig{RoleAssignments: f.repo},
	)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	start := make(chan struct{})
	fixedResult := make(chan error, 1)
	granularResult := make(chan error, 1)
	go func() {
		<-start
		fixedResult <- legacy.UpdateMemberRole(ctx, api.UpdateMemberRoleInput{
			OrgID: f.owner.OrgID, ActorID: f.owner.UserID, UserID: member.UserID, NewRole: domain.OrgRoleOwner,
		})
	}()
	go func() {
		<-start
		_, err := f.s.SetMemberRole(ctx, api.SetOrgMemberRoleInput{
			Actor: f.owner, UserID: member.UserID, RoleID: second.ID,
			ExpectedRoleRevision: second.Revision, ExpectedAssignmentRevision: 1,
		})
		granularResult <- err
	}()
	close(start)
	if err := <-fixedResult; err != nil {
		t.Fatal("fixed-role write:", err)
	}
	if err := <-granularResult; err != nil && !errors.Is(err, domain.ErrOrgAuthorizationConflict) {
		t.Fatal("granular assignment:", err)
	}
	access, err := f.s.ListEffectivePermissions(t.Context(), api.ListOrgEffectivePermissionsInput{Actor: member})
	if err != nil || !access.IsFullAccess || access.Role.Slug != "owner" {
		t.Fatalf("concurrent writes broke owner authorization: %+v error=%v", access, err)
	}
}

func TestMySQL_OrgPermissionsFixedRoleResetUsesCurrentMembership(t *testing.T) {
	if testdb.Selected() != "mysql" {
		t.Skip("requires selected MySQL backend")
	}
	f := newOrgPermissionFixture(t)
	f.db.SetMaxOpenConns(4)
	member := f.member(t, domain.OrgRoleMember)
	role := f.role(t, "custom")
	f.assign(t, member, role)
	legacy := NewOrgService(
		f.org.orgs, f.s.users, sqlstore.NewSessionRepository(f.db), f.db,
		OrgServiceConfig{RoleAssignments: f.repo},
	)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	err := f.db.WithTx(ctx, func(txCtx context.Context) error {
		var isolation string
		if err := f.db.QueryRowContext(txCtx, "SELECT @@transaction_isolation").Scan(&isolation); err != nil {
			return err
		}
		if isolation != "REPEATABLE-READ" {
			t.Fatalf("test requires REPEATABLE-READ, got %s", isolation)
		}
		// Establish an older snapshot, then promote through another connection.
		if _, err := f.org.orgs.GetMembership(txCtx, f.owner.OrgID, member.UserID); err != nil {
			return err
		}
		if err := f.org.UpdateMemberRole(ctx, api.UpdateMemberRoleInput{
			OrgID: f.owner.OrgID, ActorID: f.owner.UserID, UserID: member.UserID, NewRole: domain.OrgRoleOwner,
		}); err != nil {
			return err
		}
		stale, err := f.org.orgs.GetMembership(txCtx, f.owner.OrgID, member.UserID)
		if err != nil {
			return err
		}
		if stale.Role != domain.OrgRoleMember {
			t.Fatalf("test did not retain old membership: %+v", stale)
		}
		return legacy.UpdateMemberRole(txCtx, api.UpdateMemberRoleInput{
			OrgID: f.owner.OrgID, ActorID: f.owner.UserID, UserID: member.UserID, NewRole: domain.OrgRoleMember,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	membership, err := f.org.orgs.GetMembership(ctx, f.owner.OrgID, member.UserID)
	if err != nil || membership.Role != domain.OrgRoleMember {
		t.Fatalf("stale snapshot prevented demotion: %+v error=%v", membership, err)
	}
	org, err := f.org.orgs.GetByID(ctx, f.owner.OrgID)
	if err != nil || org.OwnerCount != 1 {
		t.Fatalf("stale snapshot broke owner count: %+v error=%v", org, err)
	}
	assignment, revision, err := f.repo.MemberRole(ctx, f.owner.OrgID, member.UserID)
	if err != nil || assignment.Slug != "member" || revision != 3 {
		t.Fatalf("stale snapshot broke assignment: %+v revision=%d error=%v", assignment, revision, err)
	}
}
