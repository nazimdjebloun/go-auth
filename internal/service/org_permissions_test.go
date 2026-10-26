package service

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/token"
)

type orgPermissionFixture struct {
	s       *OrgPermissionsService
	org     *OrgService
	invites *OrgInviteService
	db      *sqlstore.DB
	repo    *sqlstore.OrgPermissionsRepository
	owner   api.OrgPermissionActor
}

func newOrgPermissionFixture(t *testing.T) orgPermissionFixture {
	t.Helper()
	raw := testdb.OpenSelected(t)
	testdb.Apply(t, raw)
	db := sqlstore.NewDB(raw, testdb.Driver(raw))
	users := sqlstore.NewUserRepository(db)
	orgs := sqlstore.NewOrgRepository(db).WithOrgPermissions()
	repo := sqlstore.NewOrgPermissionsRepository(db)
	sessions := sqlstore.NewSessionRepository(db)
	sess := NewSessionService(db, sessions, token.New(), DefaultSessionConfig())
	s := NewOrgPermissionsService(users, orgs, sessions, sess, repo, repo, repo, repo, OrgPermissionsServiceConfig{})
	org := NewOrgService(orgs, users, sessions, db, OrgServiceConfig{OrgPermissions: s})
	s.AttachOrgService(org)
	invites := NewOrgInviteService(sqlstore.NewOrgInviteRepository(db), orgs, users, db, token.New(), &testutil.MockMailer{}, OrgInviteServiceConfig{OrgPermissions: s, InviteTTL: time.Hour})
	f := orgPermissionFixture{s: s, org: org, invites: invites, db: db, repo: repo}
	owner := f.account(t)
	organization, err := org.CreateOrg(t.Context(), api.CreateOrgInput{OwnerID: owner.UserID, Name: "Organization", Slug: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	f.owner = orgActor(organization.ID, owner.UserID, "")
	return f
}

func (f orgPermissionFixture) account(t *testing.T) api.OrgPermissionActor {
	t.Helper()
	id := uuid.NewString()
	now := time.Now().UTC()
	if err := f.s.users.Create(t.Context(), &domain.User{ID: id, Email: id + "@example.com", Role: domain.RoleUser, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	return orgActor(f.owner.OrgID, id, "")
}
func (f orgPermissionFixture) member(t *testing.T, base domain.OrgRole) api.OrgPermissionActor {
	t.Helper()
	actor := f.account(t)
	if err := f.org.AddMember(t.Context(), api.AddMemberInput{OrgID: f.owner.OrgID, ActorID: f.owner.UserID, UserID: actor.UserID, Role: base}); err != nil {
		t.Fatal(err)
	}
	return actor
}
func (f orgPermissionFixture) install(t *testing.T, keys ...string) {
	t.Helper()
	if _, err := f.s.UpdateLibraryPermissions(t.Context(), api.UpdateOrgLibraryPermissionsInput{Actor: f.owner, Create: keys}); err != nil {
		t.Fatal(err)
	}
}
func (f orgPermissionFixture) permission(t *testing.T, key string) *domain.OrgPermission {
	t.Helper()
	p, err := f.s.CreatePermission(t.Context(), api.CreateOrgPermissionInput{Actor: f.owner, Key: key, Name: key})
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func (f orgPermissionFixture) role(t *testing.T, slug string, keys ...string) *domain.OrgPermissionRole {
	t.Helper()
	r, err := f.s.CreateRole(t.Context(), api.CreateOrgRoleInput{Actor: f.owner, Slug: slug, Name: slug, PermissionKeys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func (f orgPermissionFixture) assign(t *testing.T, actor api.OrgPermissionActor, role *domain.OrgPermissionRole) *api.OrgMemberRoleResult {
	t.Helper()
	_, rev, err := f.repo.MemberRole(t.Context(), actor.OrgID, actor.UserID)
	if err != nil {
		t.Fatal(err)
	}
	r, err := f.s.SetMemberRole(t.Context(), api.SetOrgMemberRoleInput{Actor: f.owner, UserID: actor.UserID, RoleID: role.ID, ExpectedRoleRevision: role.Revision, ExpectedAssignmentRevision: rev})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func (f orgPermissionFixture) allowed(t *testing.T, actor api.OrgPermissionActor, key string, want bool) {
	t.Helper()
	d, err := f.s.CheckPermission(t.Context(), api.CheckOrgPermissionInput{Actor: actor, PermissionKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed != want {
		t.Fatalf("%s allowed=%v want %v", key, d.Allowed, want)
	}
}

func TestOrgPermissionsRolesAndLiveRevocation(t *testing.T) {
	f := newOrgPermissionFixture(t)
	member := f.member(t, domain.OrgRoleMember)
	admin := f.member(t, domain.OrgRoleAdmin)
	f.allowed(t, admin, "goauth.org.invites.create", true)
	f.allowed(t, admin, "goauth.org.organization.delete", false)
	f.allowed(t, member, "goauth.org.members.read", true)
	f.install(t, "goauth.org.organization.update")
	p := f.permission(t, "org.projects.create")
	r := f.role(t, "operations", "org.projects.create", "goauth.org.organization.update")
	f.assign(t, member, r)
	f.allowed(t, member, "org.projects.create", true)
	f.allowed(t, member, "goauth.org.members.read", false)
	f.allowed(t, admin, "org.projects.create", false)
	f.allowed(t, f.owner, "org.projects.create", true)
	f.allowed(t, f.owner, "goauth.org.unknown.action", false)
	name := "Changed"
	if _, err := f.org.UpdateOrg(t.Context(), api.UpdateOrgInput{OrgID: f.owner.OrgID, ActorID: member.UserID, Name: &name}); err != nil {
		t.Fatal("custom role cannot perform granted org operation:", err)
	}
	if _, err := f.org.ListMembers(t.Context(), api.ListMembersInput{OrgID: f.owner.OrgID, ActorID: member.UserID}); !errors.Is(err, domain.ErrOrgForbidden) {
		t.Fatalf("ungranted service call: %v", err)
	}
	disabled := false
	if _, err := f.s.UpdatePermission(t.Context(), api.UpdateOrgPermissionInput{Actor: f.owner, PermissionID: p.ID, ExpectedRevision: p.Revision, IsEnabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	f.allowed(t, member, "org.projects.create", false)
	f.allowed(t, f.owner, "org.projects.create", false)
	if _, err := f.s.UpdateLibraryPermissions(t.Context(), api.UpdateOrgLibraryPermissionsInput{Actor: f.owner, Delete: []string{"goauth.org.organization.update"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.org.UpdateOrg(t.Context(), api.UpdateOrgInput{OrgID: f.owner.OrgID, ActorID: member.UserID, Name: &name}); !errors.Is(err, domain.ErrOrgForbidden) {
		t.Fatalf("revoked grant survived: %v", err)
	}
	access, err := f.s.ListEffectivePermissions(t.Context(), api.ListOrgEffectivePermissionsInput{Actor: f.owner})
	if err != nil || !access.IsFullAccess || slices.Contains(access.PermissionKeys, p.Key) {
		t.Fatalf("owner access: %+v %v", access, err)
	}
}

func TestOrgPermissionsDelegationAndOwnerInvariants(t *testing.T) {
	f := newOrgPermissionFixture(t)
	actor := f.member(t, domain.OrgRoleMember)
	target := f.member(t, domain.OrgRoleMember)
	f.install(t, "goauth.org.roles.create", "goauth.org.roles.update", "goauth.org.roles.assign")
	f.permission(t, "org.invoices.read")
	f.permission(t, "org.invoices.delete")
	role := f.role(t, "delegator", "goauth.org.roles.create", "goauth.org.roles.update", "goauth.org.roles.assign", "org.invoices.read")
	f.assign(t, actor, role)
	if _, err := f.s.CreateRole(t.Context(), api.CreateOrgRoleInput{Actor: actor, Slug: "too-powerful", Name: "Too powerful", PermissionKeys: []string{"org.invoices.delete"}}); !errors.Is(err, domain.ErrOrgForbidden) {
		t.Fatalf("overbroad grant: %v", err)
	}
	if _, err := f.s.SetRolePermissions(t.Context(), api.SetOrgRolePermissionsInput{Actor: actor, RoleID: role.ID, ExpectedRevision: role.Revision}); !errors.Is(err, domain.ErrOrgForbidden) {
		t.Fatalf("own role mutation: %v", err)
	}
	ownerRole, err := f.repo.RoleBySlug(t.Context(), f.owner.OrgID, "owner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.SetMemberRole(t.Context(), api.SetOrgMemberRoleInput{Actor: actor, UserID: target.UserID, RoleID: ownerRole.ID, ExpectedRoleRevision: 1}); !errors.Is(err, domain.ErrOrgForbidden) {
		t.Fatalf("owner escalation: %v", err)
	}
	if _, err = f.s.UpdateRole(t.Context(), api.UpdateOrgRoleInput{Actor: f.owner, RoleID: ownerRole.ID, ExpectedRevision: 1}); !errors.Is(err, domain.ErrProtectedOrgRole) {
		t.Fatalf("protected owner edit: %v", err)
	}
	memberRole, err := f.repo.RoleBySlug(t.Context(), f.owner.OrgID, "member")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.SetMemberRole(t.Context(), api.SetOrgMemberRoleInput{Actor: f.owner, UserID: f.owner.UserID, RoleID: memberRole.ID, ExpectedRoleRevision: 1}); !errors.Is(err, domain.ErrCannotRemoveLastOwner) {
		t.Fatalf("last owner demotion: %v", err)
	}
	if err = f.org.UpdateMemberRole(t.Context(), api.UpdateMemberRoleInput{OrgID: f.owner.OrgID, ActorID: actor.UserID, UserID: target.UserID, NewRole: domain.OrgRoleAdmin}); !errors.Is(err, domain.ErrOrgForbidden) {
		t.Fatalf("legacy assignment bypass: %v", err)
	}
	if err = f.org.UpdateMemberRole(t.Context(), api.UpdateMemberRoleInput{OrgID: f.owner.OrgID, ActorID: f.owner.UserID, UserID: actor.UserID, NewRole: domain.OrgRoleMember}); err != nil {
		t.Fatal(err)
	}
	f.allowed(t, actor, "org.invoices.read", false)
	f.allowed(t, actor, "goauth.org.members.read", true)
}

func TestOrgPermissionsScopeAndDatabaseConstraints(t *testing.T) {
	f := newOrgPermissionFixture(t)
	member := f.member(t, domain.OrgRoleMember)
	f.permission(t, "org.projects.read")
	role := f.role(t, "reader", "org.projects.read")
	second, err := f.org.CreateOrg(t.Context(), api.CreateOrgInput{OwnerID: f.owner.UserID, Name: "Second", Slug: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	other := f.owner
	other.OrgID = second.ID
	if _, err = f.s.SetMemberRole(t.Context(), api.SetOrgMemberRoleInput{Actor: other, UserID: member.UserID, RoleID: role.ID, ExpectedRoleRevision: 1}); !errors.Is(err, domain.ErrOrgMemberNotFound) {
		t.Fatalf("cross org target: %v", err)
	}
	if err = f.org.AddMember(t.Context(), api.AddMemberInput{OrgID: second.ID, ActorID: other.UserID, UserID: member.UserID, Role: domain.OrgRoleMember}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.SetMemberRole(t.Context(), api.SetOrgMemberRoleInput{Actor: other, UserID: member.UserID, RoleID: role.ID, ExpectedRoleRevision: 1}); !errors.Is(err, domain.ErrOrgRoleNotFound) {
		t.Fatalf("cross org role: %v", err)
	}
	if _, err = f.db.ExecContext(t.Context(), `INSERT INTO org_member_roles(org_id,user_id,role_id,revision) VALUES ($1,$2,$3,1)`, second.ID, member.UserID, role.ID); err == nil {
		t.Fatal("SQL accepted cross-org membership role")
	}
	p, err := f.s.CreatePermission(t.Context(), api.CreateOrgPermissionInput{Actor: other, Key: "org.projects.read", Name: "Same key, different org"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.ExecContext(t.Context(), `INSERT INTO org_role_permissions(org_id,role_id,permission_id,created_at) VALUES ($1,$2,$3,$4)`, f.owner.OrgID, role.ID, p.ID, time.Now().UTC()); err == nil {
		t.Fatal("SQL accepted cross-org permission grant")
	}
	platform := f.account(t)
	platform.OrgID = f.owner.OrgID
	if _, err = f.db.ExecContext(t.Context(), `UPDATE users SET role='admin' WHERE id=$1`, platform.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.CheckPermission(t.Context(), api.CheckOrgPermissionInput{Actor: platform, PermissionKey: "org.projects.read"}); !errors.Is(err, domain.ErrOrgMemberNotFound) {
		t.Fatalf("platform role bypassed membership: %v", err)
	}
	if err = f.org.DeleteOrg(t.Context(), api.DeleteOrgInput{OrgID: f.owner.OrgID, ActorID: f.owner.UserID}); err != nil {
		t.Fatal("org delete with role references:", err)
	}
	testdb.AssertForeignKeyIntegrity(t, f.db.DB)
}

func TestOrgPermissionsInviteRevisionAndClaimRollback(t *testing.T) {
	f := newOrgPermissionFixture(t)
	account := f.account(t)
	f.permission(t, "org.invoices.read")
	role := f.role(t, "accountant", "org.invoices.read")
	create := func() *domain.OrgInvite {
		t.Helper()
		invite, err := f.invites.CreateOrgInvite(t.Context(), api.CreateOrgInviteInput{OrgID: f.owner.OrgID, InvitedBy: f.owner.UserID, Email: account.UserID + "@example.com", OrgRoleID: role.ID, ExpectedRoleRevision: role.Revision})
		if err != nil {
			t.Fatal(err)
		}
		return invite
	}
	invite := create()
	name := "Renamed"
	updated, err := f.s.UpdateRole(t.Context(), api.UpdateOrgRoleInput{Actor: f.owner, RoleID: role.ID, ExpectedRevision: role.Revision, Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.invites.AcceptInvite(t.Context(), api.AcceptInviteInput{UserID: account.UserID, RawCode: invite.RawCode}); !errors.Is(err, domain.ErrOrgInviteRoleChanged) {
		t.Fatalf("stale invite role: %v", err)
	}
	if existing, err := f.invites.orgInvites.GetByID(t.Context(), invite.ID); err != nil || existing == nil {
		t.Fatalf("failed acceptance consumed invite: %v", err)
	}
	if member, err := f.org.orgs.GetMembership(t.Context(), f.owner.OrgID, account.UserID); err != nil || member != nil {
		t.Fatalf("failed acceptance added member: %+v %v", member, err)
	}
	if err = f.invites.DeleteOrgInvite(t.Context(), api.DeleteOrgInviteInput{OrgID: f.owner.OrgID, ActorID: f.owner.UserID, InviteID: invite.ID}); err != nil {
		t.Fatal(err)
	}
	role = updated
	invite = create()
	if err = f.invites.AcceptInvite(t.Context(), api.AcceptInviteInput{UserID: account.UserID, RawCode: invite.RawCode}); err != nil {
		t.Fatal(err)
	}
	f.allowed(t, account, "org.invoices.read", true)
	if err = f.invites.AcceptInvite(t.Context(), api.AcceptInviteInput{UserID: account.UserID, RawCode: invite.RawCode}); !errors.Is(err, domain.ErrOrgInviteExpired) {
		t.Fatalf("invite reused: %v", err)
	}
}

type rejectingOrgAudit struct{}

func (rejectingOrgAudit) Record(context.Context, audit.Event) error {
	return errors.New("audit unavailable")
}

func TestOrgPermissionsAuditRollbackAndConcurrentAssignments(t *testing.T) {
	f := newOrgPermissionFixture(t)
	member := f.member(t, domain.OrgRoleMember)
	f.s.config.Audit = rejectingOrgAudit{}
	if _, err := f.s.CreatePermission(t.Context(), api.CreateOrgPermissionInput{Actor: f.owner, Key: "org.rollback.read", Name: "Rollback"}); err == nil {
		t.Fatal("expected audit failure")
	}
	if p, err := f.repo.PermissionByKey(t.Context(), f.owner.OrgID, "org.rollback.read"); err != nil || p != nil {
		t.Fatalf("audit failure committed permission: %+v %v", p, err)
	}
	f.s.config.Audit = nil
	first := f.role(t, "first")
	second := f.role(t, "second")
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, role := range []*domain.OrgPermissionRole{first, second} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.s.SetMemberRole(t.Context(), api.SetOrgMemberRoleInput{Actor: f.owner, UserID: member.UserID, RoleID: role.ID, ExpectedRoleRevision: 1})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success, conflicts := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, domain.ErrOrgAuthorizationConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflicts != 1 {
		t.Fatalf("assignment results: success=%d conflicts=%d", success, conflicts)
	}
}

func TestOrgPermissionsLegacyAssignmentAndResetAudit(t *testing.T) {
	f := newOrgPermissionFixture(t)
	actor := f.member(t, domain.OrgRoleMember)
	admin := f.member(t, domain.OrgRoleAdmin)
	f.install(t, "goauth.org.roles.assign", "goauth.org.members.read", "goauth.org.organization.read")
	delegator := f.role(t, "limited-manager", "goauth.org.roles.assign", "goauth.org.members.read", "goauth.org.organization.read")
	f.assign(t, actor, delegator)
	err := f.org.UpdateMemberRole(t.Context(), api.UpdateMemberRoleInput{OrgID: f.owner.OrgID, ActorID: actor.UserID, UserID: admin.UserID, NewRole: domain.OrgRoleMember})
	if !errors.Is(err, domain.ErrOrgForbidden) {
		t.Fatalf("implicit admin demotion bypassed old-role bounds: %v", err)
	}
	f.org.audit = rejectingOrgAudit{}
	err = f.org.UpdateMemberRole(t.Context(), api.UpdateMemberRoleInput{OrgID: f.owner.OrgID, ActorID: f.owner.UserID, UserID: actor.UserID, NewRole: domain.OrgRoleMember})
	if err == nil {
		t.Fatal("same-classification reset skipped fail-closed audit")
	}
	f.allowed(t, actor, "goauth.org.roles.assign", true)
	log := &orgAuditCapture{}
	f.org.audit = log
	if err = f.org.UpdateMemberRole(t.Context(), api.UpdateMemberRoleInput{OrgID: f.owner.OrgID, ActorID: f.owner.UserID, UserID: actor.UserID, NewRole: domain.OrgRoleMember}); err != nil {
		t.Fatal(err)
	}
	if len(log.events) != 1 || log.events[0].Metadata["oldRoleId"] != delegator.ID || log.events[0].ActorID == nil || *log.events[0].ActorID != f.owner.UserID {
		t.Fatalf("reset audit: %+v", log.events)
	}
	f.allowed(t, actor, "goauth.org.roles.assign", false)
}

type orgAuditCapture struct{ events []audit.Event }

func (c *orgAuditCapture) Record(_ context.Context, event audit.Event) error {
	c.events = append(c.events, event)
	return nil
}

type orgBlockingMailer struct {
	entered chan struct{}
	release chan struct{}
}

func (m *orgBlockingMailer) Send(ctx context.Context, _, _, _, _ string) error {
	close(m.entered)
	select {
	case <-m.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestOrgPermissionsResendReleasesAuthorizationLocks(t *testing.T) {
	f := newOrgPermissionFixture(t)
	account := f.account(t)
	invite, err := f.invites.CreateOrgInvite(t.Context(), api.CreateOrgInviteInput{OrgID: f.owner.OrgID, InvitedBy: f.owner.UserID, Email: account.UserID + "@example.com", Role: domain.OrgRoleMember})
	if err != nil {
		t.Fatal(err)
	}
	mailer := &orgBlockingMailer{entered: make(chan struct{}), release: make(chan struct{})}
	f.invites.mailer = mailer
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- f.invites.ResendOrgInviteEmail(ctx, api.ResendOrgInviteEmailInput{OrgID: f.owner.OrgID, ActorID: f.owner.UserID, InviteID: invite.ID})
	}()
	select {
	case <-mailer.entered:
	case <-ctx.Done():
		t.Fatal("resend never reached delivery")
	}
	_, err = f.s.CreatePermission(ctx, api.CreateOrgPermissionInput{Actor: f.owner, Key: "org.during.delivery", Name: "During delivery"})
	close(mailer.release)
	if err != nil {
		t.Fatalf("email delivery retained authorization locks: %v", err)
	}
	if err = <-result; err != nil {
		t.Fatal(err)
	}
}

func TestOrgPermissionsCRUDAndOwnershipLifecycle(t *testing.T) {
	f := newOrgPermissionFixture(t)
	member := f.member(t, domain.OrgRoleMember)
	p := f.permission(t, "org.projects.read")
	role := f.role(t, "reader", p.Key)
	if err := f.s.DeletePermission(t.Context(), api.DeleteOrgPermissionInput{Actor: f.owner, PermissionID: p.ID, ExpectedRevision: 1}); !errors.Is(err, domain.ErrOrgPermissionInUse) {
		t.Fatalf("referenced definition deleted: %v", err)
	}
	if _, err := f.s.UpdateRole(t.Context(), api.UpdateOrgRoleInput{Actor: f.owner, RoleID: role.ID, ExpectedRevision: 99}); !errors.Is(err, domain.ErrOrgAuthorizationConflict) {
		t.Fatalf("stale role update: %v", err)
	}
	f.assign(t, member, role)
	if err := f.s.DeleteRole(t.Context(), api.DeleteOrgRoleInput{Actor: f.owner, RoleID: role.ID, ExpectedRevision: 1}); !errors.Is(err, domain.ErrOrgRoleInUse) {
		t.Fatalf("assigned role deleted: %v", err)
	}
	ownerRole, err := f.repo.RoleBySlug(t.Context(), f.owner.OrgID, "owner")
	if err != nil {
		t.Fatal(err)
	}
	f.assign(t, member, ownerRole)
	originalOwner := f.owner
	f.assign(t, originalOwner, role)
	f.owner = member
	org, err := f.org.orgs.GetByID(t.Context(), f.owner.OrgID)
	if err != nil || org.OwnerCount != 1 || org.MemberCount != 2 {
		t.Fatalf("ownership counters: %+v %v", org, err)
	}
	user, err := f.s.users.GetByID(t.Context(), originalOwner.UserID)
	if err != nil || user.OrgOwnerCount != 0 {
		t.Fatalf("demoted owner count: %+v %v", user, err)
	}
	if err = f.org.RemoveMember(t.Context(), api.RemoveMemberInput{OrgID: f.owner.OrgID, ActorID: f.owner.UserID, UserID: originalOwner.UserID}); err != nil {
		t.Fatal(err)
	}
	if current, _, err := f.repo.MemberRole(t.Context(), f.owner.OrgID, originalOwner.UserID); err != nil || current != nil {
		t.Fatalf("removed membership retained assignment: %+v %v", current, err)
	}
	if err = f.s.DeleteRole(t.Context(), api.DeleteOrgRoleInput{Actor: f.owner, RoleID: role.ID, ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}
	if err = f.s.DeletePermission(t.Context(), api.DeleteOrgPermissionInput{Actor: f.owner, PermissionID: p.ID, ExpectedRevision: 1}); err != nil {
		t.Fatal(err)
	}
	if err = f.org.DeleteOrg(t.Context(), api.DeleteOrgInput{OrgID: f.owner.OrgID, ActorID: f.owner.UserID}); err != nil {
		t.Fatal(err)
	}
	testdb.AssertForeignKeyIntegrity(t, f.db.DB)
}

func TestOrgPermissionsInitializeExistingOrganization(t *testing.T) {
	f := newOrgPermissionFixture(t)
	owner := f.account(t)
	member := f.account(t)
	legacy := NewOrgService(f.org.orgs, f.s.users, sqlstore.NewSessionRepository(f.db), f.db, OrgServiceConfig{})
	org, err := legacy.CreateOrg(t.Context(), api.CreateOrgInput{OwnerID: owner.UserID, Name: "Existing", Slug: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	owner.OrgID = org.ID
	member.OrgID = org.ID
	if err = legacy.AddMember(t.Context(), api.AddMemberInput{OrgID: org.ID, ActorID: owner.UserID, UserID: member.UserID, Role: domain.OrgRoleMember}); err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.CheckPermission(t.Context(), api.CheckOrgPermissionInput{Actor: owner, PermissionKey: "goauth.org.organization.read"}); !errors.Is(err, domain.ErrOrgPermissionsNotInitialized) {
		t.Fatalf("existing org initialized implicitly: %v", err)
	}
	if err = f.s.Initialize(t.Context(), api.InitializeOrgPermissionsInput{Actor: member}); !errors.Is(err, domain.ErrOrgForbidden) {
		t.Fatalf("member initialized org: %v", err)
	}
	if err = f.s.Initialize(t.Context(), api.InitializeOrgPermissionsInput{Actor: owner}); err != nil {
		t.Fatal(err)
	}
	f.allowed(t, member, "goauth.org.members.read", true)
	if err = f.s.Initialize(t.Context(), api.InitializeOrgPermissionsInput{Actor: owner}); !errors.Is(err, domain.ErrOrgPermissionsInitialized) {
		t.Fatalf("repeat initialization: %v", err)
	}
	role, revision, err := f.repo.MemberRole(t.Context(), org.ID, member.UserID)
	if err != nil || role != nil || revision != 0 {
		t.Fatalf("legacy membership assignment rewritten: %+v %d %v", role, revision, err)
	}
}
