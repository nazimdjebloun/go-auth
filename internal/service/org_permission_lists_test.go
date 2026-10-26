package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type orgRoleReadCounter struct {
	port.OrgPermissionRoleStore
	reads int
}

func (r *orgRoleReadCounter) MemberRole(ctx context.Context, orgID, userID string) (*domain.OrgPermissionRole, uint64, error) {
	r.reads++
	return r.OrgPermissionRoleStore.MemberRole(ctx, orgID, userID)
}

func (r *orgRoleReadCounter) InviteRole(ctx context.Context, orgID, inviteID string) (*domain.OrgPermissionRole, uint64, error) {
	r.reads++
	return r.OrgPermissionRoleStore.InviteRole(ctx, orgID, inviteID)
}

func (r *orgRoleReadCounter) RoleBySlug(ctx context.Context, orgID, slug string) (*domain.OrgPermissionRole, error) {
	r.reads++
	return r.OrgPermissionRoleStore.RoleBySlug(ctx, orgID, slug)
}

func TestOrgPermissionsMemberListRoleEnrichment(t *testing.T) {
	f := newOrgPermissionFixture(t)
	admin := f.member(t, domain.OrgRoleAdmin)
	custom := f.member(t, domain.OrgRoleMember)
	member := f.member(t, domain.OrgRoleMember)
	role := f.role(t, "custom")
	assignment := f.assign(t, custom, role)

	// The same user and protected slugs in another org must not duplicate or
	// replace this org's assignment or legacy fallback.
	other, err := f.org.CreateOrg(t.Context(), api.CreateOrgInput{OwnerID: f.owner.UserID, Name: "Other", Slug: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.org.AddMember(t.Context(), api.AddMemberInput{OrgID: other.ID, ActorID: f.owner.UserID, UserID: custom.UserID, Role: domain.OrgRoleAdmin}); err != nil {
		t.Fatal(err)
	}
	otherActor := orgActor(other.ID, f.owner.UserID, "")
	otherRole, err := f.s.CreateRole(t.Context(), api.CreateOrgRoleInput{Actor: otherActor, Slug: "custom", Name: "Other custom"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.SetMemberRole(t.Context(), api.SetOrgMemberRoleInput{Actor: otherActor, UserID: custom.UserID, RoleID: otherRole.ID, ExpectedRoleRevision: 1}); err != nil {
		t.Fatal(err)
	}
	actors := []api.OrgPermissionActor{f.owner, admin, custom, member}
	for i, actor := range actors {
		if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET name=$1 WHERE id=$2", string(rune('A'+i)), actor.UserID); err != nil {
			t.Fatal(err)
		}
	}
	wantRoleIDs := make(map[string]string)
	for _, actor := range []api.OrgPermissionActor{f.owner, admin, member} {
		base := domain.OrgRoleMember
		if actor == f.owner {
			base = domain.OrgRoleOwner
		} else if actor == admin {
			base = domain.OrgRoleAdmin
		}
		builtin, err := f.repo.RoleBySlug(t.Context(), f.owner.OrgID, string(base))
		if err != nil {
			t.Fatal(err)
		}
		wantRoleIDs[actor.UserID] = builtin.ID
	}
	wantRoleIDs[custom.UserID] = role.ID
	counter := &orgRoleReadCounter{OrgPermissionRoleStore: f.s.roles}
	f.s.roles = counter
	one := 1
	input := api.ListMembersInput{OrgID: f.owner.OrgID, ActorID: f.owner.UserID, Limit: &one, Offset: 1, OrderBy: api.OrgMemberSortName, OrderDirection: api.SortAscending}
	page, err := f.org.ListMembers(t.Context(), input)
	if err != nil || len(page.Members) != 1 || page.Members[0].UserID != admin.UserID {
		t.Fatalf("member page = %+v, error = %v", page, err)
	}
	pageReads := counter.reads
	counter.reads = 0
	zero := 0
	input.Limit, input.Offset = &zero, 0
	all, err := f.org.ListMembers(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Members) != len(actors) || counter.reads != pageReads {
		t.Fatalf("unlimited members = %d, role reads = %d (page = %d)", len(all.Members), counter.reads, pageReads)
	}
	for i, got := range all.Members {
		wantRevision := uint64(0)
		if got.UserID == custom.UserID {
			wantRevision = assignment.AssignmentRevision
		}
		if got.UserID != actors[i].UserID || got.OrgRoleID == nil || *got.OrgRoleID != wantRoleIDs[got.UserID] || got.OrgRoleAssignmentRevision != wantRevision {
			t.Fatalf("member role = %+v", got)
		}
	}
	f.org.orgPermissions = nil
	disabled, err := f.org.ListMembers(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range disabled.Members {
		if got.OrgRoleID != nil || got.OrgRoleAssignmentRevision != 0 {
			t.Fatalf("disabled feature exposed role metadata: %+v", got)
		}
	}
}

func TestOrgPermissionsInviteListRoleEnrichment(t *testing.T) {
	f := newOrgPermissionFixture(t)
	role := f.role(t, "custom")
	custom, err := f.invites.CreateOrgInvite(t.Context(), api.CreateOrgInviteInput{OrgID: f.owner.OrgID, InvitedBy: f.owner.UserID, Email: "a@example.com", OrgRoleID: role.ID, ExpectedRoleRevision: role.Revision})
	if err != nil {
		t.Fatal(err)
	}
	builtin, err := f.invites.CreateOrgInvite(t.Context(), api.CreateOrgInviteInput{OrgID: f.owner.OrgID, InvitedBy: f.owner.UserID, Email: "b@example.com", Role: domain.OrgRoleMember})
	if err != nil {
		t.Fatal(err)
	}
	legacy := &domain.OrgInvite{ID: uuid.NewString(), OrgID: f.owner.OrgID, InvitedBy: f.owner.UserID, Email: "c@example.com", Role: domain.OrgRoleMember, CodeHash: uuid.NewString(), ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC()}
	if err := f.invites.orgInvites.Create(t.Context(), legacy); err != nil {
		t.Fatal(err)
	}
	name := "Changed"
	if _, err := f.s.UpdateRole(t.Context(), api.UpdateOrgRoleInput{Actor: f.owner, RoleID: role.ID, ExpectedRevision: role.Revision, Name: &name}); err != nil {
		t.Fatal(err)
	}
	counter := &orgRoleReadCounter{OrgPermissionRoleStore: f.s.roles}
	f.s.roles = counter
	one := 1
	input := api.ListOrgInvitesInput{OrgID: f.owner.OrgID, ActorID: f.owner.UserID, Limit: &one, Offset: 1, OrderBy: api.OrgInviteSortEmail, OrderDirection: api.SortAscending}
	page, err := f.invites.ListOrgInvites(t.Context(), input)
	if err != nil || len(page.Invites) != 1 || page.Invites[0].ID != builtin.ID {
		t.Fatalf("invite page = %+v, error = %v", page, err)
	}
	pageReads := counter.reads
	counter.reads = 0
	zero := 0
	input.Limit, input.Offset = &zero, 0
	all, err := f.invites.ListOrgInvites(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Invites) != 3 || counter.reads != pageReads {
		t.Fatalf("unlimited invites = %d, role reads = %d (page = %d)", len(all.Invites), counter.reads, pageReads)
	}
	if got := all.Invites[0]; got.ID != custom.ID || got.OrgRoleID == nil || *got.OrgRoleID != role.ID || got.OrgRoleRevision != custom.OrgRoleRevision {
		t.Fatalf("custom invitation lost its original role revision: %+v", got)
	}
	if got := all.Invites[1]; got.ID != builtin.ID || got.OrgRoleID == nil || *got.OrgRoleID != *builtin.OrgRoleID || got.OrgRoleRevision != builtin.OrgRoleRevision {
		t.Fatalf("built-in invitation role = %+v", got)
	}
	if got := all.Invites[2]; got.ID != legacy.ID || got.OrgRoleID != nil || got.OrgRoleRevision != 0 {
		t.Fatalf("legacy invitation gained a proposed role: %+v", got)
	}
	search, pending := "b@", "pending"
	input.Search, input.Status = &search, &pending
	filtered, err := f.invites.ListOrgInvites(t.Context(), input)
	if err != nil || len(filtered.Invites) != 1 || filtered.Invites[0].ID != builtin.ID {
		t.Fatalf("filtered invites = %+v, error = %v", filtered, err)
	}
	count, err := f.invites.CountOrgInvites(t.Context(), input)
	if err != nil || count != 1 {
		t.Fatalf("filtered count = %d, error = %v", count, err)
	}
	f.invites.orgPermissions = nil
	input.Search, input.Status = nil, nil
	disabled, err := f.invites.ListOrgInvites(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range disabled.Invites {
		if got.OrgRoleID != nil || got.OrgRoleRevision != 0 {
			t.Fatalf("disabled feature exposed proposed role: %+v", got)
		}
	}
}

func TestOrgPermissionsSelfInspectionAndResendAuthority(t *testing.T) {
	f := newOrgPermissionFixture(t)
	member := f.member(t, domain.OrgRoleMember)
	if _, err := f.s.GetMemberRole(t.Context(), api.GetOrgMemberRoleInput{Actor: member, UserID: member.UserID}); !errors.Is(err, domain.ErrOrgForbidden) {
		t.Fatalf("self role inspection bypassed roles.read: %v", err)
	}
	if _, err := f.s.ListEffectivePermissions(t.Context(), api.ListOrgEffectivePermissionsInput{Actor: member}); err != nil {
		t.Fatalf("self access required roles.read: %v", err)
	}
	inviter := f.member(t, domain.OrgRoleAdmin)
	invite, err := f.invites.CreateOrgInvite(t.Context(), api.CreateOrgInviteInput{OrgID: f.owner.OrgID, InvitedBy: inviter.UserID, Email: "invited@example.com", Role: domain.OrgRoleMember})
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.invites.orgInvites.GetByID(t.Context(), invite.ID)
	if err != nil || before == nil {
		t.Fatalf("stored invitation missing: %+v, error = %v", before, err)
	}
	if err := f.invites.ResendOrgInviteEmail(t.Context(), api.ResendOrgInviteEmailInput{OrgID: f.owner.OrgID, ActorID: member.UserID, InviteID: invite.ID}); !errors.Is(err, domain.ErrOrgForbidden) {
		t.Fatalf("resend bypassed resender's grants: %v", err)
	}
	if err := f.org.UpdateMemberRole(t.Context(), api.UpdateMemberRoleInput{OrgID: f.owner.OrgID, ActorID: f.owner.UserID, UserID: inviter.UserID, NewRole: domain.OrgRoleMember}); err != nil {
		t.Fatal(err)
	}
	if err := f.invites.ResendOrgInviteEmail(t.Context(), api.ResendOrgInviteEmailInput{OrgID: f.owner.OrgID, ActorID: f.owner.UserID, InviteID: invite.ID}); !errors.Is(err, domain.ErrOrgForbidden) {
		t.Fatalf("owner overrode original inviter's lost authority: %v", err)
	}
	stored, err := f.invites.orgInvites.GetByID(t.Context(), invite.ID)
	if err != nil || stored == nil || stored.CodeHash != before.CodeHash || !stored.ExpiresAt.Equal(before.ExpiresAt) {
		t.Fatalf("rejected resend rotated the invitation: %+v, error = %v", stored, err)
	}
	if err := f.invites.DeleteOrgInvite(t.Context(), api.DeleteOrgInviteInput{OrgID: f.owner.OrgID, ActorID: f.owner.UserID, InviteID: invite.ID}); err != nil {
		t.Fatal(err)
	}
	replacement, err := f.invites.CreateOrgInvite(t.Context(), api.CreateOrgInviteInput{OrgID: f.owner.OrgID, InvitedBy: f.owner.UserID, Email: invite.Email, Role: domain.OrgRoleMember})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.invites.ResendOrgInviteEmail(t.Context(), api.ResendOrgInviteEmailInput{OrgID: f.owner.OrgID, ActorID: f.owner.UserID, InviteID: replacement.ID}); err != nil {
		t.Fatalf("replacement invitation could not be resent: %v", err)
	}
}
