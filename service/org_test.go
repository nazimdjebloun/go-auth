package service

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

func newTestOrgService() *OrgService {
	orgs := testutil.NewMockOrgRepo()
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tx := &testutil.MockTxManager{}

	return NewOrgService(orgs, users, sessions, tx, OrgServiceConfig{
		MaxOrgsPerUser: 3,
		Logger:         nil,
	})
}

func newTestOrgInviteService() (*OrgService, *OrgInviteService) {
	orgs := testutil.NewMockOrgRepo()
	invites := testutil.NewMockOrgInviteRepo()
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tx := &testutil.MockTxManager{}
	gen := &testutil.MockTokenGen{}

	orgSvc := NewOrgService(orgs, users, sessions, tx, OrgServiceConfig{
		MaxOrgsPerUser: 3,
		Logger:         nil,
	})
	inviteSvc := NewOrgInviteService(invites, orgs, users, tx, gen, &testutil.MockMailer{}, OrgInviteServiceConfig{
		MaxOrgsPerUser: 3,
		InviteTTL:      7 * 24 * time.Hour,
		BaseURL:        "http://localhost:3000",
		AppName:        "TestApp",
		URLValidator:   &port.URLValidator{AllowHTTP: true},
		Logger:         nil,
	})
	return orgSvc, inviteSvc
}

func TestCreateOrg_Success(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, err := svc.CreateOrg(ctx, CreateOrgInput{
		Name:    "Test Org",
		Slug:    "test-org",
		OwnerID: "user-1",
	})
	if err != nil {
		t.Fatalf("CreateOrg failed: %v", err)
	}
	if org.Name != "Test Org" {
		t.Errorf("expected name Test Org, got %s", org.Name)
	}
	if org.Slug != "test-org" {
		t.Errorf("expected slug test-org, got %s", org.Slug)
	}
	if org.OwnerCount != 1 {
		t.Errorf("expected owner count 1, got %d", org.OwnerCount)
	}

	member, err := svc.GetMembership(ctx, GetOrgMembershipInput{OrgID: org.ID, UserID: "user-1"})
	if err != nil {
		t.Fatalf("GetMembership failed: %v", err)
	}
	if member == nil {
		t.Fatal("expected member to exist")
	}
	if member.Role != domain.OrgRoleOwner {
		t.Errorf("expected owner role, got %s", member.Role)
	}
}

func TestCreateOrg_DuplicateSlug(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	_, err := svc.CreateOrg(ctx, CreateOrgInput{
		Name: "Org A", Slug: "same-slug", OwnerID: "user-1",
	})
	if err != nil {
		t.Fatalf("first create failed: %v", err)
	}

	_, err = svc.CreateOrg(ctx, CreateOrgInput{
		Name: "Org B", Slug: "same-slug", OwnerID: "user-2",
	})
	if err != domain.ErrOrgSlugExists {
		t.Errorf("expected ErrOrgSlugExists, got %v", err)
	}
}

func TestCreateOrg_ReservedSlug(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	_, err := svc.CreateOrg(ctx, CreateOrgInput{
		Name: "Admin", Slug: "admin", OwnerID: "user-1",
	})
	if err != domain.ErrOrgSlugReserved {
		t.Errorf("expected ErrOrgSlugReserved, got %v", err)
	}
}

func TestCreateOrg_OwnerCountLimit(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		slug := "org-" + string(rune('a'+i))
		_, err := svc.CreateOrg(ctx, CreateOrgInput{
			Name: slug, Slug: slug, OwnerID: "user-1",
		})
		if err != nil {
			t.Fatalf("create %d failed: %v", i, err)
		}
	}

	_, err := svc.CreateOrg(ctx, CreateOrgInput{
		Name: "too-many", Slug: "too-many", OwnerID: "user-1",
	})
	if err != domain.ErrOrgLimitReached {
		t.Errorf("expected ErrOrgLimitReached, got %v", err)
	}
}

func TestCreateOrg_EmptyName(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	_, err := svc.CreateOrg(ctx, CreateOrgInput{
		Name: "", Slug: "no-name", OwnerID: "user-1",
	})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestGetOrg_NotFound(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	// The org doesn't exist, so no actor has membership in it — this mirrors
	// the HTTP layer, where RequireOrgMember already rejects the request
	// before a handler could distinguish "no such org" from "not a member".
	_, err := svc.GetByID(ctx, GetOrgInput{OrgID: "nonexistent", ActorID: "user-1"})
	if err != domain.ErrOrgMemberNotFound {
		t.Errorf("expected ErrOrgMemberNotFound, got %v", err)
	}
}

func TestGetBySlug(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	created, err := svc.CreateOrg(ctx, CreateOrgInput{
		Name: "Test", Slug: "my-slug", OwnerID: "user-1",
	})
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	org, err := svc.GetBySlug(ctx, GetOrgBySlugInput{Slug: "my-slug", ActorID: "user-1"})
	if err != nil {
		t.Fatalf("GetBySlug failed: %v", err)
	}
	if org.ID != created.ID {
		t.Errorf("expected id %s, got %s", created.ID, org.ID)
	}
}

func TestUpdateOrg_NameAndSlug(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	created, err := svc.CreateOrg(ctx, CreateOrgInput{
		Name: "Old", Slug: "old-slug", OwnerID: "user-1",
	})
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	newName := "New Name"
	newSlug := "new-slug"
	updated, err := svc.UpdateOrg(ctx, UpdateOrgInput{
		OrgID:   created.ID,
		Name:    &newName,
		Slug:    &newSlug,
		ActorID: "user-1",
	})
	if err != nil {
		t.Fatalf("UpdateOrg failed: %v", err)
	}
	if updated.Name != newName {
		t.Errorf("expected name %s, got %s", newName, updated.Name)
	}
	if updated.Slug != newSlug {
		t.Errorf("expected slug %s, got %s", newSlug, updated.Slug)
	}
}

func TestUpdateOrg_ConflictingSlug(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	svc.CreateOrg(ctx, CreateOrgInput{Name: "A", Slug: "slug-a", OwnerID: "user-1"})
	svc.CreateOrg(ctx, CreateOrgInput{Name: "B", Slug: "slug-b", OwnerID: "user-1"})

	org, err := svc.GetBySlug(ctx, GetOrgBySlugInput{Slug: "slug-a", ActorID: "user-1"})
	if err != nil {
		t.Fatalf("get slug-a failed: %v", err)
	}

	newSlug := "slug-b"
	_, err = svc.UpdateOrg(ctx, UpdateOrgInput{
		OrgID:   org.ID,
		Slug:    &newSlug,
		ActorID: "user-1",
	})
	if err != domain.ErrOrgSlugExists {
		t.Errorf("expected ErrOrgSlugExists, got %v", err)
	}
}

func TestDeleteOrg(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	created, err := svc.CreateOrg(ctx, CreateOrgInput{
		Name: "To Delete", Slug: "to-delete", OwnerID: "user-1",
	})
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}

	if err := svc.DeleteOrg(ctx, DeleteOrgInput{OrgID: created.ID, ActorID: "user-1"}); err != nil {
		t.Fatalf("DeleteOrg failed: %v", err)
	}

	_, err = svc.GetByID(ctx, GetOrgInput{OrgID: created.ID, ActorID: "user-1"})
	if err != domain.ErrOrgNotFound {
		t.Errorf("expected ErrOrgNotFound after delete, got %v", err)
	}
}

func TestDeleteOrg_NotFound(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	// The org doesn't exist, so no actor has membership in it — see
	// TestGetOrg_NotFound for why this is ErrOrgMemberNotFound, not
	// ErrOrgNotFound.
	err := svc.DeleteOrg(ctx, DeleteOrgInput{OrgID: "nonexistent", ActorID: "user-1"})
	if err != domain.ErrOrgMemberNotFound {
		t.Errorf("expected ErrOrgMemberNotFound, got %v", err)
	}
}

func TestListUserOrgs(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	svc.CreateOrg(ctx, CreateOrgInput{Name: "A", Slug: "org-a", OwnerID: "user-1"})
	svc.CreateOrg(ctx, CreateOrgInput{Name: "B", Slug: "org-b", OwnerID: "user-1"})

	orgs, err := svc.ListUserOrgs(ctx, "user-1")
	if err != nil {
		t.Fatalf("ListUserOrgs failed: %v", err)
	}
	if len(orgs) != 2 {
		t.Errorf("expected 2 orgs, got %d", len(orgs))
	}
}

func TestAddMember_Success(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "my-org", OwnerID: "owner-1"})

	err := svc.AddMember(ctx, AddMemberInput{
		OrgID: org.ID, UserID: "user-2", Role: domain.OrgRoleMember, ActorID: "owner-1",
	})
	if err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}

	member, _ := svc.GetMembership(ctx, GetOrgMembershipInput{OrgID: org.ID, UserID: "user-2"})
	if member == nil {
		t.Fatal("expected member after add")
	}
	if member.Role != domain.OrgRoleMember {
		t.Errorf("expected member role, got %s", member.Role)
	}
}

func TestAddMember_ActorNotAdmin_Forbidden(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "my-org", OwnerID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "member-1", Role: domain.OrgRoleMember, ActorID: "owner-1"})

	err := svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "user-2", Role: domain.OrgRoleMember, ActorID: "member-1"})
	if err != domain.ErrOrgForbidden {
		t.Errorf("expected ErrOrgForbidden, got %v", err)
	}
}

func TestAddMember_Duplicate(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "user-2", Role: domain.OrgRoleMember, ActorID: "owner-1"})

	err := svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "user-2", Role: domain.OrgRoleMember, ActorID: "owner-1"})
	if err != domain.ErrOrgMemberExists {
		t.Errorf("expected ErrOrgMemberExists, got %v", err)
	}
}

func TestAddMember_OwnerIncrementsCount(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})

	err := svc.AddMember(ctx, AddMemberInput{
		OrgID: org.ID, UserID: "user-2", Role: domain.OrgRoleOwner, ActorID: "owner-1",
	})
	if err != nil {
		t.Fatalf("AddMember owner failed: %v", err)
	}

	// user-2 now owns 1 org (acme), can own up to 3 total
	for i := 0; i < 2; i++ {
		slug := "org-" + string(rune('x'+i))
		_, err := svc.CreateOrg(ctx, CreateOrgInput{Name: slug, Slug: slug, OwnerID: "user-2"})
		if err != nil {
			t.Fatalf("user-2 create %d failed: %v", i, err)
		}
	}

	_, err = svc.CreateOrg(ctx, CreateOrgInput{Name: "fail", Slug: "fail", OwnerID: "user-2"})
	if err != domain.ErrOrgLimitReached {
		t.Errorf("expected ErrOrgLimitReached, got %v", err)
	}
}

func TestRemoveMember_Success(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "user-2", Role: domain.OrgRoleMember, ActorID: "owner-1"})

	err := svc.RemoveMember(ctx, RemoveMemberInput{OrgID: org.ID, UserID: "user-2", ActorID: "owner-1"})
	if err != nil {
		t.Fatalf("RemoveMember failed: %v", err)
	}

	member, _ := svc.GetMembership(ctx, GetOrgMembershipInput{OrgID: org.ID, UserID: "user-2"})
	if member != nil {
		t.Error("expected member to be removed")
	}
}

func TestRemoveMember_NotFound(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	err := svc.RemoveMember(ctx, RemoveMemberInput{OrgID: "org-id", UserID: "nonexistent", ActorID: "admin-1"})
	if err != domain.ErrOrgMemberNotFound {
		t.Errorf("expected ErrOrgMemberNotFound, got %v", err)
	}
}

func TestRemoveMember_CannotRemoveLastOwner(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})

	// Self-removal (actorID == userID) skips the admin-role check.
	err := svc.RemoveMember(ctx, RemoveMemberInput{OrgID: org.ID, UserID: "owner-1", ActorID: "owner-1"})
	if err != domain.ErrCannotRemoveLastOwner {
		t.Errorf("expected ErrCannotRemoveLastOwner, got %v", err)
	}
}

func TestRemoveMember_ActorNotAdmin_Forbidden(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "member-1", Role: domain.OrgRoleMember, ActorID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "member-2", Role: domain.OrgRoleMember, ActorID: "owner-1"})

	// member-1 is only a Member, not an Admin, and is trying to remove
	// someone else (member-2) rather than leaving themselves.
	err := svc.RemoveMember(ctx, RemoveMemberInput{OrgID: org.ID, UserID: "member-2", ActorID: "member-1"})
	if err != domain.ErrOrgForbidden {
		t.Errorf("expected ErrOrgForbidden, got %v", err)
	}
}

func TestUpdateMemberRole_PromoteToOwner(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "user-2", Role: domain.OrgRoleMember, ActorID: "owner-1"})

	err := svc.UpdateMemberRole(ctx, UpdateMemberRoleInput{
		OrgID: org.ID, UserID: "user-2", NewRole: domain.OrgRoleOwner, ActorID: "owner-1",
	})
	if err != nil {
		t.Fatalf("UpdateMemberRole failed: %v", err)
	}

	member, _ := svc.GetMembership(ctx, GetOrgMembershipInput{OrgID: org.ID, UserID: "user-2"})
	if member.Role != domain.OrgRoleOwner {
		t.Errorf("expected owner role, got %s", member.Role)
	}
}

func TestUpdateMemberRole_DemoteFromOwner(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "user-2", Role: domain.OrgRoleOwner, ActorID: "owner-1"})

	err := svc.UpdateMemberRole(ctx, UpdateMemberRoleInput{
		OrgID: org.ID, UserID: "owner-1", NewRole: domain.OrgRoleMember, ActorID: "user-2",
	})
	if err != nil {
		t.Fatalf("UpdateMemberRole demote failed: %v", err)
	}

	member, _ := svc.GetMembership(ctx, GetOrgMembershipInput{OrgID: org.ID, UserID: "owner-1"})
	if member.Role != domain.OrgRoleMember {
		t.Errorf("expected member role, got %s", member.Role)
	}
}

func TestUpdateMemberRole_CannotDemoteLastOwner(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})

	err := svc.UpdateMemberRole(ctx, UpdateMemberRoleInput{
		OrgID: org.ID, UserID: "owner-1", NewRole: domain.OrgRoleMember, ActorID: "owner-1",
	})
	if err != domain.ErrCannotRemoveLastOwner {
		t.Errorf("expected ErrCannotRemoveLastOwner, got %v", err)
	}
}

func TestUpdateMemberRole_InvalidRole(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	err := svc.UpdateMemberRole(ctx, UpdateMemberRoleInput{
		OrgID: "org", UserID: "user", NewRole: "superadmin", ActorID: "admin",
	})
	if err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestLeaveOrg(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "user-2", Role: domain.OrgRoleMember, ActorID: "owner-1"})

	err := svc.LeaveOrg(ctx, LeaveOrgInput{OrgID: org.ID, UserID: "user-2"})
	if err != nil {
		t.Fatalf("LeaveOrg failed: %v", err)
	}

	member, _ := svc.GetMembership(ctx, GetOrgMembershipInput{OrgID: org.ID, UserID: "user-2"})
	if member != nil {
		t.Error("expected user to have left")
	}
}

func TestLeaveOrg_LastOwnerBlocked(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})

	err := svc.LeaveOrg(ctx, LeaveOrgInput{OrgID: org.ID, UserID: "owner-1"})
	if err != domain.ErrCannotRemoveLastOwner {
		t.Errorf("expected ErrCannotRemoveLastOwner, got %v", err)
	}
}

func TestSetActiveOrg_Success(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "user-1"})

	err := svc.SetActiveOrg(ctx, SetActiveOrgInput{SessionID: "session-1", UserID: "user-1", OrgID: org.ID})
	if err != nil {
		t.Fatalf("SetActiveOrg failed: %v", err)
	}
}

func TestSetActiveOrg_NotMember(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "user-1"})

	err := svc.SetActiveOrg(ctx, SetActiveOrgInput{SessionID: "session-2", UserID: "user-2", OrgID: org.ID})
	if err != domain.ErrOrgMemberNotFound {
		t.Errorf("expected ErrOrgMemberNotFound, got %v", err)
	}
}

func TestClearActiveOrg_Success(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	err := svc.ClearActiveOrg(ctx, ClearActiveOrgInput{SessionID: "session-1"})
	if err != nil {
		t.Fatalf("ClearActiveOrg failed: %v", err)
	}
	sessions := svc.sessions.(*testutil.MockSessionRepo)
	if len(sessions.ClearActiveOrgCalls) != 1 || sessions.ClearActiveOrgCalls[0] != "session-1" {
		t.Errorf("expected ClearActiveOrg to reach the repo with session-1, got %v", sessions.ClearActiveOrgCalls)
	}
}

func TestListMembers_Pagination(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "user-1"})
	for i := 0; i < 5; i++ {
		uid := "user-" + string(rune('a'+i))
		svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: uid, Role: domain.OrgRoleMember, ActorID: "user-1"})
	}

	members, total, err := svc.ListMembers(ctx, ListMembersInput{OrgID: org.ID, ActorID: "user-1", Offset: 0, Limit: 2})
	if err != nil {
		t.Fatalf("ListMembers failed: %v", err)
	}
	if len(members) > 2 {
		t.Errorf("expected at most 2 members, got %d", len(members))
	}
	if total < 5 {
		t.Errorf("expected total >= 5, got %d", total)
	}
}

func TestCreateOrgInvite_Success(t *testing.T) {
	orgSvc, inviteSvc := newTestOrgInviteService()
	ctx := context.Background()

	org, _ := orgSvc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})

	invite, err := inviteSvc.CreateOrgInvite(ctx, CreateOrgInviteInput{
		OrgID: org.ID, Email: "test@example.com", Role: domain.OrgRoleMember, InvitedBy: "owner-1",
	})
	if err != nil {
		t.Fatalf("CreateOrgInvite failed: %v", err)
	}
	if invite.OrgID != org.ID {
		t.Errorf("expected org id %s, got %s", org.ID, invite.OrgID)
	}
}

func TestCreateOrgInvite_InvalidRole(t *testing.T) {
	_, inviteSvc := newTestOrgInviteService()
	ctx := context.Background()

	_, err := inviteSvc.CreateOrgInvite(ctx, CreateOrgInviteInput{
		OrgID: "org", Email: "a@b.com", Role: "bogus", InvitedBy: "user",
	})
	if err == nil {
		t.Fatal("expected error for invalid invite role")
	}
}

func newTestOrgInviteServiceNoMailer() (*OrgService, *OrgInviteService, *testutil.MockOrgInviteRepo) {
	orgs := testutil.NewMockOrgRepo()
	invites := testutil.NewMockOrgInviteRepo()
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	tx := &testutil.MockTxManager{}
	gen := &testutil.MockTokenGen{}

	orgSvc := NewOrgService(orgs, users, sessions, tx, OrgServiceConfig{
		MaxOrgsPerUser: 3,
		Logger:         nil,
	})
	inviteSvc := NewOrgInviteService(invites, orgs, users, tx, gen, nil, OrgInviteServiceConfig{
		MaxOrgsPerUser: 3,
		InviteTTL:      7 * 24 * time.Hour,
		BaseURL:        "http://localhost:3000",
		AppName:        "TestApp",
		URLValidator:   &port.URLValidator{AllowHTTP: true},
		Logger:         nil,
	})
	return orgSvc, inviteSvc, invites
}

func TestCreateOrgInvite_NoMailer_ReturnsEmailNotConfigured(t *testing.T) {
	orgSvc, inviteSvc, _ := newTestOrgInviteServiceNoMailer()
	ctx := context.Background()

	org, _ := orgSvc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})

	_, err := inviteSvc.CreateOrgInvite(ctx, CreateOrgInviteInput{
		OrgID: org.ID, Email: "test@example.com", Role: domain.OrgRoleMember, InvitedBy: "owner-1",
	})
	if err == nil {
		t.Fatal("expected an error with no mailer configured, got nil")
	}
	if ae, ok := err.(*domain.AuthError); !ok || authErrCode(ae) != "email_not_configured" {
		t.Fatalf("err = %v, want email_not_configured", err)
	}
}

func TestResendOrgInviteEmail_NoMailer_ReturnsEmailNotConfigured(t *testing.T) {
	orgSvc, inviteSvc, invites := newTestOrgInviteServiceNoMailer()
	ctx := context.Background()

	// Seed the invite directly (bypassing CreateOrgInvite, which itself now
	// requires a mailer) so Resend is exercised in isolation.
	org, _ := orgSvc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	invite := &domain.OrgInvite{
		ID:        "invite-1",
		OrgID:     org.ID,
		Email:     "test@example.com",
		Role:      domain.OrgRoleMember,
		InvitedBy: "owner-1",
		ExpiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
		CreatedAt: time.Now().UTC(),
	}
	if err := invites.Create(ctx, invite); err != nil {
		t.Fatalf("seed invite: %v", err)
	}

	err := inviteSvc.ResendOrgInviteEmail(ctx, org.ID, invite.ID, "owner-1")
	if err == nil {
		t.Fatal("expected an error with no mailer configured, got nil")
	}
	if ae, ok := err.(*domain.AuthError); !ok || authErrCode(ae) != "email_not_configured" {
		t.Fatalf("err = %v, want email_not_configured", err)
	}
}

func TestDeleteOrgInvite_Success(t *testing.T) {
	orgSvc, inviteSvc := newTestOrgInviteService()
	ctx := context.Background()

	org, _ := orgSvc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	invite, _ := inviteSvc.CreateOrgInvite(ctx, CreateOrgInviteInput{
		OrgID: org.ID, Email: "a@b.com", Role: domain.OrgRoleMember, InvitedBy: "owner-1",
	})

	err := inviteSvc.DeleteOrgInvite(ctx, org.ID, invite.ID, "owner-1")
	if err != nil {
		t.Fatalf("DeleteOrgInvite failed: %v", err)
	}
}

func TestDeleteOrgInvite_NotFound(t *testing.T) {
	orgSvc, inviteSvc := newTestOrgInviteService()
	ctx := context.Background()

	// A real org with an authorized actor, so the "not found" check for the
	// invite itself is what's actually being exercised.
	org, _ := orgSvc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})

	err := inviteSvc.DeleteOrgInvite(ctx, org.ID, "nonexistent", "owner-1")
	if err == nil {
		t.Fatal("expected error for nonexistent invite")
	}
	if ae, ok := err.(*domain.AuthError); ok && authErrCode(ae) != "invite_not_found" {
		t.Errorf("expected invite_not_found, got %s", authErrCode(ae))
	}
}

func TestDeleteOrgInvite_ActorNotAdmin_Forbidden(t *testing.T) {
	orgSvc, inviteSvc := newTestOrgInviteService()
	ctx := context.Background()

	org, _ := orgSvc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	orgSvc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "member-1", Role: domain.OrgRoleMember, ActorID: "owner-1"})
	invite, _ := inviteSvc.CreateOrgInvite(ctx, CreateOrgInviteInput{
		OrgID: org.ID, Email: "a@b.com", Role: domain.OrgRoleMember, InvitedBy: "owner-1",
	})

	err := inviteSvc.DeleteOrgInvite(ctx, org.ID, invite.ID, "member-1")
	if err != domain.ErrOrgForbidden {
		t.Errorf("expected ErrOrgForbidden, got %v", err)
	}
}

func TestListOrgInvites(t *testing.T) {
	orgSvc, inviteSvc := newTestOrgInviteService()
	ctx := context.Background()

	org, _ := orgSvc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	inviteSvc.CreateOrgInvite(ctx, CreateOrgInviteInput{
		OrgID: org.ID, Email: "a@b.com", Role: domain.OrgRoleMember, InvitedBy: "owner-1",
	})
	inviteSvc.CreateOrgInvite(ctx, CreateOrgInviteInput{
		OrgID: org.ID, Email: "c@d.com", Role: domain.OrgRoleAdmin, InvitedBy: "owner-1",
	})

	invites, err := inviteSvc.ListOrgInvites(ctx, org.ID, "owner-1")
	if err != nil {
		t.Fatalf("ListOrgInvites failed: %v", err)
	}
	if len(invites) != 2 {
		t.Errorf("expected 2 invites, got %d", len(invites))
	}
}

func TestGetByID_ActorNotMember_Forbidden(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})

	_, err := svc.GetByID(ctx, GetOrgInput{OrgID: org.ID, ActorID: "outsider"})
	if err != domain.ErrOrgMemberNotFound {
		t.Errorf("expected ErrOrgMemberNotFound, got %v", err)
	}
}

func TestUpdateOrg_ActorNotAdmin_Forbidden(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "member-1", Role: domain.OrgRoleMember, ActorID: "owner-1"})

	newName := "New Name"
	_, err := svc.UpdateOrg(ctx, UpdateOrgInput{OrgID: org.ID, Name: &newName, ActorID: "member-1"})
	if err != domain.ErrOrgForbidden {
		t.Errorf("expected ErrOrgForbidden, got %v", err)
	}
}

func TestDeleteOrg_ActorNotOwner_Forbidden(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "admin-1", Role: domain.OrgRoleAdmin, ActorID: "owner-1"})

	// An Admin can manage members but must not be able to delete the org —
	// that's Owner-only.
	err := svc.DeleteOrg(ctx, DeleteOrgInput{OrgID: org.ID, ActorID: "admin-1"})
	if err != domain.ErrOrgForbidden {
		t.Errorf("expected ErrOrgForbidden, got %v", err)
	}
}

func TestUpdateMemberRole_ActorNotAdmin_Forbidden(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "member-1", Role: domain.OrgRoleMember, ActorID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "member-2", Role: domain.OrgRoleMember, ActorID: "owner-1"})

	err := svc.UpdateMemberRole(ctx, UpdateMemberRoleInput{
		OrgID: org.ID, UserID: "member-2", NewRole: domain.OrgRoleAdmin, ActorID: "member-1",
	})
	if err != domain.ErrOrgForbidden {
		t.Errorf("expected ErrOrgForbidden, got %v", err)
	}
}

func TestCreateOrgInvite_ActorNotAdmin_Forbidden(t *testing.T) {
	orgSvc, inviteSvc := newTestOrgInviteService()
	ctx := context.Background()

	org, _ := orgSvc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	orgSvc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "member-1", Role: domain.OrgRoleMember, ActorID: "owner-1"})

	_, err := inviteSvc.CreateOrgInvite(ctx, CreateOrgInviteInput{
		OrgID: org.ID, Email: "a@b.com", Role: domain.OrgRoleMember, InvitedBy: "member-1",
	})
	if err != domain.ErrOrgForbidden {
		t.Errorf("expected ErrOrgForbidden, got %v", err)
	}
}

func TestCreateOrgInvite_AdminCannotInviteOwner_Forbidden(t *testing.T) {
	orgSvc, inviteSvc := newTestOrgInviteService()
	ctx := context.Background()

	org, _ := orgSvc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	orgSvc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "admin-1", Role: domain.OrgRoleAdmin, ActorID: "owner-1"})

	_, err := inviteSvc.CreateOrgInvite(ctx, CreateOrgInviteInput{
		OrgID: org.ID, Email: "a@b.com", Role: domain.OrgRoleOwner, InvitedBy: "admin-1",
	})
	if err != domain.ErrOrgForbidden {
		t.Errorf("expected ErrOrgForbidden, got %v", err)
	}
}

func TestUpdateMemberRole_SameRole(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})

	err := svc.UpdateMemberRole(ctx, UpdateMemberRoleInput{
		OrgID: org.ID, UserID: "owner-1", NewRole: domain.OrgRoleOwner, ActorID: "owner-1",
	})
	if err != nil {
		t.Fatalf("changing to same role should succeed: %v", err)
	}
}

func TestUpdateMemberRole_NotFound(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	err := svc.UpdateMemberRole(ctx, UpdateMemberRoleInput{
		OrgID: "org", UserID: "unknown", NewRole: domain.OrgRoleAdmin, ActorID: "admin",
	})
	if err != domain.ErrOrgMemberNotFound {
		t.Errorf("expected ErrOrgMemberNotFound, got %v", err)
	}
}

func TestResolveMaxOrgsPerUser(t *testing.T) {
	tests := []struct {
		input int
		want  int
	}{
		{0, 100},
		{-1, 100},
		{1, 1},
		{50, 50},
		{100, 100},
	}
	for _, tt := range tests {
		got := resolveMaxOrgsPerUser(tt.input)
		if got != tt.want {
			t.Errorf("resolveMaxOrgsPerUser(%d) = %d, want %d", tt.input, got, tt.want)
		}
	}
}
