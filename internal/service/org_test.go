package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

func newTestOrgService() *OrgService {
	orgs := testutil.NewMockOrgRepo()
	users := testutil.NewMockUserRepo()
	orgs.SetUsers(users)
	sessions := testutil.NewMockSessionRepo()
	tx := &testutil.MockTxManager{}

	return NewOrgService(orgs, users, sessions, tx, OrgServiceConfig{
		MaxOrgsPerUser: 3,
		Logger:         nil,
	})
}

// newTestOrgServiceWithMaxOrgs is like newTestOrgService but with a much
// higher per-user org cap, for tests that need to seed more than the
// default 3 orgs (e.g. proving default-vs-unlimited Limit behavior needs
// more than 20 rows to be a meaningful distinction).
func newTestOrgServiceWithMaxOrgs(maxOrgs int) *OrgService {
	orgs := testutil.NewMockOrgRepo()
	users := testutil.NewMockUserRepo()
	orgs.SetUsers(users)
	sessions := testutil.NewMockSessionRepo()
	tx := &testutil.MockTxManager{}

	return NewOrgService(orgs, users, sessions, tx, OrgServiceConfig{
		MaxOrgsPerUser: maxOrgs,
		Logger:         nil,
	})
}

// newTestOrgServiceWithUsers is like newTestOrgService but also returns the
// underlying MockUserRepo, for tests that need real User records (name/email)
// to exercise ListMembers' Search/OrderBy against name/email.
func newTestOrgServiceWithUsers() (*OrgService, *testutil.MockUserRepo) {
	orgs := testutil.NewMockOrgRepo()
	users := testutil.NewMockUserRepo()
	orgs.SetUsers(users)
	sessions := testutil.NewMockSessionRepo()
	tx := &testutil.MockTxManager{}

	svc := NewOrgService(orgs, users, sessions, tx, OrgServiceConfig{
		MaxOrgsPerUser: 3,
		Logger:         nil,
	})
	return svc, users
}

// newTestOrgServiceWithAudit is like newTestOrgServiceWithUsers but also
// wires a MockAuditPublisher, for tests asserting which event type a
// mutation published (self-service vs admin-override).
func newTestOrgServiceWithAudit() (*OrgService, *testutil.MockUserRepo, *testutil.MockAuditPublisher) {
	orgs := testutil.NewMockOrgRepo()
	users := testutil.NewMockUserRepo()
	orgs.SetUsers(users)
	sessions := testutil.NewMockSessionRepo()
	tx := &testutil.MockTxManager{}
	pub := testutil.NewMockAuditPublisher()

	svc := NewOrgService(orgs, users, sessions, tx, OrgServiceConfig{
		MaxOrgsPerUser: 3,
		Logger:         nil,
		Audit:          pub,
	})
	return svc, users, pub
}

func newTestOrgInviteService() (*OrgService, *OrgInviteService) {
	orgs := testutil.NewMockOrgRepo()
	invites := testutil.NewMockOrgInviteRepo()
	users := testutil.NewMockUserRepo()
	orgs.SetUsers(users)
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

	result, err := svc.ListUserOrgs(ctx, ListUserOrgsInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("ListUserOrgs failed: %v", err)
	}
	if len(result.Orgs) != 2 {
		t.Errorf("expected 2 orgs, got %d", len(result.Orgs))
	}
	if len(result.Orgs) != 2 {
		t.Errorf("expected total 2, got %d", len(result.Orgs))
	}
}

func TestListUserOrgs_Search(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	svc.CreateOrg(ctx, CreateOrgInput{Name: "Acme Corp", Slug: "acme-corp", OwnerID: "user-1"})
	svc.CreateOrg(ctx, CreateOrgInput{Name: "Widgets Inc", Slug: "widgets-inc", OwnerID: "user-1"})

	search := "acme"
	result, err := svc.ListUserOrgs(ctx, ListUserOrgsInput{UserID: "user-1", Search: &search})
	if err != nil {
		t.Fatalf("ListUserOrgs failed: %v", err)
	}
	if len(result.Orgs) != 1 || result.Orgs[0].Name != "Acme Corp" {
		t.Errorf("expected only Acme Corp, got %+v", result.Orgs)
	}
}

func TestListUserOrgs_Sort(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	svc.CreateOrg(ctx, CreateOrgInput{Name: "Zeta", Slug: "zeta", OwnerID: "user-1"})
	svc.CreateOrg(ctx, CreateOrgInput{Name: "Alpha", Slug: "alpha", OwnerID: "user-1"})

	result, err := svc.ListUserOrgs(ctx, ListUserOrgsInput{UserID: "user-1", OrderBy: "name", OrderDirection: "asc"})
	if err != nil {
		t.Fatalf("ListUserOrgs failed: %v", err)
	}
	if len(result.Orgs) != 2 || result.Orgs[0].Name != "Alpha" || result.Orgs[1].Name != "Zeta" {
		t.Fatalf("expected [Alpha, Zeta] ascending, got %+v", result.Orgs)
	}

	result, err = svc.ListUserOrgs(ctx, ListUserOrgsInput{UserID: "user-1", OrderBy: "name", OrderDirection: "desc"})
	if err != nil {
		t.Fatalf("ListUserOrgs failed: %v", err)
	}
	if len(result.Orgs) != 2 || result.Orgs[0].Name != "Zeta" || result.Orgs[1].Name != "Alpha" {
		t.Fatalf("expected [Zeta, Alpha] descending, got %+v", result.Orgs)
	}
}

func TestListUserOrgs_DefaultLimit(t *testing.T) {
	svc := newTestOrgServiceWithMaxOrgs(30)
	ctx := context.Background()

	for i := 0; i < 25; i++ {
		slug := "org-" + string(rune('a'+i))
		svc.CreateOrg(ctx, CreateOrgInput{Name: slug, Slug: slug, OwnerID: "user-1"})
	}

	// Limit left nil (not set) — must default to 20, not return everything.
	result, err := svc.ListUserOrgs(ctx, ListUserOrgsInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("ListUserOrgs failed: %v", err)
	}
	if len(result.Orgs) != 20 || result.Limit != 20 {
		t.Errorf("expected 20 orgs (default limit), got %d orgs, limit=%d", len(result.Orgs), result.Limit)
	}
	count, err := svc.CountUserOrgs(ctx, ListUserOrgsInput{UserID: "user-1"})
	if err != nil {
		t.Fatalf("CountUserOrgs failed: %v", err)
	}
	if count != 25 {
		t.Errorf("expected total 25, got %d", count)
	}
}

func TestListUserOrgs_Unlimited(t *testing.T) {
	svc := newTestOrgServiceWithMaxOrgs(30)
	ctx := context.Background()

	for i := 0; i < 25; i++ {
		slug := "org-" + string(rune('a'+i))
		svc.CreateOrg(ctx, CreateOrgInput{Name: slug, Slug: slug, OwnerID: "user-1"})
	}

	// Explicit Limit: 0 must return every row, not the default 20.
	zero := 0
	result, err := svc.ListUserOrgs(ctx, ListUserOrgsInput{UserID: "user-1", Limit: &zero})
	if err != nil {
		t.Fatalf("ListUserOrgs failed: %v", err)
	}
	if len(result.Orgs) != 25 || result.Limit != 0 {
		t.Errorf("expected all 25 orgs (unlimited), got %d orgs, limit=%d", len(result.Orgs), result.Limit)
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

	two := 2
	result, err := svc.ListMembers(ctx, ListMembersInput{OrgID: org.ID, ActorID: "user-1", Offset: 0, Limit: &two})
	if err != nil {
		t.Fatalf("ListMembers failed: %v", err)
	}
	if len(result.Members) > 2 {
		t.Errorf("expected at most 2 members, got %d", len(result.Members))
	}
	count, err := svc.CountMembers(ctx, ListMembersInput{OrgID: org.ID, ActorID: "user-1"})
	if err != nil {
		t.Fatalf("CountMembers failed: %v", err)
	}
	if count < 5 {
		t.Errorf("expected total >= 5, got %d", count)
	}
}

func TestListMembers_DefaultLimit(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "user-1"})
	for i := 0; i < 25; i++ {
		uid := "user-" + string(rune('a'+i))
		svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: uid, Role: domain.OrgRoleMember, ActorID: "user-1"})
	}

	// Limit left nil (not set) — must default to 20, not return everything.
	result, err := svc.ListMembers(ctx, ListMembersInput{OrgID: org.ID, ActorID: "user-1"})
	if err != nil {
		t.Fatalf("ListMembers failed: %v", err)
	}
	if len(result.Members) != 20 || result.Limit != 20 {
		t.Errorf("expected 20 members (default limit), got %d members, limit=%d", len(result.Members), result.Limit)
	}
	count, err := svc.CountMembers(ctx, ListMembersInput{OrgID: org.ID, ActorID: "user-1"})
	if err != nil {
		t.Fatalf("CountMembers failed: %v", err)
	}
	if count != 26 { // 25 added members + the owner
		t.Errorf("expected total 26, got %d", count)
	}
}

func TestListMembers_Unlimited(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "user-1"})
	for i := 0; i < 25; i++ {
		uid := "user-" + string(rune('a'+i))
		svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: uid, Role: domain.OrgRoleMember, ActorID: "user-1"})
	}

	// Explicit Limit: 0 must return every row, not the default 20.
	zero := 0
	result, err := svc.ListMembers(ctx, ListMembersInput{OrgID: org.ID, ActorID: "user-1", Limit: &zero})
	if err != nil {
		t.Fatalf("ListMembers failed: %v", err)
	}
	if len(result.Members) != 26 || result.Limit != 0 {
		t.Errorf("expected all 26 members (unlimited), got %d members, limit=%d", len(result.Members), result.Limit)
	}
}

func TestListMembers_RoleFilter(t *testing.T) {
	svc := newTestOrgService()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "admin-1", Role: domain.OrgRoleAdmin, ActorID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "member-1", Role: domain.OrgRoleMember, ActorID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "member-2", Role: domain.OrgRoleMember, ActorID: "owner-1"})

	role := domain.OrgRoleMember
	result, err := svc.ListMembers(ctx, ListMembersInput{OrgID: org.ID, ActorID: "owner-1", Role: &role})
	if err != nil {
		t.Fatalf("ListMembers failed: %v", err)
	}
	if len(result.Members) != 2 {
		t.Fatalf("expected 2 members, got %d", len(result.Members))
	}
	for _, m := range result.Members {
		if m.Role != domain.OrgRoleMember {
			t.Errorf("expected only member role, got %s for %s", m.Role, m.UserID)
		}
	}
}

func TestListMembers_Search(t *testing.T) {
	svc, users := newTestOrgServiceWithUsers()
	ctx := context.Background()

	users.Create(ctx, &domain.User{ID: "owner-1", Email: "owner@example.com", Name: "Owner One"})
	users.Create(ctx, &domain.User{ID: "user-2", Email: "alice@example.com", Name: "Alice Anderson"})
	users.Create(ctx, &domain.User{ID: "user-3", Email: "bob@example.com", Name: "Bob Baker"})

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "user-2", Role: domain.OrgRoleMember, ActorID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "user-3", Role: domain.OrgRoleMember, ActorID: "owner-1"})

	search := "alice"
	result, err := svc.ListMembers(ctx, ListMembersInput{OrgID: org.ID, ActorID: "owner-1", Search: &search})
	if err != nil {
		t.Fatalf("ListMembers failed: %v", err)
	}
	if len(result.Members) != 1 || result.Members[0].UserID != "user-2" {
		t.Fatalf("expected only user-2 (Alice), got %+v", result.Members)
	}
}

func TestListMembers_Sort(t *testing.T) {
	svc, users := newTestOrgServiceWithUsers()
	ctx := context.Background()

	users.Create(ctx, &domain.User{ID: "owner-1", Email: "owner@example.com", Name: "Owner One"})
	users.Create(ctx, &domain.User{ID: "admin-1", Email: "admin@example.com", Name: "Admin One"})
	users.Create(ctx, &domain.User{ID: "member-1", Email: "member@example.com", Name: "Member One"})

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "admin-1", Role: domain.OrgRoleAdmin, ActorID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "member-1", Role: domain.OrgRoleMember, ActorID: "owner-1"})

	// Sorting by "role" is alphabetical on the raw string column
	// (admin < member < owner) — NOT by OrgRole.Weight() seniority — so
	// ascending order here is admin, member, owner, not owner-first.
	result, err := svc.ListMembers(ctx, ListMembersInput{OrgID: org.ID, ActorID: "owner-1", OrderBy: "role", OrderDirection: "asc"})
	if err != nil {
		t.Fatalf("ListMembers failed: %v", err)
	}
	if len(result.Members) != 3 {
		t.Fatalf("expected 3 members, got %d", len(result.Members))
	}
	wantOrder := []domain.OrgRole{domain.OrgRoleAdmin, domain.OrgRoleMember, domain.OrgRoleOwner}
	for i, want := range wantOrder {
		if result.Members[i].Role != want {
			t.Errorf("position %d: expected role %s, got %s", i, want, result.Members[i].Role)
		}
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
	orgs.SetUsers(users)
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

	result, err := inviteSvc.ListOrgInvites(ctx, ListOrgInvitesInput{OrgID: org.ID, ActorID: "owner-1"})
	if err != nil {
		t.Fatalf("ListOrgInvites failed: %v", err)
	}
	if len(result.Invites) != 2 {
		t.Errorf("expected 2 invites, got %d", len(result.Invites))
	}
	if result.Limit != 20 {
		t.Errorf("expected limit 20 (default), got %d", result.Limit)
	}

	count, err := inviteSvc.CountOrgInvites(ctx, ListOrgInvitesInput{OrgID: org.ID, ActorID: "owner-1"})
	if err != nil {
		t.Fatalf("CountOrgInvites failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected count 2, got %d", count)
	}
}

func TestListOrgInvites_StatusFilter(t *testing.T) {
	orgSvc, inviteSvc := newTestOrgInviteService()
	ctx := context.Background()

	org, _ := orgSvc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	pending, _ := inviteSvc.CreateOrgInvite(ctx, CreateOrgInviteInput{
		OrgID: org.ID, Email: "pending@test.com", Role: domain.OrgRoleMember, InvitedBy: "owner-1",
	})
	expired, _ := inviteSvc.CreateOrgInvite(ctx, CreateOrgInviteInput{
		OrgID: org.ID, Email: "expired@test.com", Role: domain.OrgRoleMember, InvitedBy: "owner-1",
	})
	// Backdate the second invite directly — the service won't let you create
	// an already-expired one, so mutate it post-creation via the repo.
	expired.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	if err := inviteSvc.orgInvites.Update(ctx, expired); err != nil {
		t.Fatal(err)
	}

	pendingStatus := "pending"
	result, err := inviteSvc.ListOrgInvites(ctx, ListOrgInvitesInput{OrgID: org.ID, ActorID: "owner-1", Status: &pendingStatus})
	if err != nil {
		t.Fatalf("ListOrgInvites failed: %v", err)
	}
	if len(result.Invites) != 1 || result.Invites[0].ID != pending.ID {
		t.Fatalf("expected only the pending invite, got %+v", result.Invites)
	}

	expiredStatus := "expired"
	result, err = inviteSvc.ListOrgInvites(ctx, ListOrgInvitesInput{OrgID: org.ID, ActorID: "owner-1", Status: &expiredStatus})
	if err != nil {
		t.Fatalf("ListOrgInvites failed: %v", err)
	}
	if len(result.Invites) != 1 || result.Invites[0].ID != expired.ID {
		t.Fatalf("expected only the expired invite, got %+v", result.Invites)
	}
}

func TestListOrgInvites_Search(t *testing.T) {
	orgSvc, inviteSvc := newTestOrgInviteService()
	ctx := context.Background()

	org, _ := orgSvc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	inviteSvc.CreateOrgInvite(ctx, CreateOrgInviteInput{OrgID: org.ID, Email: "alice@test.com", Role: domain.OrgRoleMember, InvitedBy: "owner-1"})
	inviteSvc.CreateOrgInvite(ctx, CreateOrgInviteInput{OrgID: org.ID, Email: "bob@test.com", Role: domain.OrgRoleMember, InvitedBy: "owner-1"})

	search := "alice"
	result, err := inviteSvc.ListOrgInvites(ctx, ListOrgInvitesInput{OrgID: org.ID, ActorID: "owner-1", Search: &search})
	if err != nil {
		t.Fatalf("ListOrgInvites failed: %v", err)
	}
	if len(result.Invites) != 1 || result.Invites[0].Email != "alice@test.com" {
		t.Fatalf("expected only alice@test.com, got %+v", result.Invites)
	}
}

func TestListOrgInvites_DefaultLimit(t *testing.T) {
	orgSvc, inviteSvc := newTestOrgInviteService()
	ctx := context.Background()

	org, _ := orgSvc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	for i := 0; i < 25; i++ {
		inviteSvc.CreateOrgInvite(ctx, CreateOrgInviteInput{
			OrgID: org.ID, Email: fmt.Sprintf("invite%d@test.com", i), Role: domain.OrgRoleMember, InvitedBy: "owner-1",
		})
	}

	result, err := inviteSvc.ListOrgInvites(ctx, ListOrgInvitesInput{OrgID: org.ID, ActorID: "owner-1"})
	if err != nil {
		t.Fatalf("ListOrgInvites failed: %v", err)
	}
	if len(result.Invites) != 20 || result.Limit != 20 {
		t.Errorf("expected 20 invites (default limit), got %d, limit=%d", len(result.Invites), result.Limit)
	}

	count, err := inviteSvc.CountOrgInvites(ctx, ListOrgInvitesInput{OrgID: org.ID, ActorID: "owner-1"})
	if err != nil {
		t.Fatalf("CountOrgInvites failed: %v", err)
	}
	if count != 25 {
		t.Errorf("expected count 25, got %d", count)
	}
}

func TestListOrgInvites_Unlimited(t *testing.T) {
	orgSvc, inviteSvc := newTestOrgInviteService()
	ctx := context.Background()

	org, _ := orgSvc.CreateOrg(ctx, CreateOrgInput{Name: "O", Slug: "acme", OwnerID: "owner-1"})
	for i := 0; i < 25; i++ {
		inviteSvc.CreateOrgInvite(ctx, CreateOrgInviteInput{
			OrgID: org.ID, Email: fmt.Sprintf("invite%d@test.com", i), Role: domain.OrgRoleMember, InvitedBy: "owner-1",
		})
	}

	zero := 0
	result, err := inviteSvc.ListOrgInvites(ctx, ListOrgInvitesInput{OrgID: org.ID, ActorID: "owner-1", Limit: &zero})
	if err != nil {
		t.Fatalf("ListOrgInvites failed: %v", err)
	}
	if len(result.Invites) != 25 || result.Limit != 0 {
		t.Errorf("expected all 25 invites (unlimited), got %d, limit=%d", len(result.Invites), result.Limit)
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

// ─── Platform-admin oversight ───────────────────────────────────

func mustCreateAdminUser(t *testing.T, users *testutil.MockUserRepo, id string) {
	t.Helper()
	if err := users.Create(context.Background(), &domain.User{ID: id, Email: id + "@example.com", Role: domain.RoleAdmin}); err != nil {
		t.Fatalf("failed to create admin user %s: %v", id, err)
	}
}

func TestAdminListOrgs_Search(t *testing.T) {
	svc, users, _ := newTestOrgServiceWithAudit()
	mustCreateAdminUser(t, users, "admin1")
	ctx := context.Background()

	svc.CreateOrg(ctx, CreateOrgInput{Name: "Acme Inc", Slug: "acme", OwnerID: "owner-1"})
	svc.CreateOrg(ctx, CreateOrgInput{Name: "Widget Co", Slug: "widget", OwnerID: "owner-2"})

	term := "acme"
	result, err := svc.AdminListOrgs(ctx, AdminListOrgsInput{ActorID: "admin1", Search: &term})
	if err != nil {
		t.Fatalf("AdminListOrgs failed: %v", err)
	}
	if len(result.Orgs) != 1 || result.Orgs[0].Slug != "acme" {
		t.Fatalf("expected exactly the acme org, got %+v", result)
	}
}

func TestAdminListOrgs_DateRange(t *testing.T) {
	orgs := testutil.NewMockOrgRepo()
	users := testutil.NewMockUserRepo()
	orgs.SetUsers(users)
	mustCreateAdminUser(t, users, "admin1")
	sessions := testutil.NewMockSessionRepo()
	tx := &testutil.MockTxManager{}
	svc := NewOrgService(orgs, users, sessions, tx, OrgServiceConfig{MaxOrgsPerUser: 10})
	ctx := context.Background()

	old, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "Old Org", Slug: "old-org", OwnerID: "owner-1"})
	oldOrg, _ := orgs.GetByID(ctx, old.ID)
	oldOrg.CreatedAt = time.Now().UTC().AddDate(0, 0, -30)
	if err := orgs.Update(ctx, oldOrg); err != nil {
		t.Fatalf("failed to backdate org: %v", err)
	}
	svc.CreateOrg(ctx, CreateOrgInput{Name: "New Org", Slug: "new-org", OwnerID: "owner-2"})

	cutoff := time.Now().UTC().AddDate(0, 0, -1)
	result, err := svc.AdminListOrgs(ctx, AdminListOrgsInput{ActorID: "admin1", CreatedAfter: &cutoff})
	if err != nil {
		t.Fatalf("AdminListOrgs failed: %v", err)
	}
	if len(result.Orgs) != 1 || result.Orgs[0].Slug != "new-org" {
		t.Fatalf("expected only new-org after cutoff, got %+v", result)
	}
}

func TestAdminListOrgs_Sort(t *testing.T) {
	svc, users, _ := newTestOrgServiceWithAudit()
	mustCreateAdminUser(t, users, "admin1")
	ctx := context.Background()

	svc.CreateOrg(ctx, CreateOrgInput{Name: "Zeta", Slug: "zeta", OwnerID: "owner-1"})
	svc.CreateOrg(ctx, CreateOrgInput{Name: "Alpha", Slug: "alpha", OwnerID: "owner-2"})

	result, err := svc.AdminListOrgs(ctx, AdminListOrgsInput{ActorID: "admin1", OrderBy: "name", OrderDirection: "asc"})
	if err != nil {
		t.Fatalf("AdminListOrgs failed: %v", err)
	}
	if len(result.Orgs) != 2 || result.Orgs[0].Name != "Alpha" || result.Orgs[1].Name != "Zeta" {
		t.Fatalf("expected Alpha before Zeta ascending, got %+v", result.Orgs)
	}
}

func TestAdminGetOrg_Found(t *testing.T) {
	svc, users, _ := newTestOrgServiceWithAudit()
	mustCreateAdminUser(t, users, "admin1")
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "Acme", Slug: "acme", OwnerID: "owner-1"})

	got, err := svc.AdminGetOrg(ctx, AdminGetOrgInput{OrgID: org.ID, ActorID: "admin1"})
	if err != nil {
		t.Fatalf("AdminGetOrg failed: %v", err)
	}
	if got.ID != org.ID {
		t.Errorf("expected org %s, got %s", org.ID, got.ID)
	}
}

func TestAdminGetOrg_NotFound(t *testing.T) {
	svc, users, _ := newTestOrgServiceWithAudit()
	mustCreateAdminUser(t, users, "admin1")

	_, err := svc.AdminGetOrg(context.Background(), AdminGetOrgInput{OrgID: "nonexistent", ActorID: "admin1"})
	if err != domain.ErrOrgNotFound {
		t.Errorf("expected ErrOrgNotFound, got %v", err)
	}
}

func TestAdminGetOrg_PublishesViewedEvent(t *testing.T) {
	svc, users, pub := newTestOrgServiceWithAudit()
	mustCreateAdminUser(t, users, "admin1")
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "Acme", Slug: "acme", OwnerID: "owner-1"})
	pub.Events = nil // drop the EventOrgCreated from CreateOrg above

	if _, err := svc.AdminGetOrg(ctx, AdminGetOrgInput{OrgID: org.ID, ActorID: "admin1"}); err != nil {
		t.Fatalf("AdminGetOrg failed: %v", err)
	}
	if len(pub.Events) != 1 || pub.Events[0].Type != audit.EventAdminOrgViewed {
		t.Fatalf("expected exactly one EventAdminOrgViewed, got %+v", pub.Events)
	}
}

func TestAdminListOrgMembers_BypassesMembership(t *testing.T) {
	svc, users, _ := newTestOrgServiceWithAudit()
	mustCreateAdminUser(t, users, "admin1") // not a member of the org below
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "Acme", Slug: "acme", OwnerID: "owner-1"})

	result, err := svc.AdminListOrgMembers(ctx, AdminListOrgMembersInput{OrgID: org.ID, ActorID: "admin1"})
	if err != nil {
		t.Fatalf("AdminListOrgMembers failed for a non-member admin: %v", err)
	}
	if len(result.Members) != 1 || result.Members[0].UserID != "owner-1" {
		t.Fatalf("expected the one owner member, got %+v", result)
	}
}

func TestAdminListOrgMembers_PublishesViewedEvent(t *testing.T) {
	svc, users, pub := newTestOrgServiceWithAudit()
	mustCreateAdminUser(t, users, "admin1")
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "Acme", Slug: "acme", OwnerID: "owner-1"})
	pub.Events = nil

	if _, err := svc.AdminListOrgMembers(ctx, AdminListOrgMembersInput{OrgID: org.ID, ActorID: "admin1"}); err != nil {
		t.Fatalf("AdminListOrgMembers failed: %v", err)
	}
	if len(pub.Events) != 1 || pub.Events[0].Type != audit.EventAdminOrgViewed {
		t.Fatalf("expected exactly one EventAdminOrgViewed, got %+v", pub.Events)
	}
}

func TestAdminDeleteOrg_BypassesMembership(t *testing.T) {
	svc, users, _ := newTestOrgServiceWithAudit()
	mustCreateAdminUser(t, users, "admin1") // not a member
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "Acme", Slug: "acme", OwnerID: "owner-1"})

	if err := svc.AdminDeleteOrg(ctx, AdminOrgActionInput{OrgID: org.ID, ActorID: "admin1"}); err != nil {
		t.Fatalf("AdminDeleteOrg failed for a non-member admin: %v", err)
	}
	if got, _ := svc.orgs.GetByID(ctx, org.ID); got != nil {
		t.Errorf("expected org to be deleted, still found: %+v", got)
	}
}

func TestAdminDeleteOrg_PublishesAdminEventNotSelfServiceEvent(t *testing.T) {
	svc, users, pub := newTestOrgServiceWithAudit()
	mustCreateAdminUser(t, users, "admin1")
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "Acme Inc", Slug: "acme", OwnerID: "owner-1"})
	pub.Events = nil

	if err := svc.AdminDeleteOrg(ctx, AdminOrgActionInput{OrgID: org.ID, ActorID: "admin1"}); err != nil {
		t.Fatalf("AdminDeleteOrg failed: %v", err)
	}
	if len(pub.Events) != 1 {
		t.Fatalf("expected exactly one published event, got %d", len(pub.Events))
	}
	evt := pub.Events[0]
	if evt.Type != audit.EventAdminOrgDeleted {
		t.Errorf("expected EventAdminOrgDeleted (not the self-service EventOrgDeleted), got %s", evt.Type)
	}
	if evt.Metadata["orgName"] != "Acme Inc" {
		t.Errorf("expected orgName snapshotted into metadata, got %v", evt.Metadata)
	}
}

func TestDeleteOrg_SelfService_PublishesSelfServiceEvent(t *testing.T) {
	svc, _, pub := newTestOrgServiceWithAudit()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "Acme", Slug: "acme", OwnerID: "owner-1"})
	pub.Events = nil

	if err := svc.DeleteOrg(ctx, DeleteOrgInput{OrgID: org.ID, ActorID: "owner-1"}); err != nil {
		t.Fatalf("DeleteOrg failed: %v", err)
	}
	if len(pub.Events) != 1 || pub.Events[0].Type != audit.EventOrgDeleted {
		t.Fatalf("expected exactly one EventOrgDeleted, got %+v", pub.Events)
	}
}

func TestAdminAddMember_RecoversOrphanedOrg(t *testing.T) {
	orgs := testutil.NewMockOrgRepo()
	users := testutil.NewMockUserRepo()
	orgs.SetUsers(users)
	mustCreateAdminUser(t, users, "admin1")
	sessions := testutil.NewMockSessionRepo()
	tx := &testutil.MockTxManager{}
	svc := NewOrgService(orgs, users, sessions, tx, OrgServiceConfig{MaxOrgsPerUser: 10})
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "Acme", Slug: "acme", OwnerID: "owner-1"})

	// removeMemberTx's TryDecrementOrgOwnerCount guard correctly refuses to
	// remove an org's last owner through the normal path (see
	// TestUpdateMemberRole_CannotDemoteLastOwner for the same guard on role
	// changes) — so a sole owner can never be *legitimately* removed. The
	// real orphaned-org scenario this recovers from is an owner's account
	// being deleted elsewhere in the system (e.g. AdminService.DeleteUser),
	// which does not go through OrgService at all: the membership row is
	// simply gone. Simulated here via the repository directly, bypassing
	// OrgService's own guard, since that's exactly what an out-of-band
	// deletion would do.
	if err := orgs.RemoveMember(ctx, org.ID, "owner-1"); err != nil {
		t.Fatalf("failed to simulate the dangling-membership scenario: %v", err)
	}
	result, _ := svc.AdminListOrgMembers(ctx, AdminListOrgMembersInput{OrgID: org.ID, ActorID: "admin1"})
	if len(result.Members) != 0 {
		t.Fatalf("expected the org to be memberless, got %+v", result)
	}

	// AdminAddMember reinstates a new owner — the recovery path.
	if err := svc.AdminAddMember(ctx, AdminAddMemberInput{OrgID: org.ID, UserID: "new-owner", Role: domain.OrgRoleOwner, ActorID: "admin1"}); err != nil {
		t.Fatalf("AdminAddMember failed: %v", err)
	}
	m, err := orgs.GetMembership(ctx, org.ID, "new-owner")
	if err != nil || m == nil || m.Role != domain.OrgRoleOwner {
		t.Fatalf("expected new-owner to be an Owner, got %+v, err=%v", m, err)
	}
}

func TestAdminRemoveMember_BypassesMembership_PublishesAdminEvent(t *testing.T) {
	svc, users, pub := newTestOrgServiceWithAudit()
	mustCreateAdminUser(t, users, "admin1") // not a member
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "Acme", Slug: "acme", OwnerID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "member-1", Role: domain.OrgRoleMember, ActorID: "owner-1"})
	pub.Events = nil

	if err := svc.AdminRemoveMember(ctx, AdminRemoveMemberInput{OrgID: org.ID, UserID: "member-1", ActorID: "admin1"}); err != nil {
		t.Fatalf("AdminRemoveMember failed for a non-member admin: %v", err)
	}
	if len(pub.Events) != 1 || pub.Events[0].Type != audit.EventAdminOrgMemberRemoved {
		t.Fatalf("expected exactly one EventAdminOrgMemberRemoved, got %+v", pub.Events)
	}
}

func TestAdminUpdateMemberRole_SkipsOwnerEscalationGuard_PublishesAdminEvent(t *testing.T) {
	svc, users, pub := newTestOrgServiceWithAudit()
	mustCreateAdminUser(t, users, "admin1") // not a member, not an Owner anywhere
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "Acme", Slug: "acme", OwnerID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "member-1", Role: domain.OrgRoleMember, ActorID: "owner-1"})
	pub.Events = nil

	// The self-service UpdateMemberRole would reject this: granting Owner
	// requires the actor to already be an Owner of this org, and admin1 is
	// neither a member nor an Owner anywhere. AdminUpdateMemberRole skips
	// that guard deliberately.
	if err := svc.AdminUpdateMemberRole(ctx, AdminUpdateMemberRoleInput{
		OrgID: org.ID, UserID: "member-1", NewRole: domain.OrgRoleOwner, ActorID: "admin1",
	}); err != nil {
		t.Fatalf("AdminUpdateMemberRole should bypass the owner-escalation guard, got: %v", err)
	}
	m, _ := svc.orgs.GetMembership(ctx, org.ID, "member-1")
	if m == nil || m.Role != domain.OrgRoleOwner {
		t.Fatalf("expected member-1 to now be Owner, got %+v", m)
	}
	if len(pub.Events) != 1 || pub.Events[0].Type != audit.EventAdminOrgMemberRoleChanged {
		t.Fatalf("expected exactly one EventAdminOrgMemberRoleChanged, got %+v", pub.Events)
	}
}

func TestUpdateMemberRole_NowPublishesEvent(t *testing.T) {
	svc, _, pub := newTestOrgServiceWithAudit()
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "Acme", Slug: "acme", OwnerID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "member-1", Role: domain.OrgRoleMember, ActorID: "owner-1"})
	pub.Events = nil

	if err := svc.UpdateMemberRole(ctx, UpdateMemberRoleInput{
		OrgID: org.ID, UserID: "member-1", NewRole: domain.OrgRoleAdmin, ActorID: "owner-1",
	}); err != nil {
		t.Fatalf("UpdateMemberRole failed: %v", err)
	}
	if len(pub.Events) != 1 || pub.Events[0].Type != audit.EventOrgMemberRoleChanged {
		t.Fatalf("expected exactly one EventOrgMemberRoleChanged (previously never published), got %+v", pub.Events)
	}
}

func TestAdminOrgMethods_ActorNotAdmin_Forbidden(t *testing.T) {
	svc, users, _ := newTestOrgServiceWithAudit()
	if err := users.Create(context.Background(), &domain.User{ID: "regular-user", Email: "regular@example.com", Role: domain.RoleUser}); err != nil {
		t.Fatalf("failed to create regular user: %v", err)
	}
	ctx := context.Background()

	org, _ := svc.CreateOrg(ctx, CreateOrgInput{Name: "Acme", Slug: "acme", OwnerID: "owner-1"})
	svc.AddMember(ctx, AddMemberInput{OrgID: org.ID, UserID: "member-1", Role: domain.OrgRoleMember, ActorID: "owner-1"})

	cases := []struct {
		name string
		call func() error
	}{
		{"AdminListOrgs", func() error {
			_, err := svc.AdminListOrgs(ctx, AdminListOrgsInput{ActorID: "regular-user"})
			return err
		}},
		{"AdminGetOrg", func() error {
			_, err := svc.AdminGetOrg(ctx, AdminGetOrgInput{OrgID: org.ID, ActorID: "regular-user"})
			return err
		}},
		{"AdminListOrgMembers", func() error {
			_, err := svc.AdminListOrgMembers(ctx, AdminListOrgMembersInput{OrgID: org.ID, ActorID: "regular-user"})
			return err
		}},
		{"AdminAddMember", func() error {
			return svc.AdminAddMember(ctx, AdminAddMemberInput{OrgID: org.ID, UserID: "someone", Role: domain.OrgRoleMember, ActorID: "regular-user"})
		}},
		{"AdminDeleteOrg", func() error {
			return svc.AdminDeleteOrg(ctx, AdminOrgActionInput{OrgID: org.ID, ActorID: "regular-user"})
		}},
		{"AdminRemoveMember", func() error {
			return svc.AdminRemoveMember(ctx, AdminRemoveMemberInput{OrgID: org.ID, UserID: "member-1", ActorID: "regular-user"})
		}},
		{"AdminUpdateMemberRole", func() error {
			return svc.AdminUpdateMemberRole(ctx, AdminUpdateMemberRoleInput{OrgID: org.ID, UserID: "member-1", NewRole: domain.OrgRoleAdmin, ActorID: "regular-user"})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.call(); err != domain.ErrForbidden {
				t.Errorf("expected ErrForbidden for a non-admin actor, got %v", err)
			}
		})
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
