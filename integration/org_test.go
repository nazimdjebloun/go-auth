package integration_test

import (
	"context"
	"database/sql"
	"testing"
	"time"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/service"
)

func openOrgAuth(t *testing.T, db *sql.DB, mailer port.Mailer) *goauth.Auth {
	t.Helper()
	migrateDB(t, db, "sqlite")
	cfg, err := goauth.NewConfig(
		goauth.WithApp(goauth.AppConfig{
			Name:    "TestApp",
			BaseURL: "http://localhost:8080",
			Database: goauth.DatabaseConfig{
				DB:     db,
				Driver: goauth.DriverSQLite,
			},
		}),
		goauth.WithSession(goauth.SessionConfig{
			TTL:             1 * time.Hour,
			IdleTTL:         1 * time.Hour,
			RefreshTokenTTL: 1 * time.Hour,
		}),
		goauth.WithSecurity(goauth.SecurityConfig{
			AllowedOrigins: []string{"http://localhost:8080"},
			TokenTTL:       1 * time.Hour,
		}),
		goauth.WithRegistration(goauth.RegistrationConfig{
			EnableEmailPassword:           true,
			EnableOAuth:              true,
			EnableInvite:             false,
			AllowPublic:              true,
			InviteTTL:                1 * time.Hour,
			VerificationCodeTTL:      1 * time.Hour,
		}),
		goauth.WithCookie(goauth.CookieConfig{Name: "goauth_session"}),
		goauth.WithMailer(mailer),
		goauth.WithEmail(goauth.EmailConfig{AllowHTTPURLs: true}),
		goauth.WithOrganizations(goauth.OrganizationConfig{
			Enable: true,
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	a, err := goauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestOrg_CreateOrgAndGetByID(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()

	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner@test.com", Password: "V@lidPswd1", Name: "Owner",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "My Org", Slug: "my-org", OwnerID: res.User.ID,
	})
	if err != nil {
		t.Fatalf("CreateOrg failed: %v", err)
	}
	if org.Name != "My Org" || org.Slug != "my-org" {
		t.Errorf("Name=%q Slug=%q", org.Name, org.Slug)
	}
	if org.OwnerCount != 1 || org.MemberCount != 1 {
		t.Errorf("OwnerCount=%d MemberCount=%d", org.OwnerCount, org.MemberCount)
	}

	var dbName, dbSlug string
	var dbOwnerCount, dbMemberCount int
	if err := db.QueryRow("SELECT name,slug,owner_count,member_count FROM organizations WHERE id=?", org.ID).
		Scan(&dbName, &dbSlug, &dbOwnerCount, &dbMemberCount); err != nil {
		t.Fatalf("query org: %v", err)
	}
	if dbOwnerCount != 1 || dbMemberCount != 1 {
		t.Errorf("db counts: owner=%d member=%d", dbOwnerCount, dbMemberCount)
	}

	var role string
	if err := db.QueryRow("SELECT role FROM organization_members WHERE org_id=? AND user_id=?", org.ID, res.User.ID).
		Scan(&role); err != nil {
		t.Fatalf("query membership: %v", err)
	}
	if role != "owner" {
		t.Errorf("role=%q", role)
	}

	got, err := a.Services.Org.GetByID(ctx, org.ID)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if got.ID != org.ID {
		t.Error("GetByID wrong org")
	}
}

func TestOrg_CreateOrgDuplicateSlug(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "u@test.com", Password: "V@lidPswd1", Name: "U",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	if _, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "First", Slug: "dup", OwnerID: res.User.ID,
	}); err != nil {
		t.Fatal(err)
	}

	_, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "Second", Slug: "dup", OwnerID: res.User.ID,
	})
	if err == nil {
		t.Fatal("expected error for duplicate slug")
	}
	if err.Error() != domain.ErrOrgSlugExists.Error() {
		t.Errorf("expected slug exists error, got %v", err)
	}
}

func TestOrg_CreateOrgReservedSlug(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "u@test.com", Password: "V@lidPswd1", Name: "U",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	_, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "Admin", Slug: "admin", OwnerID: res.User.ID,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != domain.ErrOrgSlugReserved.Error() {
		t.Errorf("got %v", err)
	}
}

func TestOrg_GetBySlug(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "u@test.com", Password: "V@lidPswd1", Name: "U",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "By Slug", Slug: "by-slug", OwnerID: res.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := a.Services.Org.GetBySlug(ctx, "by-slug")
	if err != nil {
		t.Fatalf("GetBySlug failed: %v", err)
	}
	if got.ID != org.ID {
		t.Error("GetBySlug wrong org")
	}

	_, err = a.Services.Org.GetBySlug(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestOrg_UpdateOrg(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "u@test.com", Password: "V@lidPswd1", Name: "U",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "Old Name", Slug: "old-slug", OwnerID: res.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	newName, newSlug := "New Name", "new-slug"
	updated, err := a.Services.Org.UpdateOrg(ctx, service.UpdateOrgInput{
		OrgID: org.ID, Name: &newName, Slug: &newSlug,
	})
	if err != nil {
		t.Fatalf("UpdateOrg failed: %v", err)
	}
	if updated.Name != newName || updated.Slug != newSlug {
		t.Errorf("Name=%q Slug=%q", updated.Name, updated.Slug)
	}

	var dbSlug string
	db.QueryRow("SELECT slug FROM organizations WHERE id=?", org.ID).Scan(&dbSlug)
	if dbSlug != newSlug {
		t.Errorf("db slug=%q", dbSlug)
	}
}

func TestOrg_DeleteOrg(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "u@test.com", Password: "V@lidPswd1", Name: "U",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "To Delete", Slug: "to-delete", OwnerID: res.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := a.Services.Org.DeleteOrg(ctx, org.ID); err != nil {
		t.Fatalf("DeleteOrg failed: %v", err)
	}

	if _, err := a.Services.Org.GetByID(ctx, org.ID); err == nil {
		t.Fatal("expected error after deletion")
	}
}

func TestOrg_AddAndRemoveMember(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()

	owner, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner@test.com", Password: "V@lidPswd1", Name: "Owner",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	member, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "member@test.com", Password: "V@lidPswd1", Name: "Member",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "Team", Slug: "team", OwnerID: owner.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := a.Services.Org.AddMember(ctx, service.AddMemberInput{
		OrgID: org.ID, UserID: member.User.ID, Role: domain.OrgRoleMember,
	}); err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}

	m, err := a.Services.Org.GetMembership(ctx, org.ID, member.User.ID)
	if err != nil {
		t.Fatalf("GetMembership failed: %v", err)
	}
	if m.Role != domain.OrgRoleMember {
		t.Errorf("role=%q", m.Role)
	}

	var dbCount int
	db.QueryRow("SELECT member_count FROM organizations WHERE id=?", org.ID).Scan(&dbCount)
	if dbCount != 2 {
		t.Errorf("member_count=%d", dbCount)
	}

	if err := a.Services.Org.RemoveMember(ctx, org.ID, member.User.ID); err != nil {
		t.Fatalf("RemoveMember failed: %v", err)
	}

	if _, err := a.Services.Org.GetMembership(ctx, org.ID, member.User.ID); err == nil {
		t.Fatal("expected error after removal")
	}

	db.QueryRow("SELECT member_count FROM organizations WHERE id=?", org.ID).Scan(&dbCount)
	if dbCount != 1 {
		t.Errorf("member_count=%d", dbCount)
	}
}

func TestOrg_AddDuplicateMember(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()

	owner, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner@test.com", Password: "V@lidPswd1", Name: "Owner",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "Dup", Slug: "dup", OwnerID: owner.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = a.Services.Org.AddMember(ctx, service.AddMemberInput{
		OrgID: org.ID, UserID: owner.User.ID, Role: domain.OrgRoleMember,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if err.Error() != domain.ErrOrgMemberExists.Error() {
		t.Errorf("got %v", err)
	}
}

func TestOrg_UpdateMemberRole(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()

	owner, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner@test.com", Password: "V@lidPswd1", Name: "Owner",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	member, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "member@test.com", Password: "V@lidPswd1", Name: "Member",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "Roles", Slug: "roles", OwnerID: owner.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := a.Services.Org.AddMember(ctx, service.AddMemberInput{
		OrgID: org.ID, UserID: member.User.ID, Role: domain.OrgRoleMember,
	}); err != nil {
		t.Fatal(err)
	}

	if err := a.Services.Org.UpdateMemberRole(ctx, service.UpdateMemberRoleInput{
		OrgID: org.ID, UserID: member.User.ID, NewRole: domain.OrgRoleOwner, ActorID: owner.User.ID,
	}); err != nil {
		t.Fatalf("promote failed: %v", err)
	}

	var dbRole string
	db.QueryRow("SELECT role FROM organization_members WHERE org_id=? AND user_id=?", org.ID, member.User.ID).Scan(&dbRole)
	if dbRole != "owner" {
		t.Errorf("role=%q", dbRole)
	}

	var dbOwnerCount int
	db.QueryRow("SELECT owner_count FROM organizations WHERE id=?", org.ID).Scan(&dbOwnerCount)
	if dbOwnerCount != 2 {
		t.Errorf("owner_count=%d", dbOwnerCount)
	}
}

func TestOrg_CannotRemoveLastOwner(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()

	owner, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner@test.com", Password: "V@lidPswd1", Name: "Owner",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "OnlyOne", Slug: "only-one", OwnerID: owner.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := a.Services.Org.RemoveMember(ctx, org.ID, owner.User.ID); err == nil {
		t.Fatal("expected error")
	}
}

func TestOrg_ListMembers(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()

	owner, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner@test.com", Password: "V@lidPswd1", Name: "Owner",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "List", Slug: "list", OwnerID: owner.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, email := range []string{"m1@test.com", "m2@test.com", "m3@test.com"} {
		u, rerr := a.Register(ctx, goauth.RegisterInput{
			Email: email, Password: "V@lidPswd1", Name: "M",
		})
		if rerr != nil {
			t.Fatal(rerr)
		}
		if err := a.Services.Org.AddMember(ctx, service.AddMemberInput{
			OrgID: org.ID, UserID: u.User.ID, Role: domain.OrgRoleMember,
		}); err != nil {
			t.Fatal(err)
		}
	}

	members, total, err := a.Services.Org.ListMembers(ctx, org.ID, 0, 2)
	if err != nil {
		t.Fatalf("ListMembers failed: %v", err)
	}
	if len(members) > 2 {
		t.Errorf("expected <=2, got %d", len(members))
	}
	if total < 4 {
		t.Errorf("total=%d, want >=4", total)
	}
}

func TestOrg_ListUserOrgs(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()

	owner, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner@test.com", Password: "V@lidPswd1", Name: "Owner",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	org1, _ := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "A", Slug: "org-a", OwnerID: owner.User.ID,
	})
	org2, _ := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "B", Slug: "org-b", OwnerID: owner.User.ID,
	})

	orgs, err := a.Services.Org.ListUserOrgs(ctx, owner.User.ID)
	if err != nil {
		t.Fatalf("ListUserOrgs failed: %v", err)
	}
	if len(orgs) != 2 {
		t.Errorf("expected 2, got %d", len(orgs))
	}

	ids := map[string]bool{org1.ID: true, org2.ID: true}
	for _, o := range orgs {
		delete(ids, o.ID)
	}
	if len(ids) != 0 {
		t.Error("returned orgs don't match")
	}
}

func TestOrg_CreateOrgInviteAndDelete(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()

	owner, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner@test.com", Password: "V@lidPswd1", Name: "Owner",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "InviteTest", Slug: "invite-test", OwnerID: owner.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	invite, err := a.Services.OrgInvite.CreateOrgInvite(ctx, service.CreateOrgInviteInput{
		OrgID: org.ID, Email: "newguy@test.com", Role: domain.OrgRoleMember, InvitedBy: owner.User.ID,
	})
	if err != nil {
		t.Fatalf("CreateOrgInvite failed: %v", err)
	}
	if invite.OrgID != org.ID {
		t.Error("mismatch")
	}

	var dbEmail, dbRole string
	db.QueryRow("SELECT email, role FROM organization_invites WHERE id=?", invite.ID).Scan(&dbEmail, &dbRole)
	if dbEmail != "newguy@test.com" || dbRole != "member" {
		t.Errorf("email=%q role=%q", dbEmail, dbRole)
	}

	invites, err := a.Services.OrgInvite.ListOrgInvites(ctx, org.ID)
	if err != nil {
		t.Fatalf("ListOrgInvites failed: %v", err)
	}
	if len(invites) != 1 {
		t.Errorf("expected 1, got %d", len(invites))
	}

	if err := a.Services.OrgInvite.DeleteOrgInvite(ctx, invite.ID); err != nil {
		t.Fatalf("DeleteOrgInvite failed: %v", err)
	}

	if _, err := a.Services.OrgInvite.ListOrgInvites(ctx, org.ID); err != nil {
		t.Fatal(err)
	}
}

func TestOrg_MaxOrgLimit(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()

	owner, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner@test.com", Password: "V@lidPswd1", Name: "Owner",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	for i := 0; i < 3; i++ {
		slug := "limit-" + string(rune('a'+i))
		if _, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
			Name: slug, Slug: slug, OwnerID: owner.User.ID,
		}); err != nil {
			t.Fatalf("create %d failed: %v", i, err)
		}
	}

	orgs, err := a.Services.Org.ListUserOrgs(ctx, owner.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(orgs) != 3 {
		t.Errorf("expected 3, got %d", len(orgs))
	}
}

func TestOrg_AcceptInvite_AndBecomesMember(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()

	owner, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner@test.com", Password: "V@lidPswd1", Name: "Owner",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	invitee, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "invitee@test.com", Password: "V@lidPswd1", Name: "Invitee",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "AcceptTest", Slug: "accept-test", OwnerID: owner.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	invite, err := a.Services.OrgInvite.CreateOrgInvite(ctx, service.CreateOrgInviteInput{
		OrgID: org.ID, Email: "invitee@test.com", Role: domain.OrgRoleMember, InvitedBy: owner.User.ID,
	})
	if err != nil {
		t.Fatalf("CreateOrgInvite failed: %v", err)
	}
	if invite.RawCode == "" {
		t.Fatal("expected non-empty RawCode on creation")
	}

	// Accept the invite
	if err := a.Services.OrgInvite.AcceptInvite(ctx, service.AcceptInviteInput{
		UserID: invitee.User.ID, RawCode: invite.RawCode,
	}); err != nil {
		t.Fatalf("AcceptInvite failed: %v", err)
	}

	// Verify membership
	m, err := a.Services.Org.GetMembership(ctx, org.ID, invitee.User.ID)
	if err != nil {
		t.Fatalf("GetMembership after accept failed: %v", err)
	}
	if m.Role != domain.OrgRoleMember {
		t.Errorf("role=%q, want member", m.Role)
	}

	// Member count incremented
	var dbCount int
	db.QueryRow("SELECT member_count FROM organizations WHERE id=?", org.ID).Scan(&dbCount)
	if dbCount != 2 {
		t.Errorf("member_count=%d, want 2", dbCount)
	}

	// Invite is claimed (no longer listed)
	invites, err := a.Services.OrgInvite.ListOrgInvites(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(invites) != 0 {
		t.Errorf("expected 0 pending invites, got %d", len(invites))
	}
}

func TestOrg_AcceptInvite_WrongEmail(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openOrgAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()

	owner, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "owner@test.com", Password: "V@lidPswd1", Name: "Owner",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	invitee, aerr := a.Register(ctx, goauth.RegisterInput{
		Email: "wrong@test.com", Password: "V@lidPswd1", Name: "Wrong",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	org, err := a.Services.Org.CreateOrg(ctx, service.CreateOrgInput{
		Name: "EmailMismatch", Slug: "email-mismatch", OwnerID: owner.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	invite, err := a.Services.OrgInvite.CreateOrgInvite(ctx, service.CreateOrgInviteInput{
		OrgID: org.ID, Email: "expected@test.com", Role: domain.OrgRoleMember, InvitedBy: owner.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = a.Services.OrgInvite.AcceptInvite(ctx, service.AcceptInviteInput{
		UserID: invitee.User.ID, RawCode: invite.RawCode,
	})
	if err == nil {
		t.Fatal("expected error for wrong email")
	}
	if err.Error() != domain.ErrOrgInviteEmailMismatch.Error() {
		t.Errorf("expected email mismatch error, got %v", err)
	}
}
