package service

import (
	"errors"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

func TestFixedOrgInvitesRequireCurrentAuthority(t *testing.T) {
	for _, tc := range []struct {
		name    string
		role    domain.OrgRole
		actor   string
		revoke  string
		accept  bool
		expired bool
		denied  bool
	}{
		{name: "admin cannot renew expired owner invite", role: domain.OrgRoleOwner, actor: "admin", expired: true, denied: true},
		{name: "owner cannot renew demoted issuer delegation", role: domain.OrgRoleOwner, actor: "owner", revoke: "demote", denied: true},
		{name: "accept rejects demoted owner issuer", role: domain.OrgRoleOwner, revoke: "demote", accept: true, denied: true},
		{name: "accept rejects removed issuer", role: domain.OrgRoleMember, revoke: "remove", accept: true, denied: true},
		{name: "admin renews member invite", role: domain.OrgRoleMember, actor: "admin", expired: true},
		{name: "owner renews owner invite", role: domain.OrgRoleOwner, actor: "owner", expired: true},
		{name: "current owner delegation accepts", role: domain.OrgRoleOwner, accept: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPasswordTransactionFixture(t)
			ctx := t.Context()
			now := time.Now().UTC()
			ids := map[string]string{
				"admin":     "00000000-0000-4000-8000-000000000201",
				"owner":     "00000000-0000-4000-8000-000000000202",
				"recipient": "00000000-0000-4000-8000-000000000203",
			}
			for name, id := range ids {
				if err := f.users.Create(ctx, &domain.User{ID: id, Email: name + "@example.com", Name: name, Role: domain.RoleUser, CreatedAt: now, UpdatedAt: now}); err != nil {
					t.Fatal(err)
				}
			}
			orgs := sqlstore.NewOrgRepository(f.db)
			invites := sqlstore.NewOrgInviteRepository(f.db)
			orgSvc := NewOrgService(orgs, f.users, f.sessions, f.db, OrgServiceConfig{})
			mail := &testutil.MockMailer{}
			svc := NewOrgInviteService(invites, orgs, f.users, f.db, nil, mail, OrgInviteServiceConfig{InviteTTL: time.Hour, BaseURL: "https://app.example.com"})
			org, err := orgSvc.CreateOrg(ctx, api.CreateOrgInput{Name: "Authority", Slug: "authority", OwnerID: f.userID})
			if err != nil {
				t.Fatal(err)
			}
			for name, role := range map[string]domain.OrgRole{"admin": domain.OrgRoleAdmin, "owner": domain.OrgRoleOwner} {
				if err := orgSvc.AddMember(ctx, api.AddMemberInput{OrgID: org.ID, UserID: ids[name], Role: role, ActorID: f.userID}); err != nil {
					t.Fatal(err)
				}
			}
			invite, err := svc.CreateOrgInvite(ctx, api.CreateOrgInviteInput{OrgID: org.ID, Email: "recipient@example.com", Role: tc.role, InvitedBy: f.userID})
			if err != nil {
				t.Fatal(err)
			}
			if tc.expired {
				invite.ExpiresAt = now.Add(-time.Minute)
				if err := invites.Update(ctx, invite); err != nil {
					t.Fatal(err)
				}
			}
			switch tc.revoke {
			case "demote":
				err = orgSvc.UpdateMemberRole(ctx, api.UpdateMemberRoleInput{OrgID: org.ID, UserID: f.userID, ActorID: ids["owner"], NewRole: domain.OrgRoleMember})
			case "remove":
				err = orgSvc.RemoveMember(ctx, api.RemoveMemberInput{OrgID: org.ID, UserID: f.userID, ActorID: ids["owner"]})
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := orgs.GetByID(ctx, org.ID)
			if err != nil {
				t.Fatal(err)
			}
			if tc.accept {
				err = svc.AcceptInvite(ctx, api.AcceptInviteInput{UserID: ids["recipient"], RawCode: invite.RawCode})
			} else {
				err = svc.ResendOrgInviteEmail(ctx, api.ResendOrgInviteEmailInput{OrgID: org.ID, InviteID: invite.ID, ActorID: ids[tc.actor]})
			}
			if tc.denied {
				if !errors.Is(err, domain.ErrOrgForbidden) {
					t.Fatalf("delegation error=%v, want org_forbidden", err)
				}
				stored, err := invites.GetByID(ctx, invite.ID)
				if err != nil || stored == nil || stored.CodeHash != invite.CodeHash || !stored.ExpiresAt.Equal(invite.ExpiresAt) {
					t.Fatalf("denied request changed invitation: %+v, %v", stored, err)
				}
				member, err := orgs.GetMembership(ctx, org.ID, ids["recipient"])
				if err != nil || member != nil || mail.SentCount() != 1 {
					t.Fatalf("denied request granted access or sent mail: %+v, %v, mails=%d", member, err, mail.SentCount())
				}
				after, err := orgs.GetByID(ctx, org.ID)
				if err != nil || after.MemberCount != before.MemberCount || after.OwnerCount != before.OwnerCount {
					t.Fatalf("denied request changed counters: %+v, %v", after, err)
				}
			} else if err != nil {
				t.Fatal(err)
			} else if tc.accept {
				member, err := orgs.GetMembership(ctx, org.ID, ids["recipient"])
				if err != nil || member == nil || member.Role != tc.role {
					t.Fatalf("accepted role=%+v, err=%v", member, err)
				}
			} else if mail.SentCount() != 2 {
				t.Fatal("authorized renewal did not deliver mail")
			}
		})
	}
}

func TestFixedOrgInviteCreationRechecksAuthority(t *testing.T) {
	orgSvc, svc := newTestOrgInviteService()
	ctx := t.Context()
	org, err := orgSvc.CreateOrg(ctx, api.CreateOrgInput{Name: "Authority", Slug: "authority", OwnerID: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	if err := orgSvc.AddMember(ctx, api.AddMemberInput{OrgID: org.ID, UserID: "admin", Role: domain.OrgRoleAdmin, ActorID: "owner"}); err != nil {
		t.Fatal(err)
	}
	svc.txManager = &orgAuthorizationTxBoundary{TxManager: svc.txManager, before: func() error {
		return orgSvc.UpdateMemberRole(ctx, api.UpdateMemberRoleInput{OrgID: org.ID, UserID: "admin", ActorID: "owner", NewRole: domain.OrgRoleMember})
	}}
	if _, err := svc.CreateOrgInvite(ctx, api.CreateOrgInviteInput{OrgID: org.ID, InvitedBy: "admin", Email: "recipient@example.com", Role: domain.OrgRoleMember}); !errors.Is(err, domain.ErrOrgForbidden) {
		t.Fatalf("stale authority issued invite: %v", err)
	}
}
