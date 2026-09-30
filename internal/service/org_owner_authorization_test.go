package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestOrgAdminCannotCreateOrRemoveOwner(t *testing.T) {
	for _, name := range []string{"add owner", "remove owner"} {
		t.Run(name, func(t *testing.T) {
			svc := newTestOrgService()
			ctx := context.Background()
			org, err := svc.CreateOrg(ctx, api.CreateOrgInput{OwnerID: "owner-1", Name: "Test", Slug: "owner-authority"})
			if err != nil {
				t.Fatal(err)
			}
			for _, input := range []api.AddMemberInput{
				{OrgID: org.ID, UserID: "owner-2", Role: domain.OrgRoleOwner, ActorID: "owner-1"},
				{OrgID: org.ID, UserID: "admin", Role: domain.OrgRoleAdmin, ActorID: "owner-1"},
			} {
				if err := svc.AddMember(ctx, input); err != nil {
					t.Fatal(err)
				}
			}
			if name == "add owner" {
				err = svc.AddMember(ctx, api.AddMemberInput{OrgID: org.ID, UserID: "owner-3", Role: domain.OrgRoleOwner, ActorID: "admin"})
			} else {
				err = svc.RemoveMember(ctx, api.RemoveMemberInput{OrgID: org.ID, UserID: "owner-2", ActorID: "admin"})
			}
			if !errors.Is(err, domain.ErrOrgForbidden) {
				t.Fatalf("owner mutation error=%v, want org_forbidden", err)
			}
			member, err := svc.orgs.GetMembership(ctx, org.ID, "owner-2")
			if err != nil || member == nil || member.Role != domain.OrgRoleOwner {
				t.Fatalf("owner removed: %+v, %v", member, err)
			}
			member, err = svc.orgs.GetMembership(ctx, org.ID, "owner-3")
			if err != nil || member != nil {
				t.Fatalf("owner created: %+v, %v", member, err)
			}
		})
	}
}

type orgAuthorizationTxBoundary struct {
	port.TxManager
	before func() error
}

func (m *orgAuthorizationTxBoundary) WithTx(ctx context.Context, fn func(context.Context) error) error {
	if m.before != nil {
		before := m.before
		m.before = nil
		if err := before(); err != nil {
			return err
		}
	}
	return m.TxManager.WithTx(ctx, fn)
}

func TestOrgMutationChecksCurrentActorAndTargetRoles(t *testing.T) {
	for _, name := range []string{"actor demoted before add", "target promoted before removal"} {
		t.Run(name, func(t *testing.T) {
			f := newPasswordTransactionFixture(t)
			ctx := context.Background()
			now := time.Now().UTC()
			for _, id := range []string{"admin", "target", "new-member"} {
				if err := f.users.Create(ctx, &domain.User{
					ID: id, Email: id + "@example.com", Name: id, Role: domain.RoleUser, CreatedAt: now, UpdatedAt: now,
				}); err != nil {
					t.Fatal(err)
				}
			}
			orgs := sqlstore.NewOrgRepository(f.db)
			svc := NewOrgService(orgs, f.users, f.sessions, f.db, OrgServiceConfig{})
			org, err := svc.CreateOrg(ctx, api.CreateOrgInput{OwnerID: f.userID, Name: "Test", Slug: "sql-owner-authority"})
			if err != nil {
				t.Fatal(err)
			}
			for _, input := range []api.AddMemberInput{
				{OrgID: org.ID, UserID: "admin", Role: domain.OrgRoleAdmin, ActorID: f.userID},
				{OrgID: org.ID, UserID: "target", Role: domain.OrgRoleMember, ActorID: f.userID},
			} {
				if err := svc.AddMember(ctx, input); err != nil {
					t.Fatal(err)
				}
			}
			other := NewOrgService(orgs, f.users, f.sessions, f.db, OrgServiceConfig{})
			svc.txManager = &orgAuthorizationTxBoundary{TxManager: f.db, before: func() error {
				target, newRole := "admin", domain.OrgRoleMember
				if name == "target promoted before removal" {
					target, newRole = "target", domain.OrgRoleOwner
				}
				return other.UpdateMemberRole(ctx, api.UpdateMemberRoleInput{
					OrgID: org.ID, UserID: target, NewRole: newRole, ActorID: f.userID,
				})
			}}
			if name == "actor demoted before add" {
				err = svc.AddMember(ctx, api.AddMemberInput{OrgID: org.ID, UserID: "new-member", Role: domain.OrgRoleMember, ActorID: "admin"})
			} else {
				err = svc.RemoveMember(ctx, api.RemoveMemberInput{OrgID: org.ID, UserID: "target", ActorID: "admin"})
			}
			if !errors.Is(err, domain.ErrOrgForbidden) {
				t.Fatalf("stale authorization error=%v, want org_forbidden", err)
			}
			member, err := orgs.GetMembership(ctx, org.ID, "target")
			if err != nil || member == nil {
				t.Fatalf("rejected mutation removed target: %+v, %v", member, err)
			}
			created, err := orgs.GetMembership(ctx, org.ID, "new-member")
			if err != nil || created != nil {
				t.Fatalf("rejected mutation added member: %+v, %v", created, err)
			}
		})
	}
}
