package service

import (
	"context"
	"errors"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/port"
)

type orgRemovalGuardUsers struct {
	port.UserRepository
	active bool
	calls  int
}

func (r *orgRemovalGuardUsers) WithAdminGuard(ctx context.Context, fn func(context.Context) error) error {
	r.calls++
	return r.UserRepository.WithAdminGuard(ctx, func(ctx context.Context) error {
		r.active = true
		defer func() { r.active = false }()
		return fn(ctx)
	})
}

type orgRemovalGuardStore struct {
	port.OrgRepository
	users *orgRemovalGuardUsers
}

func (r *orgRemovalGuardStore) LockMembership(ctx context.Context, orgID, userID string) (*domain.OrgMember, error) {
	if !r.users.active {
		return nil, errors.New("membership locked before account mutation guard")
	}
	return r.OrgRepository.LockMembership(ctx, orgID, userID)
}

func TestOrgPermissionsDisabledRemovalAcquiresUserGuardFirst(t *testing.T) {
	for _, self := range []bool{false, true} {
		for _, role := range []domain.OrgRole{domain.OrgRoleMember, domain.OrgRoleOwner} {
			name := "other/" + string(role)
			if self {
				name = "self/" + string(role)
			}
			t.Run(name, func(t *testing.T) {
				f := newOrgPermissionFixture(t)
				target := f.member(t, role)
				actor := f.owner
				if self {
					actor = target
				}
				users := &orgRemovalGuardUsers{UserRepository: f.s.users}
				orgs := &orgRemovalGuardStore{OrgRepository: f.org.orgs, users: users}
				legacy := NewOrgService(
					orgs,
					users,
					sqlstore.NewSessionRepository(f.db),
					f.db,
					OrgServiceConfig{RoleAssignments: f.repo},
				)
				if err := legacy.RemoveMember(t.Context(), api.RemoveMemberInput{
					OrgID: target.OrgID, UserID: target.UserID, ActorID: actor.UserID,
				}); err != nil {
					t.Fatal(err)
				}
				if users.calls != 1 || users.active {
					t.Fatalf("account guard calls=%d active=%t", users.calls, users.active)
				}
				member, err := f.org.orgs.GetMembership(t.Context(), target.OrgID, target.UserID)
				if err != nil || member != nil {
					t.Fatalf("removal did not commit: member=%+v error=%v", member, err)
				}
			})
		}
	}
}
