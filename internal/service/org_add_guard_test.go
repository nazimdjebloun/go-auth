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

type orgAddGuardStore struct {
	port.OrgRepository
	users *orgRemovalGuardUsers
}

func (r *orgAddGuardStore) LockMembership(ctx context.Context, orgID, userID string) (*domain.OrgMember, error) {
	if !r.users.active {
		return nil, errors.New("membership locked before account mutation guard")
	}
	return r.OrgRepository.LockMembership(ctx, orgID, userID)
}

func (r *orgAddGuardStore) IncrementUserOrgOwnerCount(ctx context.Context, userID string, maxOrgs int) error {
	if !r.users.active {
		return errors.New("owner count changed before account mutation guard")
	}
	return r.OrgRepository.IncrementUserOrgOwnerCount(ctx, userID, maxOrgs)
}

func (r *orgAddGuardStore) IncrementOrgMemberCount(ctx context.Context, orgID string, maxMembers int) error {
	if !r.users.active {
		return errors.New("organization changed before account mutation guard")
	}
	return r.OrgRepository.IncrementOrgMemberCount(ctx, orgID, maxMembers)
}

func (r *orgAddGuardStore) AddMember(ctx context.Context, member *domain.OrgMember) error {
	if !r.users.active {
		return errors.New("membership inserted before account mutation guard")
	}
	return r.OrgRepository.AddMember(ctx, member)
}

func TestOrgPermissionsMemberAddsAcquireUserGuardFirst(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, admin := range []bool{false, true} {
			for _, role := range []domain.OrgRole{domain.OrgRoleMember, domain.OrgRoleAdmin, domain.OrgRoleOwner} {
				for _, rollback := range []bool{false, true} {
					name := "disabled/member/" + string(role) + "/commit"
					if enabled {
						name = "enabled/member/" + string(role) + "/commit"
					}
					if admin {
						name += "/platform-admin"
					}
					if rollback {
						name += "/audit-rollback"
					}
					t.Run(name, func(t *testing.T) {
						f := newOrgPermissionFixture(t)
						target := f.account(t)
						actorID := f.owner.UserID
						if admin {
							actor := f.account(t)
							actorID = actor.UserID
							if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET role=$1 WHERE id=$2", domain.RoleAdmin, actorID); err != nil {
								t.Fatal(err)
							}
						}
						users := &orgRemovalGuardUsers{UserRepository: f.s.users}
						orgs := &orgAddGuardStore{OrgRepository: f.org.orgs, users: users}
						cfg := OrgServiceConfig{RoleAssignments: f.repo}
						if enabled {
							f.s.users = users
							f.s.orgs = orgs
							cfg.OrgPermissions = f.s
						}
						if rollback {
							cfg.Audit = rejectingOrgAudit{}
						}
						svc := NewOrgService(orgs, users, sqlstore.NewSessionRepository(f.db), f.db, cfg)
						ctx := t.Context()
						if role == domain.OrgRoleOwner && !rollback {
							// A different organization's scope must not bypass this guard.
							ctx = context.WithValue(ctx, orgManagementContextKey{}, generateID())
						}
						var err error
						if admin {
							err = svc.AdminAddMember(ctx, api.AdminAddMemberInput{
								OrgID: f.owner.OrgID, UserID: target.UserID, Role: role, ActorID: actorID,
							})
						} else {
							err = svc.AddMember(ctx, api.AddMemberInput{
								OrgID: f.owner.OrgID, UserID: target.UserID, Role: role, ActorID: actorID,
							})
						}
						if rollback {
							if err == nil || err.Error() != "audit unavailable" {
								t.Fatalf("audit failure error=%v", err)
							}
						} else if err != nil {
							t.Fatal(err)
						}
						if users.calls != 1 || users.active {
							t.Fatalf("account guard calls=%d active=%t", users.calls, users.active)
						}
						member, err := f.org.orgs.GetMembership(t.Context(), f.owner.OrgID, target.UserID)
						if err != nil {
							t.Fatal(err)
						}
						if rollback {
							if member != nil {
								t.Fatalf("failed add committed membership: %+v", member)
							}
						} else if member == nil || member.Role != role {
							t.Fatalf("added membership=%+v, want role %s", member, role)
						}
						org, err := f.org.orgs.GetByID(t.Context(), f.owner.OrgID)
						if err != nil {
							t.Fatal(err)
						}
						user, err := users.GetByID(t.Context(), target.UserID)
						if err != nil {
							t.Fatal(err)
						}
						members, owners, owned := 1, 1, 0
						if !rollback {
							members++
							if role == domain.OrgRoleOwner {
								owners++
								owned++
							}
						}
						if org.MemberCount != members || org.OwnerCount != owners || user.OrgOwnerCount != owned {
							t.Fatalf("counters: members=%d owners=%d owned=%d, want %d/%d/%d",
								org.MemberCount, org.OwnerCount, user.OrgOwnerCount, members, owners, owned)
						}
					})
				}
			}
		}
	}
}
