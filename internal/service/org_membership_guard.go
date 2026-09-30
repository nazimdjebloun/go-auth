package service

import (
	"context"

	"github.com/nazimdjebloun/go-auth/domain"
)

func requireOrgRole(member *domain.OrgMember, minimum domain.OrgRole) error {
	if member == nil {
		return domain.ErrOrgMemberNotFound
	}
	if member.Role.Weight() < minimum.Weight() {
		return domain.ErrOrgForbidden
	}
	return nil
}

// lockActorAndTarget reads current roles and holds both memberships through the
// mutation. Stable ordering avoids deadlocks for reciprocal member operations.
func (s *OrgService) lockActorAndTarget(ctx context.Context, orgID, actorID, targetID string) (*domain.OrgMember, *domain.OrgMember, error) {
	if actorID == "" {
		return nil, nil, domain.ErrForbidden
	}
	ids := []string{actorID}
	if targetID != actorID {
		ids = append(ids, targetID)
		if ids[1] < ids[0] {
			ids[0], ids[1] = ids[1], ids[0]
		}
	}
	members := make(map[string]*domain.OrgMember, len(ids))
	for _, id := range ids {
		member, err := s.orgs.LockMembership(ctx, orgID, id)
		if err != nil {
			return nil, nil, err
		}
		if member != nil {
			snapshot := *member
			member = &snapshot
		}
		members[id] = member
	}
	return members[actorID], members[targetID], nil
}
