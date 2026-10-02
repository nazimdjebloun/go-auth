package testutil

import (
	"encoding/json"
	"maps"
	"slices"

	"github.com/nazimdjebloun/go-auth/domain"
)

func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneUser(user *domain.User) *domain.User {
	if user == nil {
		return nil
	}
	cloned := *user
	cloned.PasswordHash = clonePointer(user.PasswordHash)
	cloned.PasswordPepperVersion = clonePointer(user.PasswordPepperVersion)
	cloned.VerifiedAt = clonePointer(user.VerifiedAt)
	cloned.BannedAt = clonePointer(user.BannedAt)
	cloned.LastLoginAt = clonePointer(user.LastLoginAt)
	return &cloned
}

// Preserve ID/hash/email aliases, including aliases across a session's maps.
func aliasMapCloner[T any](clone func(*T) *T) func(map[string]*T) map[string]*T {
	copies := make(map[*T]*T)
	return func(values map[string]*T) map[string]*T {
		result := make(map[string]*T, len(values))
		for key, value := range values {
			cloned, ok := copies[value]
			if !ok {
				cloned = clone(value)
				copies[value] = cloned
			}
			result[key] = cloned
		}
		return result
	}
}

func (m *MockUserRepo) mockSnapshot() func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	users := aliasMapCloner(cloneUser)(m.users)
	claims := maps.Clone(m.claimedSetPassTokens)
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.users, m.claimedSetPassTokens = users, claims
	}
}

func (m *MockTokenRepo) mockSnapshot() func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	tokens := aliasMapCloner(func(token *domain.VerificationToken) *domain.VerificationToken {
		cloned := *token
		cloned.UserID = clonePointer(token.UserID)
		cloned.UsedAt = clonePointer(token.UsedAt)
		cloned.CodeVerifier = clonePointer(token.CodeVerifier)
		return &cloned
	})(m.tokens)
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.tokens = tokens
	}
}

func (m *MockSessionRepo) mockSnapshot() func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	cloneMap := aliasMapCloner(func(session *domain.Session) *domain.Session {
		cloned := *session
		cloned.ParsedUA = clonePointer(session.ParsedUA)
		cloned.RefreshRotatedAt = clonePointer(session.RefreshRotatedAt)
		cloned.RevokedAt = clonePointer(session.RevokedAt)
		cloned.TwoFactorVerifiedAt = clonePointer(session.TwoFactorVerifiedAt)
		cloned.ActiveOrgID = clonePointer(session.ActiveOrgID)
		cloned.ActiveOrgRole = clonePointer(session.ActiveOrgRole)
		return &cloned
	})
	sessions, ids, refresh := cloneMap(m.sessions), cloneMap(m.byID), cloneMap(m.byRefreshHash)
	calls := slices.Clone(m.ClearActiveOrgCalls)
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.sessions, m.byID, m.byRefreshHash = sessions, ids, refresh
		m.ClearActiveOrgCalls = calls
	}
}

func (m *MockInviteRepo) mockSnapshot() func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	invites := aliasMapCloner(func(invite *domain.Invite) *domain.Invite {
		cloned := *invite
		cloned.AcceptedAt = clonePointer(invite.AcceptedAt)
		return &cloned
	})(m.invites)
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.invites = invites
	}
}

func (m *MockProviderAccountRepo) mockSnapshot() func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	accounts := aliasMapCloner(func(account *domain.ProviderAccount) *domain.ProviderAccount {
		cloned := *account
		cloned.TokenExpiresAt = clonePointer(account.TokenExpiresAt)
		return &cloned
	})(m.accounts)
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.accounts = accounts
	}
}

func (m *MockOrgRepo) mockSnapshot() func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	orgs := aliasMapCloner(func(org *domain.Organization) *domain.Organization {
		cloned := *org
		cloned.CreatedBy = clonePointer(org.CreatedBy)
		if org.Metadata != nil {
			cloned.Metadata = nil
			// SQL metadata is JSON. Reject invalid fixtures rather than leave
			// nested maps or slices sharing mutable state with the snapshot.
			data, err := json.Marshal(org.Metadata)
			if err != nil {
				panic(err)
			}
			if err := json.Unmarshal(data, &cloned.Metadata); err != nil {
				panic(err)
			}
		}
		return &cloned
	})(m.orgs)
	members := aliasMapCloner(clonePointer[domain.OrgMember])(m.members)
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.orgs, m.members = orgs, members
	}
}

func (m *MockOrgInviteRepo) mockSnapshot() func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	invites := aliasMapCloner(clonePointer[domain.OrgInvite])(m.invites)
	return func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		m.invites = invites
	}
}
