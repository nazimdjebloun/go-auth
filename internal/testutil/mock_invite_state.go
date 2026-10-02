package testutil

import (
	"context"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// Revoke changes only a pending or expired invite to revoked.
func (m *MockInviteRepo) Revoke(ctx context.Context, id string) (bool, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	invite := m.invites[id]
	if invite == nil || (invite.Status != domain.InvitePending && invite.Status != domain.InviteExpired) {
		return false, nil
	}
	invite.Status = domain.InviteRevoked
	return true, nil
}

// RotateCode replaces the expected code only while an invite remains reusable.
func (m *MockInviteRepo) RotateCode(ctx context.Context, id, expectedCode, newCode string, expiresAt time.Time) (bool, error) {
	recordMockTx(ctx, m)
	m.mu.Lock()
	defer m.mu.Unlock()
	invite := m.invites[id]
	if invite == nil || invite.Code != expectedCode || (invite.Status != domain.InvitePending && invite.Status != domain.InviteExpired) {
		return false, nil
	}
	delete(m.invites, invite.Code)
	invite.Code, invite.ExpiresAt, invite.Status = newCode, expiresAt, domain.InvitePending
	m.invites[newCode] = invite
	return true, nil
}
