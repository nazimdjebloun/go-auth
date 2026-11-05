package handler

import (
	"context"

	"github.com/nazimdjebloun/go-auth/domain"
)

func (m *mockSessionRepo) LockByID(_ context.Context, id string) (*domain.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, session := range m.sessions {
		if session.ID == id {
			snapshot := *session
			return &snapshot, nil
		}
	}
	return nil, nil
}
