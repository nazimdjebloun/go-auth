package service

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

type adminLookupFailureRepo struct {
	port.UserRepository
	failure     error
	afterGuard  bool
	targetReads int
}

func (r *adminLookupFailureRepo) GetByID(ctx context.Context, id string) (*domain.User, error) {
	if id == "target" {
		r.targetReads++
		if !r.afterGuard || r.targetReads > 1 {
			return nil, r.failure
		}
		return &domain.User{ID: id, Role: domain.RoleUser}, nil
	}
	return r.UserRepository.GetByID(ctx, id)
}

type adminGuardLookupFailureRepo struct{ *adminLookupFailureRepo }

func (r *adminGuardLookupFailureRepo) WithAdminGuard(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}
func (r *adminGuardLookupFailureRepo) DeleteWithAdminGuard(context.Context, string) (bool, error) {
	return false, nil
}
func (r *adminGuardLookupFailureRepo) BanWithAdminGuard(context.Context, string, bool, *time.Time, time.Time) (bool, error) {
	return false, nil
}
func (r *adminGuardLookupFailureRepo) DemoteWithAdminGuard(context.Context, string, domain.Role, time.Time) (bool, error) {
	return false, nil
}

func TestAdminTargetLookupErrors(t *testing.T) {
	operations := []struct {
		name string
		run  func(*AdminService, string) error
	}{
		{"ban", func(s *AdminService, a string) error {
			return s.BanUser(t.Context(), BanUserInput{UserID: "target", ActorID: a})
		}},
		{"unban", func(s *AdminService, a string) error {
			return s.UnbanUser(t.Context(), UnbanUserInput{UserID: "target", ActorID: a})
		}},
		{"role", func(s *AdminService, a string) error {
			return s.UpdateUserRole(t.Context(), UpdateUserRoleInput{UserID: "target", ActorID: a, Role: "user"})
		}},
		{"delete", func(s *AdminService, a string) error {
			return s.DeleteUser(t.Context(), DeleteUserInput{UserID: "target", ActorID: a})
		}},
		{"detail", func(s *AdminService, a string) error {
			_, err := s.GetUserDetail(t.Context(), GetUserDetailInput{UserID: "target", ActorID: a})
			return err
		}},
		{"revoke all", func(s *AdminService, a string) error {
			return s.RevokeUserSessions(t.Context(), RevokeUserSessionsInput{UserID: "target", ActorID: a})
		}},
		{"list sessions", func(s *AdminService, a string) error {
			_, _, err := s.ListUserSessions(t.Context(), AdminListUserSessionsInput{UserID: "target", ActorID: a})
			return err
		}},
		{"revoke session", func(s *AdminService, a string) error {
			return s.RevokeUserSession(t.Context(), RevokeUserSessionInput{UserID: "target", ActorID: a, SessionID: "session"})
		}},
	}
	backend := errors.New("database unavailable")
	for _, op := range operations {
		for _, failure := range []struct {
			name string
			err  error
		}{
			{"backend", backend}, {"canceled", context.Canceled}, {"absent", nil}, {"not found", fmt.Errorf("lookup: %w", domain.ErrUserNotFound)},
		} {
			t.Run(op.name+"/"+failure.name, func(t *testing.T) {
				users := testutil.NewMockUserRepo()
				svc, actor := newTestAdminService(users, testutil.NewMockSessionRepo(), &testutil.MockHasher{})
				// Nil session collaborators make accidental continuation fail loudly.
				svc.sessions = nil
				svc.sessionSvc = nil
				svc.providers = nil
				svc.users = &adminLookupFailureRepo{UserRepository: users, failure: failure.err}
				err := op.run(svc, actor)
				if failure.err == nil || errors.Is(failure.err, domain.ErrUserNotFound) {
					if !errors.Is(err, domain.ErrUserNotFound) {
						t.Fatalf("got %v, want not found", err)
					}
				} else if !errors.Is(err, failure.err) || errors.Is(err, domain.ErrUserNotFound) {
					t.Fatalf("backend cause not preserved: %v", err)
				}
			})
		}
	}
	for _, op := range operations {
		if op.name != "ban" && op.name != "role" && op.name != "delete" {
			continue
		}
		t.Run(op.name+"/guard recheck", func(t *testing.T) {
			users := testutil.NewMockUserRepo()
			svc, actor := newTestAdminService(users, testutil.NewMockSessionRepo(), &testutil.MockHasher{})
			repo := &adminGuardLookupFailureRepo{&adminLookupFailureRepo{UserRepository: users, failure: backend, afterGuard: true}}
			svc.users = repo
			err := op.run(svc, actor)
			if !errors.Is(err, backend) {
				t.Fatalf("guard recheck lost cause: %v", err)
			}
			if repo.targetReads != 2 {
				t.Fatalf("reads=%d", repo.targetReads)
			}
		})
	}
}
