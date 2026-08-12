package service

import (
	"context"
	"testing"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

// TestSuccessPaths_ReturnTrueNilError guards the typed-nil interface trap
// this package's error-unification pass had to get right: every method
// converted from returning *domain.AuthError to error now has to return a
// literal nil error interface on success, not a nil *domain.AuthError
// boxed into one — the latter makes `err != nil` true even though nothing
// failed. `err == nil` below is the exact check that would go wrong first;
// a plain "no error logged" assertion would not catch it.
//
// Auth.Register and Auth.Login (goauth package) have their own equivalent
// coverage in auth_test.go, since the root wrappers pass the same error
// straight through.
func TestSuccessPaths_ReturnTrueNilError(t *testing.T) {
	t.Run("AdminService.BanUser", func(t *testing.T) {
		users := testutil.NewMockUserRepo()
		sessions := testutil.NewMockSessionRepo()
		svc := newTestAdminService(users, sessions, &testutil.MockHasher{})
		users.Create(context.Background(), &domain.User{ID: "u1", Email: "a@example.com"})

		if err := svc.BanUser(context.Background(), "u1"); err != nil {
			t.Fatalf("err == nil check failed: got %v (%T)", err, err)
		}
	})

	t.Run("PasswordService.ChangePassword", func(t *testing.T) {
		users := testutil.NewMockUserRepo()
		tokens := testutil.NewMockTokenRepo()
		hasher := &testutil.MockHasher{}
		svc := newTestPasswordService(users, tokens, hasher, nil)

		hash, _ := hasher.Hash("OldPassw0rd!")
		users.Create(context.Background(), &domain.User{ID: "u1", Email: "a@example.com", PasswordHash: &hash})

		err := svc.ChangePassword(context.Background(), ChangePasswordInput{
			UserID:      "u1",
			OldPassword: "OldPassw0rd!",
			NewPassword: "NewPassw0rd!",
		})
		if err != nil {
			t.Fatalf("err == nil check failed: got %v (%T)", err, err)
		}
	})
}
