package integration_test

import (
	"context"
	"errors"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"testing"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
)

func TestVerification_UserUpdateFailureRollsBackTokenClaim(t *testing.T) {
	db, closeDB := newTestDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth2FA(t, db, mailer, goauth.TwoFactorConfig{}, goauth.RegistrationConfig{
		RequireEmailVerification: true,
	})
	defer a.Close()
	ctx := context.Background()

	registered, err := a.Register(ctx, api.RegisterInput{
		Email: "verify-rollback@example.com", Password: "Passw0rd!", Name: "Verify Rollback",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !registered.RequiresVerification {
		t.Fatal("expected registration to require verification")
	}
	code := extractCodeAfter(mailer.lastBody(), "Your code: ")
	if code == "" {
		t.Fatal("could not extract verification code")
	}

	removeFailure := testdb.FailWrites(t, db, "block_email_verification", "users", "UPDATE", "")

	if _, err := a.Services().Verify.VerifyEmail(ctx, code); !errors.Is(err, domain.ErrInternal) {
		t.Fatalf("verification error = %v, want internal_error", err)
	}
	removeFailure()

	user, err := a.Services().Verify.VerifyEmail(ctx, code)
	if err != nil {
		t.Fatalf("verification token was not rolled back with the failed user update: %v", err)
	}
	if !user.IsVerified {
		t.Fatal("expected user to be verified after retry")
	}
}
