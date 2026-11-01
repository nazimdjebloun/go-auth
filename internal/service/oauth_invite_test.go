package service

import (
	"errors"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

func TestOAuthInvitationRequiresOTPPepper(t *testing.T) {
	f := newOAuthInviteFixture(t, false)
	f.svc.twoFactorSvc.config.OTPPepper = nil
	if result, err := f.callback(t); !errors.Is(err, domain.ErrInternal) || result != nil {
		t.Fatalf("missing OTP pepper must refuse a challenge: result nil=%t err=%v", result == nil, err)
	}
	if f.mailer.SentCount() != 0 {
		t.Fatal("missing OTP pepper sent a verification code")
	}
	var proofs int
	if err := f.f.db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM verification_tokens WHERE type=$1", domain.TokenInviteVerify).Scan(&proofs); err != nil {
		t.Fatal(err)
	}
	if proofs != 0 {
		t.Fatal("missing OTP pepper persisted a verification challenge")
	}
	invite, err := f.invites.GetByID(t.Context(), f.invite.ID)
	if err != nil || invite.Status != domain.InvitePending {
		t.Fatalf("missing OTP pepper consumed the invitation: %+v %v", invite, err)
	}
	user, err := f.f.users.GetByEmail(t.Context(), f.invite.Email)
	if err != nil || user != nil {
		t.Fatalf("missing OTP pepper created an account: %+v %v", user, err)
	}
}

func TestOAuthInvitationBindingPolicy(t *testing.T) {
	for _, tc := range []struct {
		name       string
		disabled   bool
		missingKey bool
		binding    string
		wantValid  bool
	}{
		{name: "matching binding", binding: "matching", wantValid: true},
		{name: "missing binding"},
		{name: "incorrect binding", binding: "incorrect"},
		{name: "missing key", binding: "matching", missingKey: true},
		{name: "internal binding disabled", disabled: true, wantValid: true},
		{name: "internal binding disabled without key", disabled: true, missingKey: true, wantValid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOAuthInviteFixture(t, false)
			f.svc.twoFactorSvc.config.DisableTwoFactorChallengeBinding = tc.disabled
			proof, err := f.callback(t)
			if err != nil {
				t.Fatal(err)
			}
			input := api.OAuthInviteVerifyInput{ChallengeID: proof.InviteChallengeID, Code: testutil.GetLastVerificationCode(f.mailer)}
			switch tc.binding {
			case "matching":
				input.BindingToken = proof.BindingToken()
			case "incorrect":
				input.BindingToken = "incorrect"
			}
			if tc.missingKey {
				f.svc.twoFactorSvc.config.TwoFactorBindingKey = nil
			}
			result, err := f.svc.VerifyInviteEmail(t.Context(), input)
			if tc.wantValid {
				if err != nil || result == nil || result.SessionToken == "" || !result.IsNewUser {
					t.Fatalf("valid proof did not complete signup: result nil=%t err=%v", result == nil, err)
				}
				return
			}
			if !errors.Is(err, domain.ErrVerificationCodeInvalid) || result != nil {
				t.Fatalf("invalid binding was accepted: result nil=%t err=%v", result == nil, err)
			}
			token, err := f.f.tokens.GetByID(t.Context(), proof.InviteChallengeID)
			if err != nil || token == nil || token.UsedAt != nil || token.Attempts != 0 {
				t.Fatalf("binding rejection changed the proof: %+v %v", token, err)
			}
			user, err := f.f.users.GetByEmail(t.Context(), f.invite.Email)
			if err != nil || user != nil {
				t.Fatalf("binding rejection created an account: %+v %v", user, err)
			}
		})
	}
}
