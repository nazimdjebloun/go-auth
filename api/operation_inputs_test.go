package api

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestOperationInputsDoNotSerializeTransportCredentials(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  string
	}{
		{
			name: "oauth callback",
			input: OAuthCallbackInput{
				Provider: "provider", Code: "code", State: "state",
				BrowserState: "cookie-state", SessionToken: "secret-token", IP: "127.0.0.1", UserAgent: "client",
			},
			want: `{"provider":"provider","code":"code","state":"state"}`,
		},
		{
			name: "oauth link",
			input: OAuthLinkInput{
				Provider: "provider", UserID: "user", SessionTokenHash: "secret-hash",
			},
			want: `{"provider":"provider"}`,
		},
		{
			name: "two factor verify",
			input: TwoFactorVerifyInput{
				ChallengeID: "challenge", Code: "123456", BindingToken: "secret-binding", IP: "127.0.0.1", UserAgent: "client",
			},
			want: `{"challengeId":"challenge","code":"123456"}`,
		},
		{
			name:  "two factor resend",
			input: TwoFactorResendInput{ChallengeID: "challenge", BindingToken: "secret-binding"},
			want:  `{"challengeId":"challenge"}`,
		},
		{
			name: "two factor enable",
			input: TwoFactorEnableInput{
				UserID: "user", Password: "password", CallerSessionID: "session", KeepOtherSessions: false,
			},
			want: `{"password":"password","keepOtherSessions":false}`,
		},
		{
			name:  "session creation",
			input: CreateSessionInput{UserID: "user", IP: "127.0.0.1", UserAgent: "client"},
			want:  `{}`,
		},
		{
			name:  "session activity",
			input: TouchSessionInput{Token: "secret-token", LastActiveAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
			want:  `{}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != tt.want {
				t.Fatalf("JSON = %s, want %s", data, tt.want)
			}
		})
	}
}

func TestOperationInputsDoNotAcceptTrustedContextFromJSON(t *testing.T) {
	// Even a custom transport that decodes directly into operation inputs must
	// supply the identity, cookie binding, and client metadata independently.
	payload := []byte(`{
		"userId":"attacker", "actorId":"attacker", "sessionToken":"attacker",
		"sessionTokenHash":"attacker", "browserState":"attacker", "bindingToken":"attacker",
		"ip":"spoofed", "userAgent":"spoofed", "callerSessionId":"attacker",
		"token":"attacker", "lastActiveAt":"2026-01-01T00:00:00Z"
	}`)
	inputs := []any{
		ChangeNameInput{}, DeleteAccountInput{}, CreateSessionInput{}, TouchSessionInput{},
		RevokeSessionForUserInput{}, RevokeSessionsForUserInput{}, RevokeAllSessionsExceptInput{}, ListSessionsInput{},
		OAuthLinkInput{}, OAuthCallbackInput{}, OAuthUnlinkInput{},
		TwoFactorVerifyInput{}, TwoFactorResendInput{}, TwoFactorEnableInput{}, TwoFactorDisableInput{},
		HardDeleteInviteInput{}, RevokeInviteInput{}, ResendInviteEmailInput{},
		DeleteOrgInviteInput{}, ResendOrgInviteEmailInput{},
	}
	for _, input := range inputs {
		inputType := reflect.TypeOf(input)
		t.Run(inputType.Name(), func(t *testing.T) {
			decoded := reflect.New(inputType)
			if err := json.Unmarshal(payload, decoded.Interface()); err != nil {
				t.Fatal(err)
			}
			if !decoded.Elem().IsZero() {
				t.Fatalf("JSON supplied trusted context: %+v", decoded.Elem().Interface())
			}
		})
	}
}
