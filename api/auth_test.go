package api

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestChallengeBindingTokenStaysOutOfJSON(t *testing.T) {
	const binding = "private-binding-token"
	results := []struct {
		name  string
		value interface{ BindingToken() string }
	}{
		{"register", NewRegisterResult(RegisterResult{RequiresTwoFactor: true}, binding)},
		{"login", NewLoginResult(LoginResult{RequiresTwoFactor: true}, binding)},
		{"invite", NewCompleteInviteResult(CompleteInviteResult{RequiresTwoFactor: true}, binding)},
		{"oauth", NewOAuthCallbackResult(OAuthCallbackResult{RequiresTwoFactor: true}, binding)},
	}
	for _, tt := range results {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.value.BindingToken(); got != binding {
				t.Fatalf("BindingToken() = %q, want %q", got, binding)
			}
			data, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), binding) {
				t.Fatalf("JSON exposes challenge binding token: %s", data)
			}
		})
	}
}
