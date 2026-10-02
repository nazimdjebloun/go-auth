package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/oauth2"
)

func TestExchangeRejectsInvalidIdentity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"unauthorized JSON", 401, `{"id":123,"email":"user@example.com"}`},
		{"server error JSON", 500, `{"id":123,"email":"user@example.com"}`},
		{"invalid identity 0", 200, `{}`},
		{"invalid identity 1", 200, `{"id":0}`},
		{"invalid identity 2", 200, `{"id":-1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/token" {
					if _, err := fmt.Fprint(w, `{"access_token":"test-token","token_type":"bearer"}`); err != nil {
						t.Errorf("write token response: %v", err)
					}
					return
				}
				if r.URL.Path != "/user" {
					t.Errorf("unexpected profile request: %s", r.URL.Path)
				}
				w.WriteHeader(tc.status)
				if _, err := fmt.Fprint(w, tc.body); err != nil {
					t.Errorf("write profile response: %v", err)
				}
			}))
			defer server.Close()
			ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{
				Transport: &testTransport{serverURL: server.URL, base: http.DefaultTransport},
			})
			provider := &GitHub{cfg: &oauth2.Config{
				ClientID: "client", ClientSecret: "secret",
				Endpoint: oauth2.Endpoint{TokenURL: server.URL + "/token"},
			}}
			profile, err := provider.Exchange(ctx, "code", "verifier")
			if err == nil || profile != nil {
				t.Fatalf("invalid identity accepted: profile=%+v err=%v", profile, err)
			}
		})
	}
}
