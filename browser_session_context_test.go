package goauth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/ratelimit"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"golang.org/x/crypto/bcrypt"
)

// Both frontends deliberately share one API host and one browser cookie jar.
func TestBrowserSessionContexts_IndependentOnOneAPIHost(t *testing.T) {
	f := newAppHTTPFixture(t, true, false, WithRateLimitRoute("POST /auth/admin/login", ratelimit.Rate{Requests: 20, Window: time.Minute}))
	hash, err := bcrypt.GenerateFromPassword([]byte("Passw0rd!"), 4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET password_hash=$1 WHERE id=$2", string(hash), f.admin.UserID); err != nil {
		t.Fatal(err)
	}
	adminUser, err := f.users.GetByID(t.Context(), f.admin.UserID)
	if err != nil {
		t.Fatal(err)
	}
	email := uuid.NewString() + "@example.com"
	user, err := f.a.Services().Auth.Register(t.Context(), api.RegisterInput{Email: email, Name: "App user", Password: "Passw0rd!"})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(f.mux)
	defer server.Close()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := server.Client()
	client.Jar = jar
	base, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	tokens := map[string]string{}
	request := func(scope, method, path string, body any, want int) map[string]any {
		t.Helper()
		var encoded []byte
		if body != nil {
			encoded, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		r, err := http.NewRequest(method, server.URL+path, bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Origin", "http://localhost")
		if scope != "" {
			r.Header.Set("X-GoAuth-Session", scope)
		}
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if method != "GET" {
			r.Header.Set("X-CSRF-Token", tokens[scope])
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		data, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Fatalf("%s %s context=%q: status=%d want=%d body=%s", method, path, scope, response.StatusCode, want, data)
		}
		if replacement := response.Header.Get("X-CSRF-Token"); replacement != "" {
			tokens[scope] = replacement
		}
		var decoded map[string]any
		if len(data) > 0 {
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
		}
		if path == "/auth/csrf-token" && want == 200 {
			tokens[scope] = decoded["token"].(string)
		}
		return decoded
	}
	request("", "GET", "/auth/csrf-token", nil, 200)
	request("", "POST", "/auth/login", map[string]string{"email": email, "password": "Passw0rd!"}, 200)
	appToken := tokens[""]
	request("admin", "GET", "/auth/csrf-token", nil, 200)
	request("admin", "POST", "/auth/admin/login", map[string]string{"email": adminUser.Email, "password": "Passw0rd!"}, 200)
	appMe := request("", "GET", "/auth/me", nil, 200)
	adminMe := request("admin", "GET", "/auth/me", nil, 200)
	if appMe["id"] != user.User.ID || adminMe["id"] != adminUser.ID {
		t.Fatal("contexts resolved the wrong identities")
	}
	if tokens[""] != appToken {
		t.Fatal("admin login changed the app CSRF token")
	}
	stored := map[string]string{}
	for _, cookie := range jar.Cookies(base) {
		stored[cookie.Name] = cookie.Value
	}
	for _, name := range []string{"goauth_session", "goauth_refresh", "_csrf", "goauth_admin_session", "goauth_admin_refresh", "_goauth_admin_csrf"} {
		if stored[name] == "" {
			t.Fatalf("missing independent cookie %s", name)
		}
	}
	request("admin", "POST", "/auth/refresh", nil, 200)
	if request("admin", "GET", "/auth/me", nil, 200)["id"] != adminUser.ID {
		t.Fatal("refresh changed admin identity")
	}
	if request("", "GET", "/auth/me", nil, 200)["id"] != user.User.ID {
		t.Fatal("admin refresh changed app identity")
	}
	// Even with both cookie sets present, neither CSRF token can be replayed in the other context.
	adminToken := tokens["admin"]
	tokens["admin"] = appToken
	request("admin", "PUT", "/auth/name", map[string]string{"name": "must not run"}, 403)
	tokens["admin"] = adminToken
	// Copying an app credential into the admin cookie cannot relabel its stored hash.
	// #nosec G124 -- this fixture deliberately exercises supported plain-HTTP development cookies.
	jar.SetCookies(base, []*http.Cookie{{Name: "goauth_admin_session", Value: stored["goauth_session"], Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode}})
	request("admin", "GET", "/auth/me", nil, 401)
	request("", "GET", "/auth/me", nil, 200)
	request("admin", "GET", "/auth/csrf-token", nil, 200)
	request("admin", "POST", "/auth/admin/login", map[string]string{"email": adminUser.Email, "password": "Passw0rd!"}, 200)
	request("admin", "POST", "/auth/logout", nil, 200)
	request("admin", "GET", "/auth/me", nil, 401)
	request("", "GET", "/auth/me", nil, 200)
	request("admin", "GET", "/auth/csrf-token", nil, 200)
	request("admin", "POST", "/auth/admin/login", map[string]string{"email": adminUser.Email, "password": "Passw0rd!"}, 200)
	request("", "POST", "/auth/logout", nil, 200)
	request("", "GET", "/auth/me", nil, 401)
	request("admin", "GET", "/auth/me", nil, 200)
	request("bogus", "GET", "/auth/me", nil, 400)
	// A regular user's credentials cannot issue an admin-context session.
	request("admin", "POST", "/auth/admin/login", map[string]string{"email": email, "password": "Passw0rd!"}, 401)
	if !strings.HasPrefix(stored["goauth_admin_session"], "ga-admin.") {
		t.Fatal("admin context was not bound into the opaque credential")
	}
}
