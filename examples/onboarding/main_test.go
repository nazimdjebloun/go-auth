package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
)

func TestOnboardingCompleteBrowserHTTPFlow(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "onboarding.db") + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	secret := strings.Repeat("k", 32)
	mailer := &testutil.MockMailer{}
	server := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + server.Listener.Addr().String()
	defer server.Close()
	options := []goauth.Option{goauth.WithBcryptCost(4), goauth.WithMailer(mailer)}
	if auth, _, err := newApplication(dsn, baseURL, secret, options...); err == nil {
		auth.Close()
		t.Fatal("example started before migration")
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := goauth.Migrate(t.Context(), db, goauth.MigrationOptions{Driver: "sqlite"}); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	auth, handler, err := newApplication(dsn, baseURL, secret, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(auth.Close)
	server.Config.Handler = handler
	server.Start()
	client := server.Client()
	client.Jar, err = cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.Get(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	html, err := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if err != nil || page.StatusCode != 200 || !bytes.Contains(html, []byte(`id="credentials"`)) {
		t.Fatal("embedded browser page unavailable")
	}
	csrf := ""
	request := func(method, path string, body any, want int) map[string]any {
		t.Helper()
		var encoded []byte
		if body != nil {
			encoded, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		r, err := http.NewRequest(method, baseURL+path, bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Origin", baseURL)
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if method == "POST" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		if token := response.Header.Get("X-CSRF-Token"); token != "" {
			csrf = token
		}
		var data map[string]any
		if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != want {
			t.Fatalf("%s %s: status %d want %d; %v", method, path, response.StatusCode, want, data)
		}
		for _, field := range []string{"sessionToken", "refreshToken", "bindingToken", "requiresTwoFactor", "requiresVerification"} {
			if _, exists := data[field]; exists {
				t.Fatalf("unexpected credential/legacy response field %s", field)
			}
		}
		return data
	}
	check := func(data map[string]any, step string) {
		t.Helper()
		if data["step"] != step {
			t.Fatalf("expected step %s, got %v", step, data["step"])
		}
	}
	csrf = request("GET", "/auth/csrf-token", nil, 200)["token"].(string)
	request("POST", "/app/hello", nil, 401)
	credentials := map[string]string{"email": "onboarding@example.test", "password": "Passw0rd!", "name": "Onboarding"}
	check(request("POST", "/auth/register", credentials, 201), "verify_email")
	verificationCode := testutil.GetLastVerificationCode(mailer)
	check(request("POST", "/auth/login", credentials, 200), "verify_email")
	check(request("POST", "/auth/verify-email", map[string]string{"code": verificationCode}, 200), "sign_in")
	challenge := request("POST", "/auth/login", credentials, 200)
	check(challenge, "two_factor")
	code := testutil.GetLastVerificationCode(mailer)
	if len(code) != 6 {
		t.Fatal("missing second-factor email code")
	}
	request("GET", "/auth/me", nil, 401)
	check(request("POST", "/auth/2fa/verify", map[string]any{"challengeId": challenge["challengeId"], "code": code}, 200), "authenticated")
	me := request("GET", "/auth/me", nil, 200)
	check(me, "authenticated")
	// Even with authenticated cookies, a missing double-submit header is refused.
	saved := csrf
	csrf = ""
	request("POST", "/app/hello", nil, 403)
	csrf = saved
	result := request("POST", "/app/hello", nil, 200)
	if result["userId"] != me["id"] {
		t.Fatal("protected handler received a different identity")
	}
	check(request("POST", "/auth/logout", nil, 200), "sign_in")
	request("GET", "/auth/me", nil, 401)
}
