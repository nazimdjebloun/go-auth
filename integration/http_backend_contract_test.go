package integration_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
)

func TestHTTPBackendSecurityContract(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()
	if _, err := a.Register(t.Context(), api.RegisterInput{Email: "http@example.com", Name: "HTTP", Password: validTestPassword()}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.Mount(mux)
	csrfResponse := httptest.NewRecorder()
	mux.ServeHTTP(csrfResponse, httptest.NewRequest(http.MethodGet, "/auth/csrf-token", nil))
	var csrf *http.Cookie
	for _, cookie := range csrfResponse.Result().Cookies() {
		if cookie.Name == "_csrf" {
			csrf = cookie
		}
	}
	if csrf == nil {
		t.Fatal("CSRF cookie missing")
	}
	for i, tc := range []struct {
		name, body, origin string
		csrf               bool
		status             int
		code               string
	}{
		{"malformed JSON", "{", "http://localhost:8080", true, http.StatusBadRequest, "invalid_json"},
		{"missing CSRF", `{"email":"http@example.com","password":"Passw0rd!"}`, "http://localhost:8080", false, http.StatusForbidden, "csrf_token_missing"},
		{"foreign origin", `{"email":"http@example.com","password":"Passw0rd!"}`, "https://attacker.example", true, http.StatusForbidden, "csrf_origin_denied"},
		{"unknown account", `{"email":"missing@example.com","password":"Passw0rd!"}`, "http://localhost:8080", true, http.StatusUnauthorized, "invalid_credentials"},
		{"wrong password", `{"email":"http@example.com","password":"Wrongpass1!"}`, "http://localhost:8080", true, http.StatusUnauthorized, "invalid_credentials"},
		{"SQL metacharacters", `{"email":"http@example.com","password":"' OR 1=1; --"}`, "http://localhost:8080", true, http.StatusUnauthorized, "invalid_credentials"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(tc.body))
			r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", i+1)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", tc.origin)
			if tc.csrf {
				r.AddCookie(csrf)
				r.Header.Set("X-CSRF-Token", csrf.Value)
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d body=%s want %d", w.Code, w.Body, tc.status)
			}
			if contentType := w.Header().Get("Content-Type"); contentType != "application/json" {
				t.Fatalf("content-type=%q body=%s want application/json", contentType, w.Body)
			}
			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			code, _ := body["error"].(string)
			message, _ := body["message"].(string)
			if len(body) != 2 || code != tc.code || message == "" {
				t.Fatalf("invalid error envelope: %s want error=%q and message only", w.Body, tc.code)
			}
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == "goauth_session" && cookie.Value != "" {
					t.Fatal("rejected request issued a session")
				}
			}
		})
	}
}
