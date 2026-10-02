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
	}{
		{"malformed JSON", "{", "http://localhost:8080", true, http.StatusBadRequest},
		{"missing CSRF", `{"email":"http@example.com","password":"Passw0rd!"}`, "http://localhost:8080", false, http.StatusForbidden},
		{"foreign origin", `{"email":"http@example.com","password":"Passw0rd!"}`, "https://attacker.example", true, http.StatusForbidden},
		{"unknown account", `{"email":"missing@example.com","password":"Passw0rd!"}`, "http://localhost:8080", true, http.StatusUnauthorized},
		{"wrong password", `{"email":"http@example.com","password":"Wrongpass1!"}`, "http://localhost:8080", true, http.StatusUnauthorized},
		{"SQL metacharacters", `{"email":"http@example.com","password":"' OR 1=1; --"}`, "http://localhost:8080", true, http.StatusUnauthorized},
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
			if tc.status != http.StatusForbidden {
				var body map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				code, _ := body["error"].(string)
				message, _ := body["message"].(string)
				if len(body) != 2 || code == "" || message == "" {
					t.Fatalf("invalid error envelope: %s", w.Body)
				}
			} else if !strings.Contains(w.Body.String(), "Forbidden") {
				t.Fatalf("invalid CSRF refusal: %s", w.Body)
			}
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == "goauth_session" && cookie.Value != "" {
					t.Fatal("rejected request issued a session")
				}
			}
		})
	}
}
