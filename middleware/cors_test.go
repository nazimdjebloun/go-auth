package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func corsResponse(allowedOrigins []string, origin string) *httptest.ResponseRecorder {
	h := CORS(allowedOrigins)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Origin", origin)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func corsHasVaryOrigin(rec *httptest.ResponseRecorder) bool {
	for _, v := range rec.Header().Values("Vary") {
		if v == "Origin" {
			return true
		}
	}
	return false
}

func TestCORS_WildcardOmitsCredentials(t *testing.T) {
	rec := corsResponse([]string{"*"}, "https://client.example")

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://client.example" {
		t.Errorf("expected echoed origin, got %q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Errorf("expected no Access-Control-Allow-Credentials with wildcard config, got %q", got)
	}
	if !corsHasVaryOrigin(rec) {
		t.Error("expected Vary: Origin on wildcard response")
	}
}

func TestCORS_SpecificOriginsNoCrossLeak(t *testing.T) {
	allowed := []string{"https://a.example", "https://b.example"}

	ra := corsResponse(allowed, "https://a.example")
	if got := ra.Header().Get("Access-Control-Allow-Origin"); got != "https://a.example" {
		t.Errorf("expected ACAO https://a.example, got %q", got)
	}
	if got := ra.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("expected credentials for configured origin, got %q", got)
	}
	if !corsHasVaryOrigin(ra) {
		t.Error("expected Vary: Origin on a.example response")
	}

	rb := corsResponse(allowed, "https://b.example")
	if got := rb.Header().Get("Access-Control-Allow-Origin"); got != "https://b.example" {
		t.Errorf("expected ACAO https://b.example, got %q", got)
	}
	if got := rb.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("expected credentials for configured origin, got %q", got)
	}
	if !corsHasVaryOrigin(rb) {
		t.Error("expected Vary: Origin on b.example response")
	}
}

func TestCORS_ExposesCSRFReplacementAndRetryHeaders(t *testing.T) {
	allowed := corsResponse([]string{"https://panel.example"}, "https://panel.example")
	if allowed.Header().Get("Access-Control-Expose-Headers") != "X-CSRF-Token, Retry-After" {
		t.Fatal("browser cannot read token rotation or retry delay")
	}
	if allowed.Header().Get("Access-Control-Allow-Headers") != "Content-Type, Authorization, X-CSRF-Token, X-GoAuth-Session, If-Match" {
		t.Fatal("browser cannot send the session context selector")
	}
	foreign := corsResponse([]string{"https://panel.example"}, "https://attacker.example")
	if foreign.Header().Get("Access-Control-Allow-Origin") != "" || foreign.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("foreign frontend received credentialled CORS access")
	}
}

func TestCORS_AdditionalApplicationPolicy(t *testing.T) {
	cfg := CORSConfig{
		AllowedHeaders: []string{"idempotency-key", "IDEMPOTENCY-KEY", "x-csrf-token", "if-match"},
		ExposedHeaders: []string{"Content-Disposition", "content-disposition", "retry-after"},
		AllowedMethods: []string{"PROPFIND", "PROPFIND", "POST"},
	}
	called := false
	h := CORS([]string{"https://app.example"}, cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.Header().Set("Content-Disposition", `attachment; filename="report.csv"`)
		w.WriteHeader(http.StatusOK)
	}))
	for _, tc := range []struct {
		name, method, origin string
		wantPolicy           bool
	}{
		{name: "preflight", method: "OPTIONS", origin: "https://app.example", wantPolicy: true},
		{name: "actual request", method: "PROPFIND", origin: "https://app.example", wantPolicy: true},
		{name: "foreign preflight", method: "OPTIONS", origin: "https://evil.example"},
		{name: "foreign request", method: "POST", origin: "https://evil.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called = false
			r := httptest.NewRequest(tc.method, "/exports", nil)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("Access-Control-Request-Method", "PROPFIND")
			r.Header.Set("Access-Control-Request-Headers", "idempotency-key, x-csrf-token")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if tc.method == "OPTIONS" {
				if w.Code != http.StatusNoContent || called {
					t.Fatalf("preflight status=%d, handler called=%v", w.Code, called)
				}
			} else if w.Code != http.StatusOK || !called {
				t.Fatalf("actual request status=%d, handler called=%v", w.Code, called)
			}
			if !tc.wantPolicy {
				for _, header := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Headers", "Access-Control-Expose-Headers", "Access-Control-Allow-Methods"} {
					if w.Header().Get(header) != "" {
						t.Errorf("foreign origin received %s", header)
					}
				}
				return
			}
			if w.Header().Get("Access-Control-Allow-Origin") != tc.origin || w.Header().Get("Access-Control-Allow-Credentials") != "true" {
				t.Fatal("allowed origin lost credentialled access")
			}
			if got := w.Header().Get("Access-Control-Allow-Headers"); got != "Content-Type, Authorization, X-CSRF-Token, X-GoAuth-Session, If-Match, Idempotency-Key" {
				t.Errorf("allowed headers = %q", got)
			}
			if got := w.Header().Get("Access-Control-Expose-Headers"); got != "X-CSRF-Token, Retry-After, Content-Disposition" {
				t.Errorf("exposed headers = %q", got)
			}
			if got := w.Header().Get("Access-Control-Allow-Methods"); got != "GET, POST, PUT, PATCH, DELETE, OPTIONS, PROPFIND" {
				t.Errorf("allowed methods = %q", got)
			}
		})
	}
}

func TestCORS_SnapshotsApplicationPolicy(t *testing.T) {
	origins := []string{"https://app.example"}
	cfg := CORSConfig{
		AllowedHeaders: []string{"Idempotency-Key"},
		ExposedHeaders: []string{"Content-Disposition"},
		AllowedMethods: []string{"PROPFIND"},
	}
	h := CORS(origins, cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	origins[0] = "https://changed.example"
	cfg.AllowedHeaders[0] = "X-Changed"
	cfg.ExposedHeaders[0] = "X-Changed"
	cfg.AllowedMethods[0] = "CHANGED"
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Origin", "https://app.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Access-Control-Allow-Origin") != "https://app.example" {
		t.Fatal("caller mutation changed allowed origins")
	}
	for header, want := range map[string]string{
		"Access-Control-Allow-Headers":  "Idempotency-Key",
		"Access-Control-Expose-Headers": "Content-Disposition",
		"Access-Control-Allow-Methods":  "PROPFIND",
	} {
		if !strings.Contains(w.Header().Get(header), want) {
			t.Errorf("caller mutation changed %s", header)
		}
	}
}

func TestCORS_InvalidApplicationPolicyPanicsAtSetup(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  CORSConfig
	}{
		{name: "header injection", cfg: CORSConfig{AllowedHeaders: []string{"X-Request\r\nInjected: true"}}},
		{name: "exposure wildcard", cfg: CORSConfig{ExposedHeaders: []string{"*"}}},
		{name: "forbidden method", cfg: CORSConfig{AllowedMethods: []string{"trace"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("invalid CORS config accepted")
				}
			}()
			CORS([]string{"https://app.example"}, tc.cfg)
		})
	}
}
