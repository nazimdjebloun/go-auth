package middleware

import (
	"net/http"
	"net/http/httptest"
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
	if allowed.Header().Get("Access-Control-Allow-Headers") != "Content-Type, Authorization, X-CSRF-Token, X-GoAuth-Session" {
		t.Fatal("browser cannot send the session context selector")
	}
	foreign := corsResponse([]string{"https://panel.example"}, "https://attacker.example")
	if foreign.Header().Get("Access-Control-Allow-Origin") != "" || foreign.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("foreign frontend received credentialled CORS access")
	}
}
