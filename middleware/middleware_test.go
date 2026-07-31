package middleware

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/ratelimit"
	"github.com/nazimdjebloun/go-auth/service"
)

func TestExtractIP_RemoteAddr(t *testing.T) {
	cfg := &ratelimit.Config{IPv6Subnet: 64}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.1:34567"
	ip := extractIP(r, cfg)
	if ip != "192.168.1.1" {
		t.Errorf("expected 192.168.1.1, got %s", ip)
	}
}

func TestExtractIP_XForwardedFor(t *testing.T) {
	cfg := &ratelimit.Config{
		IPv6Subnet:      64,
		IPAddressHeader: "X-Forwarded-For",
		TrustedIPs:      []string{"192.168.1.1"},
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.1:34567"
	r.Header.Set("X-Forwarded-For", "10.0.0.1, 10.0.0.2")
	ip := extractIP(r, cfg)
	if ip != "10.0.0.1" {
		t.Errorf("expected 10.0.0.1, got %s", ip)
	}
}

func TestExtractIP_XForwardedFor_NotSpoofableWithoutConfig(t *testing.T) {
	cfg := &ratelimit.Config{IPv6Subnet: 64}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	r.RemoteAddr = "192.0.2.1:1234"
	ip := extractIP(r, cfg)
	if ip != "192.0.2.1" {
		t.Errorf("expected 192.0.2.1 (RemoteAddr), got %s", ip)
	}
}

func TestExtractIP_XRealIP(t *testing.T) {
	cfg := &ratelimit.Config{
		IPv6Subnet:      64,
		IPAddressHeader: "X-Real-IP",
		TrustedIPs:      []string{"192.168.1.1"},
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.1:34567"
	r.Header.Set("X-Real-IP", "10.0.0.5")
	ip := extractIP(r, cfg)
	if ip != "10.0.0.5" {
		t.Errorf("expected 10.0.0.5, got %s", ip)
	}
}

func TestExtractIP_CustomHeader(t *testing.T) {
	cfg := &ratelimit.Config{
		IPv6Subnet:      64,
		IPAddressHeader: "CF-Connecting-IP",
		TrustedIPs:      []string{"192.168.1.1"},
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.168.1.1:34567"
	r.Header.Set("CF-Connecting-IP", "203.0.113.1")
	ip := extractIP(r, cfg)
	if ip != "203.0.113.1" {
		t.Errorf("expected 203.0.113.1, got %s", ip)
	}
}

func TestExtractIP_HeaderIgnoredForUntrustedPeer(t *testing.T) {
	cfg := &ratelimit.Config{
		IPv6Subnet:      64,
		IPAddressHeader: "X-Forwarded-For",
		TrustedIPs:      []string{"10.0.0.99"},
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "192.0.2.50:1234"
	// Untrusted peer spoofing a TrustedIPs value via the header.
	r.Header.Set("X-Forwarded-For", "10.0.0.99")
	ip := extractIP(r, cfg)
	if ip != "192.0.2.50" {
		t.Errorf("expected 192.0.2.50 (RemoteAddr), got %s", ip)
	}
}

func TestExtractIP_PriorityCustomHeader(t *testing.T) {
	cfg := &ratelimit.Config{
		IPv6Subnet:      64,
		IPAddressHeader: "CF-Connecting-IP",
		TrustedIPs:      []string{"192.168.1.1"},
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("CF-Connecting-IP", "203.0.113.1")
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	r.RemoteAddr = "192.168.1.1:34567"
	ip := extractIP(r, cfg)
	if ip != "203.0.113.1" {
		t.Errorf("expected 203.0.113.1 (custom header), got %s", ip)
	}
}

func TestRateLimit_SpoofedHeaderCannotBypass(t *testing.T) {
	cfg := &ratelimit.Config{
		Enabled:         true,
		IPv6Subnet:      64,
		IPAddressHeader: "X-Forwarded-For",
		TrustedIPs:      []string{"10.0.0.99"},
		Default:         ratelimit.Rate{Requests: 2, Window: time.Minute},
	}
	rl := RateLimit(cfg)

	var calls int
	var last *httptest.ResponseRecorder
	h := rl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/auth/login", nil)
		req.RemoteAddr = "192.0.2.50:1234"
		req.Header.Set("X-Forwarded-For", "10.0.0.99")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		last = rec
	}

	if calls != 2 {
		t.Errorf("expected 2 allowed requests before limiting, got %d", calls)
	}
	if last.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 on third request, got %d", last.Code)
	}
}

type failingStore struct{}

func (failingStore) Increment(string, time.Duration) (ratelimit.StoreResult, error) {
	return ratelimit.StoreResult{}, errors.New("store down")
}

func (failingStore) Reset(string) error { return nil }

func TestRateLimit_StoreErrorLogsStructured(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	cfg := &ratelimit.Config{
		Enabled:    true,
		IPv6Subnet: 64,
		Store:      failingStore{},
		Default:    ratelimit.Rate{Requests: 2, Window: time.Minute},
		Logger:     logger,
	}
	rl := RateLimit(cfg)

	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.RemoteAddr = "192.0.2.50:1234"
	rec := httptest.NewRecorder()
	rl(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on store error, got %d", rec.Code)
	}
	out := buf.String()
	for _, want := range []string{"rate limit store error", "method=POST", "path=/auth/login", "ip=192.0.2.50"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected log to contain %q, got:\n%s", want, out)
		}
	}
}

func TestExtractIP_IPv6Subnet(t *testing.T) {
	cfg := &ratelimit.Config{IPv6Subnet: 64}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[2001:db8::1]:34567"
	ip := extractIP(r, cfg)
	// /64 mask of 2001:db8::1 should be 2001:db8:0:0:0:0:0:0
	if ip != "2001:db8::" {
		t.Errorf("expected 2001:db8::, got %s", ip)
	}
}

func TestExtractIP_IPv6NoPort(t *testing.T) {
	cfg := &ratelimit.Config{IPv6Subnet: 64}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "2001:db8::1"
	ip := extractIP(r, cfg)
	if ip != "2001:db8::" {
		t.Errorf("expected 2001:db8::, got %s", ip)
	}
}

func TestNormalizeOrigin_StandardPorts(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://example.com", "http://example.com:80"},
		{"https://example.com", "https://example.com:443"},
		{"http://example.com:80", "http://example.com:80"},
		{"https://example.com:443", "https://example.com:443"},
		{"http://example.com:8080", "http://example.com:8080"},
	}
	for _, tt := range tests {
		got := normalizeOrigin(tt.input)
		if got != tt.want {
			t.Errorf("normalizeOrigin(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeOrigin_TrailingSlash(t *testing.T) {
	got := normalizeOrigin("http://example.com/")
	want := "http://example.com:80"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestIsSameOrigin_Matching(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/path", nil)
	r.Host = "example.com"
	if !isSameOrigin("http://example.com", r, nil) {
		t.Error("expected same origin match")
	}
}

func TestIsSameOrigin_DifferentScheme(t *testing.T) {
	r := httptest.NewRequest("GET", "https://example.com/path", nil)
	r.Host = "example.com"
	r.TLS = &tls.ConnectionState{}
	if isSameOrigin("http://example.com", r, nil) {
		t.Error("expected different scheme to not match")
	}
}

func TestIsSameOrigin_DifferentHost(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/path", nil)
	r.Host = "example.com"
	if isSameOrigin("http://evil.com", r, nil) {
		t.Error("expected different host to not match")
	}
}

func TestIsSameOrigin_BehindReverseProxyHTTPS(t *testing.T) {
	// Behind nginx/Cloudflare/ALB: r.TLS is nil but X-Forwarded-Proto is https.
	r := httptest.NewRequest("GET", "https://example.com/path", nil)
	r.Host = "example.com"
	r.TLS = nil
	r.RemoteAddr = "192.168.1.10:1234"
	r.Header.Set("X-Forwarded-Proto", "https")
	if !isSameOrigin("https://example.com", r, []string{"192.168.1.10"}) {
		t.Error("expected X-Forwarded-Proto https to match https origin")
	}
}

func TestIsSameOrigin_BehindReverseProxyHTTP(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/path", nil)
	r.Host = "example.com"
	r.TLS = nil
	r.RemoteAddr = "192.168.1.10:1234"
	r.Header.Set("X-Forwarded-Proto", "http")
	if !isSameOrigin("http://example.com", r, []string{"192.168.1.10"}) {
		t.Error("expected X-Forwarded-Proto http to match http origin")
	}
}

func TestIsSameOrigin_ReverseProxySchemeMismatch(t *testing.T) {
	// Proxy says http, but origin says https — should not match.
	r := httptest.NewRequest("GET", "http://example.com/path", nil)
	r.Host = "example.com"
	r.TLS = nil
	r.RemoteAddr = "192.168.1.10:1234"
	r.Header.Set("X-Forwarded-Proto", "http")
	if isSameOrigin("https://example.com", r, []string{"192.168.1.10"}) {
		t.Error("expected scheme mismatch to not match")
	}
}

func TestIsSameOrigin_ForwardedHeader(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/path", nil)
	r.Host = "example.com"
	r.TLS = nil
	r.RemoteAddr = "192.168.1.10:1234"
	r.Header.Set("Forwarded", "for=192.0.2.60;proto=https;host=example.com")
	if !isSameOrigin("https://example.com", r, []string{"192.168.1.10"}) {
		t.Error("expected Forwarded proto=https to match https origin")
	}
}

func TestIsSameOrigin_XForwardedHost(t *testing.T) {
	r := httptest.NewRequest("GET", "https://api.example.com/path", nil)
	r.Host = "internal-host"
	r.TLS = nil
	r.RemoteAddr = "192.168.1.10:1234"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "api.example.com")
	if !isSameOrigin("https://api.example.com", r, []string{"192.168.1.10"}) {
		t.Error("expected X-Forwarded-Host to be used for comparison")
	}
}

func TestIsSameOrigin_SpoofedForwardedHeader(t *testing.T) {
	// An untrusted client spoofing X-Forwarded-Proto cannot bypass the origin
	// check: with no trusted proxy the header is ignored entirely, so the
	// effective scheme stays http and the origin must still match.
	r := httptest.NewRequest("GET", "http://example.com/path", nil)
	r.Host = "example.com"
	r.TLS = nil
	r.Header.Set("X-Forwarded-Proto", "https")
	// Attacker origin is evil.com — should still fail.
	if isSameOrigin("https://evil.com", r, nil) {
		t.Error("spoofed X-Forwarded-Proto should not help attacker")
	}
}

func TestIsSameOrigin_UntrustedPeerIgnoredForForwardedHost(t *testing.T) {
	// Spoofed X-Forwarded-Host from an untrusted peer must be ignored, so the
	// comparison uses r.Host as-is and the origin does not match.
	r := httptest.NewRequest("GET", "http://api.example.com/path", nil)
	r.Host = "internal-host"
	r.TLS = nil
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "api.example.com")
	if isSameOrigin("https://api.example.com", r, nil) {
		t.Error("spoofed forwarded headers from an untrusted peer must be ignored")
	}
	if isSameOrigin("https://api.example.com", r, []string{"192.0.2.99"}) {
		t.Error("forwarded headers must only be honored when the peer is trusted")
	}
}

func TestPeerIsTrusted(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.10:34567"

	if peerIsTrusted(req, nil) {
		t.Error("empty trusted list must trust nobody")
	}
	if !peerIsTrusted(req, []string{"192.168.1.10"}) {
		t.Error("expected exact IP match to be trusted")
	}
	if !peerIsTrusted(req, []string{"192.168.0.0/16"}) {
		t.Error("expected CIDR match to be trusted")
	}
	if peerIsTrusted(req, []string{"10.0.0.0/8"}) {
		t.Error("expected non-matching CIDR to be untrusted")
	}

	req.RemoteAddr = "not-an-address"
	if peerIsTrusted(req, []string{"192.168.1.10"}) {
		t.Error("expected malformed RemoteAddr to be untrusted")
	}
}

func TestRequestSchemeHost_DirectHTTPS(t *testing.T) {
	r := httptest.NewRequest("GET", "https://example.com/path", nil)
	r.Host = "example.com"
	scheme, host := requestSchemeHost(r, nil)
	if scheme != "https" || host != "example.com" {
		t.Errorf("expected https://example.com, got %s://%s", scheme, host)
	}
}

func TestRequestSchemeHost_DirectHTTP(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/path", nil)
	r.Host = "example.com"
	scheme, host := requestSchemeHost(r, nil)
	if scheme != "http" || host != "example.com" {
		t.Errorf("expected http://example.com, got %s://%s", scheme, host)
	}
}

func TestRequestSchemeHost_ProxyHTTPS(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/path", nil)
	r.Host = "internal"
	r.RemoteAddr = "192.168.1.10:1234"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "example.com")
	scheme, host := requestSchemeHost(r, []string{"192.168.1.10"})
	if scheme != "https" || host != "example.com" {
		t.Errorf("expected https://example.com, got %s://%s", scheme, host)
	}
}

func TestRequestSchemeHost_UntrustedPeerFallsBackToHost(t *testing.T) {
	r := httptest.NewRequest("GET", "http://example.com/path", nil)
	r.Host = "internal"
	r.RemoteAddr = "10.0.0.5:1234"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "example.com")
	scheme, host := requestSchemeHost(r, []string{"192.168.1.10"})
	if scheme != "http" || host != "internal" {
		t.Errorf("expected http://internal (forwarded headers ignored), got %s://%s", scheme, host)
	}
}

func TestIsAllowed_Wildcard(t *testing.T) {
	origins := map[string]bool{"*": true}
	if !isAllowed("http://anything.com", origins) {
		t.Error("expected wildcard to allow everything")
	}
}

func TestIsAllowed_ExactMatch(t *testing.T) {
	origins := map[string]bool{"http://example.com:80": true}
	if !isAllowed("http://example.com", origins) {
		t.Error("expected matching origin to be allowed")
	}
}

func TestIsAllowed_NoMatch(t *testing.T) {
	origins := map[string]bool{"http://example.com:80": true}
	if isAllowed("http://evil.com", origins) {
		t.Error("expected non-matching origin to be blocked")
	}
}

func TestAuthMiddleware_MissingCookie(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}

	sessCfg := service.DefaultSessionConfig()
	sessSvc := service.NewSessionService(sessions, gen, sessCfg)

	handler := AuthMiddleware(sessSvc, users, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["error"] != "session_expired" {
		t.Fatalf("expected session_expired, got %s", body["error"])
	}
}

func TestAuthMiddleware_ExpiredSession(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}

	sessCfg := service.DefaultSessionConfig()
	sessCfg.Duration = -1 * time.Hour
	sessSvc := service.NewSessionService(sessions, gen, sessCfg)

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(t.Context(), user)

	_, rawToken, _, err := sessSvc.Create(t.Context(), user.ID, "", "")
	if err != nil {
		t.Fatal(err)
	}

	handler := AuthMiddleware(sessSvc, users, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessCfg.CookieName, Value: rawToken})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["error"] != "session_expired" {
		t.Fatalf("expected session_expired, got %s", body["error"])
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}

	sessCfg := service.DefaultSessionConfig()
	sessSvc := service.NewSessionService(sessions, gen, sessCfg)

	handler := AuthMiddleware(sessSvc, users, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessCfg.CookieName, Value: "garbage-token"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["error"] != "unauthorized" {
		t.Fatalf("expected unauthorized, got %s", body["error"])
	}
}

func TestAuthMiddleware_BannedUser(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}

	sessCfg := service.DefaultSessionConfig()
	sessSvc := service.NewSessionService(sessions, gen, sessCfg)

	user := &domain.User{ID: "user-1", Email: "test@example.com", IsBanned: true}
	users.Create(t.Context(), user)

	_, rawToken, _, err := sessSvc.Create(t.Context(), user.ID, "", "")
	if err != nil {
		t.Fatal(err)
	}

	handler := AuthMiddleware(sessSvc, users, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessCfg.CookieName, Value: rawToken})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["error"] != "user_banned" {
		t.Fatalf("expected user_banned, got %s", body["error"])
	}
}

func TestAuthMiddleware_DeletedUser(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}

	sessCfg := service.DefaultSessionConfig()
	sessSvc := service.NewSessionService(sessions, gen, sessCfg)

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(t.Context(), user)

	_, rawToken, _, err := sessSvc.Create(t.Context(), user.ID, "", "")
	if err != nil {
		t.Fatal(err)
	}

	users.Delete(t.Context(), "user-1")

	handler := AuthMiddleware(sessSvc, users, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessCfg.CookieName, Value: rawToken})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["error"] != "unauthorized" {
		t.Fatalf("expected unauthorized, got %s", body["error"])
	}
}

func TestRequireRole_CorrectRole(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}

	sessCfg := service.DefaultSessionConfig()
	sessSvc := service.NewSessionService(sessions, gen, sessCfg)

	user := &domain.User{ID: "user-1", Email: "test@example.com", Role: domain.RoleAdmin}
	users.Create(t.Context(), user)

	_, rawToken, _, err := sessSvc.Create(t.Context(), user.ID, "", "")
	if err != nil {
		t.Fatal(err)
	}

	handler := AuthMiddleware(sessSvc, users, nil)(RequireRole(domain.RoleAdmin, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessCfg.CookieName, Value: rawToken})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestRequireRole_WrongRole(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}

	sessCfg := service.DefaultSessionConfig()
	sessSvc := service.NewSessionService(sessions, gen, sessCfg)

	user := &domain.User{ID: "user-1", Email: "test@example.com", Role: domain.RoleUser}
	users.Create(t.Context(), user)

	_, rawToken, _, err := sessSvc.Create(t.Context(), user.ID, "", "")
	if err != nil {
		t.Fatal(err)
	}

	handler := AuthMiddleware(sessSvc, users, nil)(RequireRole(domain.RoleAdmin, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	})))

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessCfg.CookieName, Value: rawToken})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["error"] != "forbidden" {
		t.Fatalf("expected forbidden, got %s", body["error"])
	}
}

func TestAuthMiddleware_NoTokenRotationOnValidSession(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}

	sessCfg := service.DefaultSessionConfig()
	sessCfg.Duration = 30 * time.Minute
	sessCfg.RefreshTTL = 60 * time.Minute
	sessCfg.IdleTTL = 15 * time.Minute
	sessSvc := service.NewSessionService(sessions, gen, sessCfg)

	user := &domain.User{ID: "user-1", Email: "test@example.com"}
	users.Create(t.Context(), user)

	_, rawToken, rawRefreshToken, err := sessSvc.Create(t.Context(), user.ID, "127.0.0.1", "test-agent")
	if err != nil {
		t.Fatal(err)
	}

	handler := AuthMiddleware(sessSvc, users, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := GetSessionFromContext(r.Context())
		if s == nil {
			t.Fatal("expected session in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("does not rotate token on valid session", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: sessCfg.CookieName, Value: rawToken})
		req.AddCookie(&http.Cookie{Name: sessCfg.RefreshCookieName, Value: rawRefreshToken})
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		cookies := rec.Result().Cookies()
		for _, c := range cookies {
			if c.Name == sessCfg.CookieName || c.Name == sessCfg.RefreshCookieName {
				t.Errorf("should not set new cookies on valid session, got %s", c.Name)
			}
		}
	})

	t.Run("proceeds without refresh cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: sessCfg.CookieName, Value: rawToken})
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("concurrent requests with same token both succeed", func(t *testing.T) {
		_, rawToken2, rawRefresh2, err := sessSvc.Create(t.Context(), user.ID, "127.0.0.1", "test-agent")
		if err != nil {
			t.Fatal(err)
		}

		const concurrency = 10
		results := make(chan int, concurrency)
		for range concurrency {
			go func() {
				req := httptest.NewRequest("GET", "/", nil)
				req.AddCookie(&http.Cookie{Name: sessCfg.CookieName, Value: rawToken2})
				req.AddCookie(&http.Cookie{Name: sessCfg.RefreshCookieName, Value: rawRefresh2})
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
				results <- rec.Code
			}()
		}
		for range concurrency {
			code := <-results
			if code != http.StatusOK {
				t.Errorf("expected 200, got %d", code)
			}
		}
	})

	t.Run("expired session transparently refreshes via resolveSession", func(t *testing.T) {
		shortCfg := service.DefaultSessionConfig()
		shortCfg.Duration = 1 * time.Nanosecond
		shortCfg.RefreshTTL = 60 * time.Minute
		shortCfg.IdleTTL = 0
		shortSessSvc := service.NewSessionService(sessions, gen, shortCfg)
		shortHandler := AuthMiddleware(shortSessSvc, users, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		_, rawToken3, rawRefresh3, err := shortSessSvc.Create(t.Context(), user.ID, "127.0.0.1", "test-agent")
		if err != nil {
			t.Fatal(err)
		}

		time.Sleep(2 * time.Millisecond)

		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: shortCfg.CookieName, Value: rawToken3})
		req.AddCookie(&http.Cookie{Name: shortCfg.RefreshCookieName, Value: rawRefresh3})
		rec := httptest.NewRecorder()

		shortHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rec.Code)
		}

		cookies := rec.Result().Cookies()
		var hasNewSession bool
		for _, c := range cookies {
			if c.Name == shortCfg.CookieName && c.Value != rawToken3 {
				hasNewSession = true
			}
		}
		if !hasNewSession {
			t.Error("expected new session cookie after transparent refresh")
		}
	})
}

func TestWriteJSON_EncodeErrorLogsStructured(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	rec := httptest.NewRecorder()
	writeJSON(rec, http.StatusInternalServerError, map[string]any{"bad": make(chan int)}, logger)

	out := buf.String()
	for _, want := range []string{"level=ERROR", "failed to encode JSON response", "status=500"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected log to contain %q, got:\n%s", want, out)
		}
	}
}

func TestAuthMiddleware_MissingCookieLogsDebug(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}

	sessCfg := service.DefaultSessionConfig()
	sessSvc := service.NewSessionService(sessions, gen, sessCfg)

	handler := AuthMiddleware(sessSvc, users, logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/private", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	out := buf.String()
	for _, want := range []string{"level=DEBUG", "auth rejected", `reason="missing session cookie"`, "method=GET", "path=/private"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected log to contain %q, got:\n%s", want, out)
		}
	}
}

func TestAuthMiddleware_BannedUserLogsWarn(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	gen := &testutil.MockTokenGen{Length: 32}

	sessCfg := service.DefaultSessionConfig()
	sessSvc := service.NewSessionService(sessions, gen, sessCfg)

	user := &domain.User{ID: "user-1", Email: "test@example.com", IsBanned: true}
	users.Create(t.Context(), user)

	_, rawToken, _, err := sessSvc.Create(t.Context(), user.ID, "", "")
	if err != nil {
		t.Fatal(err)
	}

	handler := AuthMiddleware(sessSvc, users, logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessCfg.CookieName, Value: rawToken})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	out := buf.String()
	for _, want := range []string{"level=WARN", "auth rejected", `reason="user banned"`, "method=GET", "path=/", "user_id=user-1"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected log to contain %q, got:\n%s", want, out)
		}
	}
}

func TestOriginCheck_RejectedOriginLogsWarn(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	oc := OriginCheck([]string{"http://example.com"}, false, nil, logger)
	handler := oc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	}))

	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.Header.Set("Origin", "http://evil.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	out := buf.String()
	for _, want := range []string{"level=WARN", "csrf rejected", `reason="origin not allowed"`, "method=POST", "path=/auth/login", "origin=http://evil.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected log to contain %q, got:\n%s", want, out)
		}
	}
}

func TestOriginCheck_RejectedRefererLogsWarn(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	oc := OriginCheck([]string{"http://example.com"}, false, nil, logger)
	handler := oc(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("inner handler should not be called")
	}))

	req := httptest.NewRequest("POST", "/auth/login", nil)
	req.Header.Set("Referer", "http://evil.com/steal")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	out := buf.String()
	for _, want := range []string{"level=WARN", "csrf rejected", `reason="referer not allowed"`, "method=POST", "path=/auth/login", "referer=http://evil.com/steal"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected log to contain %q, got:\n%s", want, out)
		}
	}
}
