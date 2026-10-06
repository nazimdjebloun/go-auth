package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

type contractRateStore struct {
	err error
}

func (s contractRateStore) Allow(context.Context, string, ratelimit.Rate) (ratelimit.Result, error) {
	return ratelimit.Result{ResetAt: time.Now().Add(time.Minute)}, s.err
}

func TestMiddlewareErrorEnvelope(t *testing.T) {
	secret := []byte("test-csrf-signing-secret")
	signed, err := generateCSRFToken(32, secret)
	if err != nil {
		t.Fatal(err)
	}
	tokenMiddleware := func(key []byte) func(http.Handler) http.Handler {
		return CSRFToken(&CSRFTokenConfig{Secret: key})
	}
	originMiddleware := OriginCheck([]string{"https://app.example.com"}, false, nil, nil)
	rateMiddleware := func(err error) func(http.Handler) http.Handler {
		return RateLimit(&ratelimit.Config{
			Enabled: true, Default: ratelimit.Rate{Requests: 1, Window: time.Minute},
			Store: contractRateStore{err: err},
		})
	}
	cases := []struct {
		name    string
		wrap    func(http.Handler) http.Handler
		method  string
		origin  string
		referer string
		cookie  string
		header  string
		status  int
		code    string
	}{
		{name: "origin missing", wrap: originMiddleware, status: 403, code: "csrf_headers_missing"},
		{name: "origin denied", wrap: originMiddleware, origin: "https://other.example", status: 403, code: "csrf_origin_denied"},
		{name: "referer denied", wrap: originMiddleware, referer: "https://other.example/page", status: 403, code: "csrf_origin_denied"},
		{name: "token cookie missing", wrap: tokenMiddleware(secret), header: signed, status: 403, code: "csrf_token_missing"},
		{name: "token header missing", wrap: tokenMiddleware(secret), cookie: signed, status: 403, code: "csrf_token_missing"},
		{name: "token invalid", wrap: tokenMiddleware(secret), cookie: "forged", header: "forged", status: 403, code: "csrf_token_invalid"},
		{name: "token mismatch", wrap: tokenMiddleware(secret), cookie: signed, header: "different", status: 403, code: "csrf_token_mismatch"},
		{name: "signing key missing", wrap: tokenMiddleware(nil), method: "GET", status: 500, code: "internal_error"},
		{name: "verification key missing", wrap: tokenMiddleware(nil), cookie: signed, header: signed, status: 500, code: "internal_error"},
		{name: "authentication missing", wrap: AuthMiddleware(nil, DefaultCookieSettings(), nil, nil), status: 401, code: "session_expired"},
		{name: "role denied", wrap: RequireRole(domain.RoleAdmin, nil), status: 403, code: "forbidden"},
		{name: "rate exceeded", wrap: rateMiddleware(nil), status: 429, code: "rate_limit_exceeded"},
		{name: "rate store unavailable", wrap: rateMiddleware(errors.New("private backend details")), status: 429, code: "rate_limit_error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			method := tc.method
			if method == "" {
				method = http.MethodPost
			}
			req := httptest.NewRequest(method, "https://api.example.com/private", nil)
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Referer", tc.referer)
			req.Header.Set("X-CSRF-Token", tc.header)
			if tc.cookie != "" {
				req.AddCookie(secureRequestCookie("_csrf", tc.cookie))
			}
			rec := httptest.NewRecorder()
			tc.wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("rejected request reached the protected handler")
			})).ServeHTTP(rec, req)
			if rec.Code != tc.status || rec.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("status=%d content-type=%q body=%s", rec.Code, rec.Header().Get("Content-Type"), rec.Body)
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("invalid JSON error envelope: %v", err)
			}
			if len(body) != 2 || body["error"] != tc.code || body["message"] == "" {
				t.Fatalf("body=%v, want error=%q and message only", body, tc.code)
			}
			if tc.status == http.StatusTooManyRequests && rec.Header().Get("Retry-After") == "" {
				t.Fatal("rate-limit error lost its Retry-After header")
			}
		})
	}
}
