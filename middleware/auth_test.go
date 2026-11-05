package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sessioncontext"
)

type countingAuthenticator struct {
	session                         *domain.Session
	user                            *domain.User
	expired                         bool
	validations, refreshes, touches int
}

func (s *countingAuthenticator) ValidateWithUser(_ context.Context, token string) (*domain.Session, *domain.User, error) {
	s.validations++
	if token != "access" {
		return nil, nil, domain.ErrSessionNotFound
	}
	if s.expired {
		return nil, nil, domain.ErrSessionExpired
	}
	return s.session, s.user, nil
}

func (s *countingAuthenticator) RefreshSession(context.Context, string) (*api.SessionResult, error) {
	s.refreshes++
	return &api.SessionResult{Session: s.session, SessionToken: "rotated-access", RefreshToken: "rotated-refresh"}, nil
}

func (s *countingAuthenticator) Touch(context.Context, api.TouchSessionInput) error {
	s.touches++
	return nil
}

func TestAuthMiddleware_ReusesOwnAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name    string
		expired bool
	}{
		{name: "valid session"},
		{name: "transparent refresh", expired: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &countingAuthenticator{session: &domain.Session{ID: "session", UserID: "user"}, user: &domain.User{ID: "user"}, expired: tc.expired}
			users := &infrastructureUserReader{user: svc.user}
			auth := AuthMiddleware(svc, DefaultCookieSettings(), users, nil)
			called := 0
			h := auth(auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called++
				if GetUserFromContext(r.Context()) != svc.user || GetSessionFromContext(r.Context()) != svc.session {
					t.Fatal("missing authenticated identity")
				}
				w.WriteHeader(204)
			})))
			r := httptest.NewRequest("GET", "/", nil)
			r.AddCookie(secureRequestCookie(DefaultCookieSettings().Name, "access"))
			r.AddCookie(secureRequestCookie(DefaultCookieSettings().RefreshName, "refresh"))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			wantRefresh := 0
			if tc.expired {
				wantRefresh = 1
			}
			if w.Code != 204 || called != 1 || svc.validations != 1 || svc.touches != 1 || svc.refreshes != wantRefresh {
				t.Fatalf("status=%d called=%d validations=%d touches=%d refreshes=%d", w.Code, called, svc.validations, svc.touches, svc.refreshes)
			}
		})
	}
}

func TestAuthMiddleware_DoesNotTrustPublicIdentitySetters(t *testing.T) {
	svc := &countingAuthenticator{}
	r := httptest.NewRequest("GET", "/", nil)
	ctx := ContextWithUser(r.Context(), &domain.User{ID: "forged"})
	ctx = ContextWithSession(ctx, &domain.Session{ID: "forged", UserID: "forged"})
	w := httptest.NewRecorder()
	AuthMiddleware(svc, DefaultCookieSettings(), nil, nil)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("public setters bypassed authentication")
	})).ServeHTTP(w, r.WithContext(ctx))
	if w.Code != 401 {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestAuthMiddleware_ReuseIsBoundToCredentialsAndInstance(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		change                      func(*http.Request) *http.Request
		otherInstance               bool
		wantStatus, wantValidations int
	}{
		{name: "changed cookie", change: func(r *http.Request) *http.Request {
			r.Header.Set("Cookie", DefaultCookieSettings().Name+"=different")
			return r
		}, wantStatus: 401, wantValidations: 2},
		{name: "removed cookie", change: func(r *http.Request) *http.Request {
			r.Header.Del("Cookie")
			return r
		}, wantStatus: 401, wantValidations: 1},
		{name: "changed session context", change: func(r *http.Request) *http.Request {
			return r.WithContext(sessioncontext.With(r.Context(), sessioncontext.Admin))
		}, wantStatus: 401, wantValidations: 1},
		{name: "replaced user", change: func(r *http.Request) *http.Request {
			return r.WithContext(ContextWithUser(r.Context(), &domain.User{ID: "other"}))
		}, wantStatus: 204, wantValidations: 2},
		{name: "different authenticator", otherInstance: true, wantStatus: 204, wantValidations: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := &countingAuthenticator{session: &domain.Session{ID: "session", UserID: "user"}, user: &domain.User{ID: "user"}}
			auth := AuthMiddleware(svc, DefaultCookieSettings(), nil, nil)
			inner := auth
			if tc.otherInstance {
				inner = AuthMiddleware(svc, DefaultCookieSettings(), nil, nil)
			}
			h := auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.change != nil {
					r = tc.change(r)
				}
				inner(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if GetUserFromContext(r.Context()) != svc.user {
						t.Fatal("identity replacement survived reauthentication")
					}
					w.WriteHeader(204)
				})).ServeHTTP(w, r)
			}))
			r := httptest.NewRequest("GET", "/", nil)
			r.AddCookie(secureRequestCookie(DefaultCookieSettings().Name, "access"))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.wantStatus || svc.validations != tc.wantValidations {
				t.Fatalf("status=%d validations=%d", w.Code, svc.validations)
			}
		})
	}
}
