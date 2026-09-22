package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

type infrastructureSessionRepo struct {
	port.SessionRepository
	validateErr, refreshErr error
	refreshCalls            int
}

var _ SessionAuthenticator = (*service.SessionService)(nil)

func (s *infrastructureSessionRepo) GetByTokenHashWithUser(context.Context, string) (*domain.Session, *domain.User, error) {
	return nil, nil, s.validateErr
}

func (s *infrastructureSessionRepo) UpdateRefreshToken(context.Context, port.UpdateRefreshInput) (*domain.Session, error) {
	s.refreshCalls++
	if s.refreshErr != nil {
		return nil, s.refreshErr
	}
	return &domain.Session{ID: "session", UserID: "user", LastActiveAt: time.Now()}, nil
}

type infrastructureUserReader struct {
	user  *domain.User
	err   error
	calls int
}

func (u *infrastructureUserReader) GetByID(context.Context, string) (*domain.User, error) {
	u.calls++
	return u.user, u.err
}

func TestAuthMiddleware_InfrastructureErrors(t *testing.T) {
	backend := errors.New("database unavailable")
	cases := []struct {
		name                             string
		validateErr, refreshErr, userErr error
		status                           int
		code                             string
		refreshCalls, userCalls, cookies int
	}{
		{"validate backend", backend, nil, nil, 500, "internal_error", 0, 0, 0},
		{"validate canceled", context.Canceled, nil, nil, 500, "internal_error", 0, 0, 0},
		{"validate missing", fmt.Errorf("lookup: %w", domain.ErrSessionNotFound), nil, nil, 401, "unauthorized", 0, 0, 0},
		{"refresh backend", domain.ErrSessionExpired, backend, nil, 500, "internal_error", 1, 0, 0},
		{"refresh deadline", domain.ErrSessionExpired, context.DeadlineExceeded, nil, 500, "internal_error", 1, 0, 0},
		{"refresh invalid", domain.ErrSessionExpired, domain.ErrInvalidRefreshToken, nil, 401, "session_expired", 1, 0, 0},
		{"refresh revoked", domain.ErrSessionExpired, domain.ErrSessionRevoked, nil, 401, "session_expired", 1, 0, 0},
		{"refresh rotated", domain.ErrSessionExpired, domain.ErrTokenAlreadyRotated, nil, 401, "session_expired", 1, 0, 0},
		{"user backend after rotation", domain.ErrSessionExpired, nil, backend, 500, "internal_error", 1, 1, 2},
		{"user absent after rotation", domain.ErrSessionExpired, nil, nil, 401, "unauthorized", 1, 1, 2},
		{"user not found sentinel", domain.ErrSessionExpired, nil, fmt.Errorf("lookup: %w", domain.ErrUserNotFound), 401, "unauthorized", 1, 1, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&logs, nil))
			repo := &infrastructureSessionRepo{validateErr: tc.validateErr, refreshErr: tc.refreshErr}
			users := &infrastructureUserReader{err: tc.userErr}
			cfg := service.DefaultSessionConfig()
			cfg.Logger = logger
			svc := service.NewSessionService(repo, &testutil.MockTokenGen{Length: 32}, cfg)
			cookies := DefaultCookieSettings()
			handler := AuthMiddleware(svc, cookies, users, logger)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("protected handler ran") }))
			req := httptest.NewRequest("GET", "/private?secret=query-secret", nil)
			req.AddCookie(&http.Cookie{Name: cookies.Name, Value: "raw-session-secret"})
			req.AddCookie(&http.Cookie{Name: cookies.RefreshName, Value: "raw-refresh-secret"})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status=%d body=%s, want %d", rec.Code, rec.Body, tc.status)
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if len(body) != 2 || body["error"] != tc.code {
				t.Fatalf("unexpected envelope: %v", body)
			}
			if tc.status == 500 && body["message"] != domain.ErrInternal.Message {
				t.Fatalf("unsafe message: %v", body)
			}
			if repo.refreshCalls != tc.refreshCalls || users.calls != tc.userCalls {
				t.Fatalf("unexpected calls: refresh=%d user=%d", repo.refreshCalls, users.calls)
			}
			if got := rec.Result().Cookies(); len(got) != tc.cookies {
				t.Fatalf("cookies=%d want %d", len(got), tc.cookies)
			} else {
				for _, c := range got {
					if c.Value == "" || c.MaxAge < 0 {
						t.Fatal("rotated credential discarded")
					}
				}
			}
			if tc.status == 500 && !strings.Contains(logs.String(), "level=ERROR") {
				t.Fatal("missing operational error log")
			}
			for _, secret := range []string{"raw-session-secret", "raw-refresh-secret", "query-secret"} {
				if strings.Contains(logs.String()+rec.Body.String(), secret) {
					t.Fatalf("leaked %s", secret)
				}
			}
			if strings.Contains(rec.Body.String(), backend.Error()) {
				t.Fatal("backend detail exposed")
			}
		})
	}
}
