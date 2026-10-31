package middleware

import (
	"log/slog"
	"net/http"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/httperr"
	"github.com/nazimdjebloun/go-auth/internal/sessioncontext"
)

// BrowserSession selects app (default) or admin credentials for one request.
// It never grants permissions and never falls back to the other cookie set.
// adminLogin fixes the context for the dedicated admin login endpoint.
func BrowserSession(logger *slog.Logger, adminLogin bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			request, err := resolveBrowserSession(r, adminLogin)
			if err != nil {
				httperr.Write(w, http.StatusBadRequest, domain.ErrInvalidSessionContext.Code, domain.ErrInvalidSessionContext.Message, logger)
				return
			}
			r = request
			next.ServeHTTP(w, r)
		})
	}
}

// ForRequest resolves the selected session, refresh, and challenge cookie names.
func (c CookieSettings) ForRequest(r *http.Request) CookieSettings {
	request, err := resolveBrowserSession(r, false)
	if err == nil {
		r = request
	}
	if sessioncontext.Current(r.Context()) == sessioncontext.Admin {
		c.Name, c.RefreshName, c.ChallengeName = c.AdminName, c.AdminRefreshName, c.AdminChallengeName
		if c.Name == "" {
			c.Name = "goauth_admin_session"
		}
		if c.RefreshName == "" {
			c.RefreshName = "goauth_admin_refresh"
		}
		if c.ChallengeName == "" {
			c.ChallengeName = "_goauth_admin_2fa_challenge"
		}
	}
	return c
}

func resolveBrowserSession(r *http.Request, adminLogin bool) (*http.Request, error) {
	values := r.Header.Values(sessioncontext.Header)
	value := r.Header.Get(sessioncontext.Header)
	if len(values) > 1 || (value != "" && value != "app" && value != "admin") || (adminLogin && value == "app") {
		return r, domain.ErrInvalidSessionContext
	}
	if adminLogin {
		return r.WithContext(sessioncontext.With(r.Context(), sessioncontext.Admin)), nil
	}
	if sessioncontext.Explicit(r.Context()) {
		return r, nil
	}
	scope := sessioncontext.App
	if value == "admin" {
		scope = sessioncontext.Admin
	}
	return r.WithContext(sessioncontext.With(r.Context(), scope)), nil
}
