package middleware

import (
	"net/http"

	"github.com/nazimdjebloun/go-auth/service"
)

// SetSessionCookie writes the session cookie for a newly issued or rotated
// session token, using the session cookie settings in cfg.
func SetSessionCookie(w http.ResponseWriter, cfg service.SessionConfig, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    token,
		Domain:   cfg.Domain,
		Path:     cfg.Path,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: http.SameSite(cfg.SameSite),
		MaxAge:   int(cfg.Duration.Seconds()),
	})
}

// ClearSessionCookie expires the session cookie.
func ClearSessionCookie(w http.ResponseWriter, cfg service.SessionConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.CookieName,
		Value:    "",
		Domain:   cfg.Domain,
		Path:     cfg.Path,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: http.SameSite(cfg.SameSite),
		MaxAge:   -1,
	})
}

// SetRefreshCookie writes the refresh cookie for a newly issued or rotated
// refresh token, using the session cookie settings in cfg. A no-op when
// token is empty — not every flow issues a refresh token.
func SetRefreshCookie(w http.ResponseWriter, cfg service.SessionConfig, token string) {
	if token == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.RefreshCookieName,
		Value:    token,
		Domain:   cfg.Domain,
		Path:     cfg.Path,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: http.SameSite(cfg.SameSite),
		MaxAge:   int(cfg.RefreshTTL.Seconds()),
	})
}

// ClearRefreshCookie expires the refresh cookie.
func ClearRefreshCookie(w http.ResponseWriter, cfg service.SessionConfig) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.RefreshCookieName,
		Value:    "",
		Domain:   cfg.Domain,
		Path:     cfg.Path,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: http.SameSite(cfg.SameSite),
		MaxAge:   -1,
	})
}
