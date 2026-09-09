package middleware

import (
	"net/http"
	"time"
)

// CookieSettings is everything the session and refresh cookies are written
// from. middleware owns this shape rather than taking the service layer's
// session config: these helpers only ever read plain values, and a delivery-
// layer package should not put a service type in its exported signatures.
type CookieSettings struct {
	Name        string // session cookie name
	RefreshName string // refresh cookie name
	Domain      string
	Path        string
	Secure      bool
	SameSite    http.SameSite
	TTL         time.Duration // session cookie MaxAge
	RefreshTTL  time.Duration // refresh cookie MaxAge
}

// SetSessionCookie writes the session cookie for a newly issued or rotated
// session token, using the session cookie settings in cfg. A no-op when
// token is empty, mirroring SetRefreshCookie — an empty token here almost
// certainly means a caller forgot to check for a flow (like an OAuth link
// callback) that doesn't issue a new session and shouldn't touch cookies at
// all, and writing it anyway would silently blank the caller's live session
// cookie. Use ClearSessionCookie to actually clear one.
func SetSessionCookie(w http.ResponseWriter, cfg CookieSettings, token string) {
	if token == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Name,
		Value:    token,
		Domain:   cfg.Domain,
		Path:     cfg.Path,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		MaxAge:   int(cfg.TTL.Seconds()),
	})
}

// ClearSessionCookie expires the session cookie.
func ClearSessionCookie(w http.ResponseWriter, cfg CookieSettings) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.Name,
		Value:    "",
		Domain:   cfg.Domain,
		Path:     cfg.Path,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		MaxAge:   -1,
	})
}

// SetRefreshCookie writes the refresh cookie for a newly issued or rotated
// refresh token, using the session cookie settings in cfg. A no-op when
// token is empty — not every flow issues a refresh token.
func SetRefreshCookie(w http.ResponseWriter, cfg CookieSettings, token string) {
	if token == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.RefreshName,
		Value:    token,
		Domain:   cfg.Domain,
		Path:     cfg.Path,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		MaxAge:   int(cfg.RefreshTTL.Seconds()),
	})
}

// ClearRefreshCookie expires the refresh cookie.
func ClearRefreshCookie(w http.ResponseWriter, cfg CookieSettings) {
	http.SetCookie(w, &http.Cookie{
		Name:     cfg.RefreshName,
		Value:    "",
		Domain:   cfg.Domain,
		Path:     cfg.Path,
		HttpOnly: true,
		Secure:   cfg.Secure,
		SameSite: cfg.SameSite,
		MaxAge:   -1,
	})
}

// DefaultCookieSettings mirrors the service layer's built-in session
// defaults for tests and zero-value handlers. Production code never uses
// this — New() builds the real value from the resolved config via
// cookiesFromSession in wire.go.
func DefaultCookieSettings() CookieSettings {
	return CookieSettings{
		Name:        "goauth_session",
		RefreshName: "goauth_refresh",
		Path:        "/",
		Secure:      true,
		SameSite:    http.SameSiteLaxMode,
		TTL:         7 * 24 * time.Hour,
		RefreshTTL:  30 * 24 * time.Hour,
	}
}
