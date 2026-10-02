package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/middleware"
)

// OAuthHandlers serves OAuth endpoints.
type OAuthHandlers struct {
	oauth        *service.OAuthService
	baseURL      string
	csrfTokenCfg *middleware.CSRFTokenConfig
	// cookies is the resolved session/refresh cookie scope, pushed at
	// construction like Handler.cookies — see handler.go.
	cookies middleware.CookieSettings
	// clientIP — see Handler.clientIP.
	clientIP  middleware.ClientIPConfig
	log       *slog.Logger
	twoFactor *service.TwoFactorService
}

// AttachTwoFactor provides challenge cookie settings for OAuth admin login.
func (h *OAuthHandlers) AttachTwoFactor(twoFactor *service.TwoFactorService) { h.twoFactor = twoFactor }

// NewOAuthHandlers returns OAuth HTTP handlers.
func NewOAuthHandlers(oauth *service.OAuthService, baseURL string, csrfTokenCfg *middleware.CSRFTokenConfig, clientIP middleware.ClientIPConfig, cookies middleware.CookieSettings, logger *slog.Logger) *OAuthHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &OAuthHandlers{
		oauth:        oauth,
		baseURL:      baseURL,
		csrfTokenCfg: csrfTokenCfg,
		clientIP:     clientIP,
		cookies:      cookies,
		log:          logger,
	}
}

func (h *OAuthHandlers) disabled() bool {
	return h.oauth == nil
}

// Initiate starts an OAuth login.
// GET /auth/oauth/{provider}
func (h *OAuthHandlers) Initiate(w http.ResponseWriter, r *http.Request) {
	if h.disabled() {
		h.writeError(w, domain.ErrProviderNotFound)
		return
	}
	provider := r.PathValue("provider")
	flow, err := h.oauth.Initiate(r.Context(), provider)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.setOAuthStateCookie(w, flow.State, 600)
	h.writeJSON(w, http.StatusOK, map[string]string{"url": flow.URL})
}

// InitiateLink starts linking an OAuth provider.
// POST /auth/oauth/{provider}/link — requires auth
func (h *OAuthHandlers) InitiateLink(w http.ResponseWriter, r *http.Request) {
	if h.disabled() {
		h.writeError(w, domain.ErrProviderNotFound)
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	session := middleware.GetSessionFromContext(r.Context())
	if user == nil || session == nil {
		h.writeError(w, domain.NewError("unauthorized", "Authentication required"))
		return
	}

	provider := r.PathValue("provider")
	flow, err := h.oauth.InitiateLink(r.Context(), provider, user.ID, session.TokenHash)
	if err != nil {
		h.writeError(w, err)
		return
	}
	h.setOAuthStateCookie(w, flow.State, 600)
	h.writeJSON(w, http.StatusOK, map[string]string{"url": flow.URL})
}

func (h *OAuthHandlers) oauthStateCookie(state string, maxAge int) *http.Cookie {
	hash := sha256.Sum256([]byte(state))
	name := "goauth_oauth_" + hex.EncodeToString(hash[:8])
	sameSite := http.SameSiteLaxMode
	if h.cookies.Secure {
		name = "__Host-" + name
		// Some providers deliver callbacks through cross-site form POST.
		sameSite = http.SameSiteNoneMode
	}
	cookie := &http.Cookie{Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
	cookie.Name = name
	cookie.Value = state
	cookie.Path = "/"
	cookie.MaxAge = maxAge
	cookie.Expires = time.Now().Add(time.Duration(maxAge) * time.Second)
	cookie.Secure = h.cookies.Secure
	cookie.SameSite = sameSite
	return cookie
}

func (h *OAuthHandlers) setOAuthStateCookie(w http.ResponseWriter, state string, maxAge int) {
	http.SetCookie(w, h.oauthStateCookie(state, maxAge))
}

// Callback completes an OAuth login or provider link.
// GET /auth/oauth/{provider}/callback, POST /auth/oauth/{provider}/callback
func (h *OAuthHandlers) Callback(w http.ResponseWriter, r *http.Request) {
	if h.disabled() {
		h.writeError(w, domain.ErrProviderNotFound)
		return
	}
	provider := r.PathValue("provider")
	code := r.FormValue("code")
	state := r.FormValue("state")

	if code == "" || state == "" {
		redirectURL := h.baseURL + "/auth/callback?error=invalid_request&provider=" + url.QueryEscape(provider)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}
	stateCookie, cookieErr := r.Cookie(h.oauthStateCookie(state, 0).Name)
	browserState := ""
	if cookieErr == nil {
		browserState = stateCookie.Value
		h.setOAuthStateCookie(w, state, -1)
	}
	sessionToken := ""
	if sessionCookie, err := r.Cookie(h.cookies.Name); err == nil {
		sessionToken = sessionCookie.Value
	}

	result, err := h.oauth.Callback(r.Context(), provider, code, state, browserState, sessionToken, middleware.ClientIP(r, h.clientIP), r.UserAgent())
	if err != nil {
		errCode := "internal_error"
		var authErr *domain.AuthError
		if errors.As(err, &authErr) {
			errCode = authErr.Code
		}
		redirectURL := h.baseURL + "/auth/callback?error=" + url.QueryEscape(errCode) + "&provider=" + url.QueryEscape(provider)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	middleware.RotateCSRFToken(w, h.csrfTokenCfg)

	if result.IsLink {
		// The caller already had a valid session before starting the link
		// flow — Callback issued no new one, so there's nothing to write.
		// Must not fall through to writeCookieRedirect: an empty
		// SessionToken there would blank the caller's live session cookie.
		http.Redirect(w, r, h.baseURL+"/auth/callback", http.StatusFound)
		return
	}

	if result.RequiresVerification {
		redirectURL := h.baseURL + "/auth/callback?requiresVerification=true&provider=" + url.QueryEscape(provider)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}
	if result.RequiresTwoFactor {
		if h.twoFactor == nil {
			http.Redirect(w, r, h.baseURL+"/auth/callback?error=internal_error", http.StatusFound)
			return
		}
		if !h.twoFactor.BindingDisabled() && result.BindingToken() != "" {
			http.SetCookie(w, newBindingCookie(bindingCookieParams{
				name: h.twoFactor.CookieName(), value: result.BindingToken(),
				domain: h.cookies.Domain, path: h.cookies.Path, secure: h.cookies.Secure,
				sameSite: h.cookies.SameSite, maxAge: int(h.twoFactor.CookieTTL().Seconds()),
			}))
		}
		params := url.Values{
			"requiresTwoFactor": {"true"}, "provider": {provider},
			"challengeId": {result.TwoFactorChallenge},
			"expiresAt":   {result.TwoFactorExpiresAt.Format(time.RFC3339)},
		}
		http.Redirect(w, r, h.baseURL+"/auth/callback?"+params.Encode(), http.StatusFound)
		return
	}

	redirectURL := h.baseURL + "/auth/callback"
	h.writeCookieRedirect(w, result.SessionToken, result.RefreshToken, redirectURL)
}

// writeCookieRedirect returns a small HTML page that sets cookies via Set-Cookie headers
// then redirects via JS. This is needed because Set-Cookie headers on cross-origin
// 302 redirects are unreliable in some browsers.
func (h *OAuthHandlers) writeCookieRedirect(w http.ResponseWriter, sessionToken, refreshToken, redirectURL string) {
	middleware.SetSessionCookie(w, h.cookies, sessionToken)
	middleware.SetRefreshCookie(w, h.cookies, refreshToken)

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Redirecting...</title></head><body>
<script>window.location.replace(%q);</script>
<noscript>JavaScript required. <a href=%q>Click here</a>.</noscript>
</body></html>`,
		redirectURL,
		redirectURL,
	); err != nil {
		h.log.Warn("oauth redirect response write failed", "err", err)
	}
}

// Unlink removes an OAuth provider from the authenticated user.
// POST /auth/oauth/{provider}/unlink — requires auth
func (h *OAuthHandlers) Unlink(w http.ResponseWriter, r *http.Request) {
	if h.disabled() {
		h.writeError(w, domain.ErrProviderNotFound)
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		h.writeError(w, domain.NewError("unauthorized", "Authentication required"))
		return
	}

	provider := r.PathValue("provider")
	if err := h.oauth.Unlink(r.Context(), user.ID, provider); err != nil {
		h.writeError(w, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"message": "Provider unlinked"})
}

// ListConnected returns the authenticated user's linked providers.
// GET /auth/oauth/providers — requires auth
func (h *OAuthHandlers) ListConnected(w http.ResponseWriter, r *http.Request) {
	if h.disabled() {
		h.writeError(w, domain.ErrProviderNotFound)
		return
	}
	user := middleware.GetUserFromContext(r.Context())
	if user == nil {
		h.writeError(w, domain.NewError("unauthorized", "Authentication required"))
		return
	}

	accounts, err := h.oauth.ListConnected(r.Context(), user.ID)
	if err != nil {
		h.writeError(w, err)
		return
	}

	// Return only safe fields — no access/refresh tokens
	type safeAccount struct {
		Provider      string `json:"provider"`
		ProviderEmail string `json:"email"`
		ProviderName  string `json:"name"`
		AvatarURL     string `json:"avatarUrl"`
		CreatedAt     string `json:"createdAt"`
	}
	safe := make([]safeAccount, len(accounts))
	for i, a := range accounts {
		safe[i] = safeAccount{
			Provider:      a.Provider,
			ProviderEmail: a.ProviderEmail,
			ProviderName:  a.ProviderName,
			AvatarURL:     a.AvatarURL,
			CreatedAt:     a.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}
	h.writeJSON(w, http.StatusOK, map[string]interface{}{"providers": safe})
}
