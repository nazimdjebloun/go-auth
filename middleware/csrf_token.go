package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/httperr"
	"github.com/nazimdjebloun/go-auth/internal/sessioncontext"
)

// CSRFHeaderName is the required browser mutation header and rotation response header.
const CSRFHeaderName = "X-CSRF-Token"
const csrfCookieName = "_csrf"

// CSRFSessionReader resolves session identity without authorizing a request.
// Expiry and account policy remain the authentication middleware's responsibility.
type CSRFSessionReader interface {
	GetByTokenHashWithUser(context.Context, string) (*domain.Session, *domain.User, error)
	GetByRefreshHash(context.Context, string) (*domain.Session, error)
	GetByPreviousRefreshHash(context.Context, string) (*domain.Session, error)
}

// CSRFTokenConfig supplies middleware dependencies. goauth.New constructs this
// itself; application configuration has no CSRF overrides or disabling switch.
// A nil config or missing key fails closed, including on safe methods.
type CSRFTokenConfig struct {
	CookieSecure       bool
	CookieSameSite     http.SameSite
	Secret             []byte
	Logger             *slog.Logger
	SessionCookie      string
	RefreshCookie      string
	AdminSessionCookie string
	AdminRefreshCookie string
	scope              sessioncontext.Scope
	Sessions           CSRFSessionReader
	ValidateSession    func(*domain.Session) error
}

func (c *CSRFTokenConfig) defaults() {
	if c.CookieSameSite == 0 {
		c.CookieSameSite = http.SameSiteLaxMode
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

func (c *CSRFTokenConfig) forRequest(r *http.Request) *CSRFTokenConfig {
	if c == nil {
		return nil
	}
	resolved := *c
	resolved.scope = sessioncontext.Current(r.Context())
	if resolved.scope == sessioncontext.Admin {
		resolved.SessionCookie, resolved.RefreshCookie = c.AdminSessionCookie, c.AdminRefreshCookie
		if resolved.SessionCookie == "" {
			resolved.SessionCookie = "goauth_admin_session"
		}
		if resolved.RefreshCookie == "" {
			resolved.RefreshCookie = "goauth_admin_refresh"
		}
	}
	return &resolved
}
func (c *CSRFTokenConfig) cookieName() string {
	if c.scope == sessioncontext.Admin {
		return "_goauth_admin_csrf"
	}
	return csrfCookieName
}
func (c *CSRFTokenConfig) bindingPurpose() string {
	if c.scope == sessioncontext.Admin {
		return "admin:browser-cookie"
	}
	return "browser-cookie"
}
func (c *CSRFTokenConfig) sessionBinding(id string) string {
	if c.scope == sessioncontext.Admin {
		return "admin:session:" + id
	}
	return "session:" + id
}
func (c *CSRFTokenConfig) browserCookieName() string {
	if c.scope == sessioncontext.Admin {
		if c.CookieSecure {
			return "__Host-goauth_admin_browser"
		}
		return "_goauth_admin_browser"
	}

	if c.CookieSecure {
		return "__Host-goauth_browser"
	}
	return "_goauth_browser"
}

type csrfCtxKey struct{}
type csrfState struct{ token, binding string }
type sessionSnapshotKey struct{}
type sessionSnapshot struct {
	token   string
	session *domain.Session
	user    *domain.User
	err     error
}

// CSRFTokenFromContext returns the validated or newly issued request token.
func CSRFTokenFromContext(ctx context.Context) string {
	s, _ := ctx.Value(csrfCtxKey{}).(csrfState)
	return s.token
}

// ContextWithCSRFToken supplies a token to a transport handler. It does not
// establish a browser/session binding or bypass verification.
func ContextWithCSRFToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, csrfCtxKey{}, csrfState{token: token})
}

func csrfHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// csrfBinding loads identity once; AuthMiddleware reuses the access-token
// snapshot and applies the exact same liveness and account checks as usual.
// Refresh-token lookup only establishes CSRF identity, never authentication.
func csrfBinding(r *http.Request, c *CSRFTokenConfig) (*http.Request, string, error) {
	if session := GetSessionFromContext(r.Context()); session != nil {
		return r, c.sessionBinding(session.ID), nil
	}
	if c.Sessions != nil {
		if cookie, err := r.Cookie(c.SessionCookie); err == nil && cookie.Value != "" && sessioncontext.Matches(r.Context(), cookie.Value) {
			session, user, err := c.Sessions.GetByTokenHashWithUser(r.Context(), csrfHash(cookie.Value))
			if err != nil {
				return r, "", err
			}
			var validation error
			if session == nil {
				validation = domain.ErrSessionNotFound
			} else if c.ValidateSession != nil {
				validation = c.ValidateSession(session)
			}
			if c.ValidateSession != nil {
				snapshot := sessionSnapshot{token: cookie.Value, session: session, user: user, err: validation}
				r = r.WithContext(context.WithValue(r.Context(), sessionSnapshotKey{}, snapshot))
			}
			if session != nil && !session.IsRevoked {
				return r, c.sessionBinding(session.ID), nil
			}
		}
		if cookie, err := r.Cookie(c.RefreshCookie); err == nil && cookie.Value != "" && sessioncontext.Matches(r.Context(), cookie.Value) {
			hash := csrfHash(cookie.Value)
			session, err := c.Sessions.GetByRefreshHash(r.Context(), hash)
			if err != nil {
				return r, "", err
			}
			if session == nil {
				session, err = c.Sessions.GetByPreviousRefreshHash(r.Context(), hash)
				if err != nil {
					return r, "", err
				}
			}
			if session != nil && !session.IsRevoked {
				return r, c.sessionBinding(session.ID), nil
			}
		}
	}
	if cookie, err := r.Cookie(c.browserCookieName()); err == nil && verifyCSRFToken(cookie.Value, c.Secret, c.bindingPurpose()) {
		return r, "browser:" + cookie.Value, nil
	}
	return r, "", nil
}

func csrfError(w http.ResponseWriter, c *CSRFTokenConfig, err error) {
	logger := slog.Default()
	if c != nil && c.Logger != nil {
		logger = c.Logger
	}
	logger.Error("goauth: CSRF protection failed", "err", err)
	httperr.Write(w, http.StatusInternalServerError, "internal_error", "Internal server error", logger)
}

// CSRFToken requires a signed, browser/session-bound cookie and matching
// X-CSRF-Token header on every unsafe method. Safe methods repair invalid
// tokens and supply a token to the bootstrap handler. There is no passthrough.
func CSRFToken(config *CSRFTokenConfig) func(http.Handler) http.Handler {
	var cfg *CSRFTokenConfig
	if config != nil {
		resolved := *config
		resolved.defaults()
		cfg = &resolved
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			request, err := resolveBrowserSession(r, false)
			if err != nil {
				httperr.Write(w, 400, domain.ErrInvalidSessionContext.Code, domain.ErrInvalidSessionContext.Message, nil)
				return
			}
			r = request
			cfg := cfg.forRequest(r)
			if cfg == nil || len(cfg.Secret) == 0 {
				csrfError(w, cfg, errors.New("missing CSRF signing configuration"))
				return
			}
			safe := r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions
			if !safe {
				cookie, err := r.Cookie(cfg.cookieName())
				if err != nil || cookie.Value == "" || r.Header.Get(CSRFHeaderName) == "" {
					httperr.Write(w, 403, "csrf_token_missing", "CSRF cookie and header are required", cfg.Logger)
					return
				}
				if subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(r.Header.Get(CSRFHeaderName))) != 1 {
					httperr.Write(w, 403, "csrf_token_mismatch", "CSRF cookie and header do not match", cfg.Logger)
					return
				}
			}
			request, binding, err := csrfBinding(r, cfg)
			if err != nil {
				csrfError(w, cfg, err)
				return
			}
			r = request
			if safe && binding == "" {
				binding, err = newBrowserBinding(w, cfg)
				if err != nil {
					csrfError(w, cfg, err)
					return
				}
			}
			active := ""
			if cookie, err := r.Cookie(cfg.cookieName()); err == nil {
				active = cookie.Value
			}
			if !safe {
				if binding == "" || !verifyCSRFToken(active, cfg.Secret, binding) {
					httperr.Write(w, 403, "csrf_token_invalid", "CSRF token is invalid for this browser or session", cfg.Logger)
					return
				}
			} else {
				w.Header().Set("Cache-Control", "no-store")
				if !verifyCSRFToken(active, cfg.Secret, binding) {
					active, err = generateCSRFToken(32, cfg.Secret, binding)
					if err != nil {
						csrfError(w, cfg, err)
						return
					}
					setCSRFCookie(w, cfg, active)
				}
			}
			r = r.WithContext(context.WithValue(r.Context(), csrfCtxKey{}, csrfState{token: active, binding: binding}))
			next.ServeHTTP(w, r)
		})
	}
}

func newBrowserBinding(w http.ResponseWriter, c *CSRFTokenConfig) (string, error) {
	value, err := generateCSRFToken(32, c.Secret, c.bindingPurpose())
	if err != nil {
		return "", err
	}
	http.SetCookie(w, newResponseCookie(responseCookieParams{name: c.browserCookieName(), value: value, path: "/", httpOnly: true, secure: c.CookieSecure, sameSite: c.CookieSameSite}))
	return "browser:" + value, nil
}

// RotateCSRFToken replaces the token using the current request context. A
// supplied sessionID binds a newly issued session; an explicitly empty ID
// creates a new anonymous browser binding after logout or credential revocation.
// It returns an error rather than silently skipping protection.
func RotateCSRFToken(w http.ResponseWriter, r *http.Request, c *CSRFTokenConfig, sessionID ...string) error {
	if c == nil || len(c.Secret) == 0 {
		return errors.New("missing CSRF signing configuration")
	}
	request, err := resolveBrowserSession(r, false)
	if err != nil {
		return err
	}
	r = request
	cfg := *c.forRequest(r)
	cfg.defaults()
	binding := ""
	if len(sessionID) > 0 {
		if sessionID[0] != "" {
			binding = cfg.sessionBinding(sessionID[0])
		} else {
			binding = ""
		}
	} else {
		// Re-resolve after the credential operation: password reset may have
		// deleted the session that was present when middleware ran.
		var err error
		_, binding, err = csrfBinding(r, &cfg)
		if err != nil {
			return err
		}
	}
	if binding == "" {
		var err error
		binding, err = newBrowserBinding(w, &cfg)
		if err != nil {
			return err
		}
	}
	token, err := generateCSRFToken(32, cfg.Secret, binding)
	if err != nil {
		return err
	}
	setCSRFCookie(w, &cfg, token)
	return nil
}

// SetAuthenticationCookies issues credentials and their session-bound CSRF
// token together. Generate the CSRF token before writing credential cookies.
func SetAuthenticationCookies(w http.ResponseWriter, r *http.Request, cookies CookieSettings, c *CSRFTokenConfig, sessionID, sessionToken, refreshToken string) error {
	request, err := resolveBrowserSession(r, false)
	if err != nil {
		return err
	}
	r = request
	cookies = cookies.ForRequest(r)
	if sessioncontext.Of(sessionToken) != sessioncontext.Current(r.Context()) || (refreshToken != "" && sessioncontext.Of(refreshToken) != sessioncontext.Current(r.Context())) {
		return domain.ErrInvalidSessionContext
	}
	if sessionID == "" || sessionToken == "" {
		return errors.New("session identity and token are required")
	}
	if err := RotateCSRFToken(w, r, c, sessionID); err != nil {
		return err
	}
	SetSessionCookie(w, cookies, sessionToken)
	SetRefreshCookie(w, cookies, refreshToken)
	return nil
}

// ClearAuthenticationCookies clears credentials and supplies a fresh anonymous
// token. Call it after the service has successfully revoked the session.
func ClearAuthenticationCookies(w http.ResponseWriter, r *http.Request, cookies CookieSettings, c *CSRFTokenConfig) error {
	cookies = cookies.ForRequest(r)
	if err := RotateCSRFToken(w, r, c, ""); err != nil {
		return err
	}
	ClearSessionCookie(w, cookies)
	ClearRefreshCookie(w, cookies)
	return nil
}

func generateCSRFToken(length int, secret []byte, binding ...string) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("csrf: signing secret is empty")
	}
	if length < 1 {
		return "", fmt.Errorf("csrf: token length must be positive, got %d", length)
	}
	nonce := make([]byte, length)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(nonce)
	context := ""
	if len(binding) > 0 {
		context = binding[0]
	}
	return encoded + "." + csrfSignature(secret, context, encoded), nil
}

func csrfSignature(secret []byte, binding, nonce string) string {
	mac := hmac.New(sha256.New, secret)
	// Length prefixes separate purpose/binding from the random nonce.
	_, _ = mac.Write([]byte("goauth-csrf-v2:" + strconv.Itoa(len(binding)) + ":" + binding + ":" + nonce))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifyCSRFToken(token string, secret []byte, binding ...string) bool {
	if len(secret) == 0 || len(token) > 8192 {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(nonce) == 0 {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(signature) != sha256.Size {
		return false
	}
	context := ""
	if len(binding) > 0 {
		context = binding[0]
	}
	expected := csrfSignature(secret, context, parts[0])
	return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) == 1
}

func setCSRFCookie(w http.ResponseWriter, c *CSRFTokenConfig, token string) {
	http.SetCookie(w, newResponseCookie(responseCookieParams{name: c.cookieName(), value: token, path: "/", httpOnly: true, secure: c.CookieSecure, sameSite: c.CookieSameSite}))
	w.Header().Set("X-CSRF-Token", token)
	w.Header().Set("Cache-Control", "no-store")
}
