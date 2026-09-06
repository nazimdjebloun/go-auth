package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
)

// RemoteAuth authenticates requests against a *remote* go-auth server instead
// of a local database. It is the counterpart to AuthMiddleware: same context
// contract, no persistence layer.
//
// The use case is a service that fronts a go-auth API but does not own its
// data — an admin console, a BFF, a gateway. Such a service has no business
// holding the application's database credentials, and standing up a second
// goauth.Auth just to reuse its middleware means duplicating the whole auth
// configuration (session TTLs, org enablement, audit retention) with nothing
// keeping the two copies in sync.
//
// RemoteAuth resolves the caller by forwarding their cookies to the upstream
// server's GET /auth/me and decoding the domain.User it returns. Because it
// stores the user under the same context key AuthMiddleware uses,
// GetUserFromContext and RequireRole work downstream without knowing which
// one authenticated the request.
//
//	remote, err := middleware.NewRemoteAuth("https://api.example.com")
//	if err != nil {
//		log.Fatal(err)
//	}
//	mux.Handle("GET /admin/reports", remote.RequireAdmin(reportsHandler))
//
// Every request asks upstream. There is deliberately no caching of the
// result: AuthMiddleware re-reads the session and the user from the database
// on every request, so a revoked session or a demoted admin stops working on
// the very next call. Caching the answer here would reintroduce exactly the
// window that design eliminates — a demoted admin would keep admin rights for
// the cache lifetime, and UpdateUserRole does not revoke sessions, so nothing
// else would catch it. The cost is one upstream round trip per request, which
// is the price of the decision being correct.
//
// Requests are authenticated by the upstream server, so this type never sees a
// password, a session secret, or a database.
type RemoteAuth struct {
	baseURL    string
	client     *http.Client
	cookieName string
	logger     *slog.Logger
}

// Errors returned by GetUser. The middleware turns these into 401 and 503
// respectively; callers using GetUser directly decide for themselves.
var (
	// ErrRemoteNoSession means the request carried no session cookie, so
	// there was nothing to verify — no upstream call was made.
	ErrRemoteNoSession = errors.New("goauth: no session cookie on request")

	// ErrRemoteUnauthorized means the upstream server rejected the session.
	ErrRemoteUnauthorized = errors.New("goauth: remote session unauthorized")

	// ErrRemoteUnavailable means the upstream server could not be reached or
	// answered in a way that leaves authentication undecided. It is never a
	// statement that the caller is unauthenticated — treat it as a 503.
	ErrRemoteUnavailable = errors.New("goauth: remote auth server unavailable")
)

const defaultRemoteTimeout = 10 * time.Second

// RemoteOption configures a RemoteAuth.
type RemoteOption func(*RemoteAuth)

// WithRemoteHTTPClient replaces the client used for upstream calls. Use it to
// set a custom transport or TLS config.
//
// The client is copied, not adopted: a zero Timeout is replaced with the
// default (a hung upstream would otherwise pin a request goroutine
// indefinitely), and CheckRedirect is always overridden — see NewRemoteAuth.
func WithRemoteHTTPClient(c *http.Client) RemoteOption {
	return func(ra *RemoteAuth) {
		if c != nil {
			ra.client = c
		}
	}
}

// WithRemoteCookieName sets the session cookie name to look for, matching the
// upstream server's CookieConfig.Name. Defaults to "goauth_session".
func WithRemoteCookieName(name string) RemoteOption {
	return func(ra *RemoteAuth) {
		if name != "" {
			ra.cookieName = name
		}
	}
}

// WithRemoteLogger sets the logger used for rejected requests. Defaults to
// slog.Default().
func WithRemoteLogger(l *slog.Logger) RemoteOption {
	return func(ra *RemoteAuth) {
		if l != nil {
			ra.logger = l
		}
	}
}

// NewRemoteAuth returns a RemoteAuth pointed at the base URL of a go-auth
// server — the scheme and host it is mounted on, without the /auth prefix
// (e.g. "https://api.example.com"). Any trailing slash is trimmed.
//
// Redirect following is disabled unconditionally, including on a client
// supplied via WithRemoteHTTPClient. GET /auth/me answers 200 or 401 and never
// redirects, so following one is always wrong — and Go compares hostnames
// while ignoring ports when deciding whether to keep the Cookie header, so a
// 3xx would hand the caller's live session cookie to any other port on the
// same host. A redirect is reported as ErrRemoteUnavailable instead.
func NewRemoteAuth(baseURL string, opts ...RemoteOption) (*RemoteAuth, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmed == "" {
		return nil, errors.New("goauth: RemoteAuth base URL is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("goauth: invalid RemoteAuth base URL %q: %w", baseURL, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("goauth: RemoteAuth base URL %q must be http or https", baseURL)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("goauth: RemoteAuth base URL %q has no host", baseURL)
	}

	ra := &RemoteAuth{
		baseURL:    trimmed,
		client:     &http.Client{},
		cookieName: "goauth_session",
		logger:     slog.Default(),
	}
	for _, opt := range opts {
		opt(ra)
	}

	// Copy so a caller's client is never mutated — they may share it.
	client := *ra.client
	if client.Timeout == 0 {
		client.Timeout = defaultRemoteTimeout
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	ra.client = &client

	return ra, nil
}

// RequireAuth rejects requests whose session the upstream server does not
// accept, and stores the resolved user in the request context for handlers
// downstream. It mirrors AuthMiddleware's context contract exactly.
func (ra *RemoteAuth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := ra.resolve(w, r)
		if !ok {
			return
		}
		next.ServeHTTP(w, r.WithContext(ContextWithUser(r.Context(), user)))
	})
}

// RequireRole is RequireAuth followed by a role check. It reuses RequireRole's
// 403 response so a remotely-authenticated route is indistinguishable from a
// locally-authenticated one to the client.
func (ra *RemoteAuth) RequireRole(role domain.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return ra.RequireAuth(RequireRole(role, ra.logger)(next))
	}
}

// RequireAdmin is RequireRole(domain.RoleAdmin) — the common case for an
// admin console fronting someone else's go-auth server.
func (ra *RemoteAuth) RequireAdmin(next http.Handler) http.Handler {
	return ra.RequireRole(domain.RoleAdmin)(next)
}

// resolve authenticates the request, writing the error response itself when it
// cannot. The bool reports whether next should run.
func (ra *RemoteAuth) resolve(w http.ResponseWriter, r *http.Request) (*domain.User, bool) {
	user, err := ra.lookup(r.Context(), r.Header.Get("Cookie"), w)
	switch {
	case err == nil:
		return user, true

	case errors.Is(err, ErrRemoteNoSession):
		// Debug: fires on every unauthenticated request, matching
		// AuthMiddleware's handling of a missing cookie.
		logRejectedRequest(r, ra.logger, slog.LevelDebug, "auth rejected", "missing session cookie")
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":   "session_expired",
			"message": "Missing session cookie",
		}, ra.logger)
		return nil, false

	case errors.Is(err, ErrRemoteUnauthorized):
		logRejectedRequest(r, ra.logger, slog.LevelInfo, "auth rejected", "upstream rejected session")
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error":   "unauthorized",
			"message": "Invalid session",
		}, ra.logger)
		return nil, false

	default:
		// Fail closed, but distinguishably: the caller may well be
		// authenticated and we simply could not find out.
		logRejectedRequest(r, ra.logger, slog.LevelError, "auth rejected", "upstream auth unavailable",
			slog.String("error", err.Error()))
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error":   "auth_unavailable",
			"message": "Authentication service unavailable",
		}, ra.logger)
		return nil, false
	}
}

// GetUser resolves the user for a raw Cookie header, for code that needs the
// caller's identity outside a middleware chain. It returns ErrRemoteNoSession,
// ErrRemoteUnauthorized, or ErrRemoteUnavailable.
//
// Unlike the middleware, this cannot forward refreshed session cookies back to
// the browser, so prefer RequireAuth inside an HTTP handler chain.
func (ra *RemoteAuth) GetUser(ctx context.Context, cookieHeader string) (*domain.User, error) {
	return ra.lookup(ctx, cookieHeader, nil)
}

// lookup resolves a Cookie header to a user. When w is non-nil, any Set-Cookie
// the upstream server issues (a transparently refreshed session) is copied
// onto it so the browser stays in sync.
func (ra *RemoteAuth) lookup(ctx context.Context, cookieHeader string, w http.ResponseWriter) (*domain.User, error) {
	// Short-circuit before the network: with no session cookie there is
	// nothing for upstream to verify, so an unauthenticated flood costs it
	// nothing.
	if sessionCookieValue(cookieHeader, ra.cookieName) == "" {
		return nil, ErrRemoteNoSession
	}
	return ra.fetch(ctx, cookieHeader, w)
}

// fetch performs the upstream GET /auth/me. Each call decodes a fresh
// domain.User, so no two requests ever share one.
func (ra *RemoteAuth) fetch(ctx context.Context, cookieHeader string, w http.ResponseWriter) (*domain.User, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ra.baseURL+"/auth/me", nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRemoteUnavailable, err)
	}
	req.Header.Set("Cookie", cookieHeader)
	req.Header.Set("Accept", "application/json")

	resp, err := ra.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRemoteUnavailable, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
	}()

	// Forward a refreshed session before inspecting the status, so a rotation
	// that accompanies a success is never dropped. Without this the browser
	// keeps a rotated refresh token, which the next refresh reads as reuse.
	if w != nil {
		for _, c := range resp.Header.Values("Set-Cookie") {
			w.Header().Add("Set-Cookie", c)
		}
	}

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, ErrRemoteUnauthorized
	default:
		// Includes 3xx: redirects are not followed, so one arrives here as an
		// undecidable answer rather than a silently chased hop.
		return nil, fmt.Errorf("%w: upstream returned %d", ErrRemoteUnavailable, resp.StatusCode)
	}

	// GET /auth/me embeds domain.User at the top level, so decoding straight
	// into it picks up id/email/role and ignores the extra hasPassword field.
	var user domain.User
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&user); err != nil {
		return nil, fmt.Errorf("%w: decoding /auth/me: %v", ErrRemoteUnavailable, err)
	}
	if user.ID == "" {
		return nil, fmt.Errorf("%w: /auth/me returned a user with no id", ErrRemoteUnavailable)
	}
	return &user, nil
}

// sessionCookieValue pulls one cookie value out of a raw Cookie header.
// http.Request.Cookie is unavailable here because GetUser accepts the header
// as a string, so parsing goes through the same net/http machinery directly.
func sessionCookieValue(cookieHeader, name string) string {
	if cookieHeader == "" || name == "" {
		return ""
	}
	header := http.Header{}
	header.Add("Cookie", cookieHeader)
	req := http.Request{Header: header}
	c, err := req.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}
