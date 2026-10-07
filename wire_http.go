package goauth

import (
	"context"
	"net/http"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/handler"
	"github.com/nazimdjebloun/go-auth/internal/httproutes"
	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/ratelimit"
)

type httpMiddleware func(http.Handler) http.Handler

type httpWiring struct {
	authMW, adminMW, rateLimitMW, corsMW, orgMemberMW httpMiddleware
	routes                                            []httproutes.Entry
}

// buildHTTP constructs the request adapters and their middleware after the
// services are available and before maintenance starts.
func buildHTTP(cfg *Config, wired serviceWiring) httpWiring {
	svc := wired.services
	cookies := wired.cookies
	sessSvc, oauthSvc, orgSvc := svc.Session, svc.OAuth, svc.Org
	userRepo, orgRepo := wired.userRepo, wired.orgRepo
	// One description of the deployment's proxy setup, shared by everything
	// that has to reason about it: the rate limiter keys limits on it, the
	// CSRF origin check recovers the original scheme/host with it, and the
	// handlers below record it on sessions and audit events. Nil rateLimit
	// leaves it zero, which trusts no forwarding header at all.
	var clientIPCfg middleware.ClientIPConfig
	if cfg.rateLimit != nil {
		clientIPCfg = middleware.ClientIPConfig{
			Header:     cfg.rateLimit.IPAddressHeader,
			TrustedIPs: cfg.rateLimit.TrustedIPs,
		}
	}

	h := handler.NewWithLogger(handler.Deps{
		AppPermissions: svc.AppPermissions,
		Auth:           svc.Auth,
		Password:       svc.Password,
		Session:        sessSvc,
		Verify:         svc.Verify,
		Invite:         svc.Invite,
		Admin:          svc.Admin,
		OAuth:          oauthSvc,
		Org:            orgSvc,
		OrgInvite:      svc.OrgInvite,
		TwoFactor:      svc.TwoFactor,
		AuditLog:       svc.AuditLog,
	}, cfg.logger, cfg.security.CSRFToken, clientIPCfg, cookies)

	// OAuth handlers (separate because they need baseURL for redirects).
	oauthHandlers := handler.NewOAuthHandlers(oauthSvc, cfg.app.BaseURL, cfg.security.CSRFToken, clientIPCfg, cookies, cfg.logger)
	oauthHandlers.AttachTwoFactor(svc.TwoFactor)

	authMW := middleware.AuthMiddleware(sessSvc, cookies, userRepo, cfg.logger)
	adminMW := middleware.RequireAdminSession(!cfg.twoFactor.DisableAdminTwoFactor || cfg.twoFactor.RequireEmail2FA, cfg.logger)
	if svc.AppPermissions != nil {
		adminMW = middleware.RequireProtectedAppAdmin(svc.AppPermissions)
	}
	var trustedIPs []string
	if cfg.rateLimit != nil {
		cfg.rateLimit.Logger = cfg.logger
		trustedIPs = cfg.rateLimit.TrustedIPs
		if !cfg.rateLimit.Enabled && cfg.logger != nil {
			cfg.logger.Warn("goauth: rate limiting is disabled — this is insecure for production",
				"fix", "re-enable with WithRateLimitEnabled(true) or use a trusted edge rate limiter")
		}
		if cfg.rateLimit.Enabled && cfg.logger != nil && ratelimit.IsDefaultStore(cfg.rateLimit.Store) {
			// Heuristic reminder, not a diagnosis — the library has no way to
			// detect "multiple instances" directly, so this fires on every
			// process using the default store, dev included.
			cfg.logger.Warn("goauth: rate limiting is using the default in-memory store, which does not share state across instances",
				"fix", "if you run more than one instance behind a load balancer, use WithRateLimitStore with a shared store (e.g. Redis) or limits apply per-instance rather than globally")
		}
	}
	rateLimitMW := middleware.RateLimit(cfg.rateLimit)
	csrfMW := middleware.OriginCheck(cfg.security.AllowedOrigins, cfg.security.AllowMissingCSRFHeaders, trustedIPs, cfg.logger)
	csrfTokenMW := middleware.CSRFToken(cfg.security.CSRFToken)
	corsMW := middleware.CORS(cfg.security.AllowedOrigins)

	// Org authorization: orgMemberMW verifies the authenticated user is a
	// member of the {orgID} path segment; orgAdminMW/orgOwnerMW additionally
	// require a minimum role. Must run after authMW (needs the user in
	// context) and before the handler. Safe to construct even when
	// organizations are disabled (orgRepo is nil) — the routes that use these
	// are only registered by Mount when organizations are enabled, so the
	// underlying orgs.GetMembership call is never reached.
	orgUserID := func(ctx context.Context) string {
		if u := middleware.GetUserFromContext(ctx); u != nil {
			return u.ID
		}
		return ""
	}
	orgMemberMW := middleware.RequireOrgMember(orgRepo, orgUserID)
	orgAdminMW := middleware.RequireOrgRole(domain.OrgRoleAdmin)
	orgOwnerMW := middleware.RequireOrgRole(domain.OrgRoleOwner)
	routes := httproutes.Build(httproutes.Features{
		AppPermissions:          cfg.appPermissions.Enable,
		AppPermissionManagement: cfg.appPermissions.EnableManagementHTTP,
		EmailRegistration:       cfg.registration.EnableEmailPassword,
		Invite:                  cfg.registration.EnableInvite,
		OAuth:                   cfg.registration.EnableOAuth && oauthSvc != nil,
		Organizations:           orgSvc != nil,
	}, h, oauthHandlers, httproutes.Middleware{
		AppOperation: func(key string) func(http.Handler) http.Handler {
			if svc.AppPermissions != nil {
				return middleware.RequireAppPermission(svc.AppPermissions, key)
			}
			return adminMW
		},
		CORS: corsMW, RateLimit: rateLimitMW, CSRFToken: csrfTokenMW,
		CSRF: csrfMW, Auth: authMW, Admin: adminMW,
		OrgMember: orgMemberMW, OrgAdmin: orgAdminMW, OrgOwner: orgOwnerMW,
	})

	return httpWiring{
		authMW: authMW, adminMW: adminMW, rateLimitMW: rateLimitMW,
		corsMW: corsMW, orgMemberMW: orgMemberMW, routes: routes,
	}
}

// cookiesFromSession maps the service session config onto the cookie fields
// middleware writes from. Called once in New() — handlers and middleware
// receive the result at construction and never touch the service config for
// cookie names again. The two shapes stay separate by design; see
// middleware.CookieSettings.
func cookiesFromSession(cfg service.SessionConfig) middleware.CookieSettings {
	return middleware.CookieSettings{
		Name:        cfg.CookieName,
		RefreshName: cfg.RefreshCookieName,
		Domain:      cfg.Domain,
		Path:        cfg.Path,
		Secure:      cfg.Secure,
		SameSite:    cfg.SameSite,
		TTL:         cfg.Duration,
		RefreshTTL:  cfg.RefreshTTL,
	}
}
