// Package handler implements the go-auth HTTP endpoints.
package handler

import (
	"log/slog"
	"net/http"

	"github.com/nazimdjebloun/go-auth/internal/service"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
)

// Deps is the set of services a Handler needs. It is named for what it is —
// a dependency bundle — rather than Services, which collided with the
// goauth.Services a consumer actually reads off Auth.
type Deps struct {
	AppPermissions *service.AppPermissionsService
	Auth           *service.AuthService
	Password       *service.PasswordService
	Session        *service.SessionService
	Verify         *service.VerificationService
	Invite         *service.InviteService
	Admin          *service.AdminService
	OAuth          *service.OAuthService
	Org            *service.OrgService
	OrgInvite      *service.OrgInviteService
	TwoFactor      *service.TwoFactorService
	AuditLog       port.AuditLogRepository
}

// Handler serves the go-auth HTTP endpoints.
type Handler struct {
	services     Deps
	log          *slog.Logger
	csrfTokenCfg *middleware.CSRFTokenConfig
	// cookies is the resolved session/refresh cookie scope, built once in
	// New() via cookiesFromSession and pushed here at construction — handlers
	// never pull cookie names off the session service.
	cookies middleware.CookieSettings
	// clientIP says how far to trust a forwarding header when recording the
	// address a login came from. Zero value trusts nothing and uses the
	// transport address, which is correct for a directly-exposed server.
	clientIP middleware.ClientIPConfig
}

// New returns a handler with default HTTP settings.
func New(s Deps) *Handler {
	return &Handler{services: s, log: slog.Default(), cookies: middleware.DefaultCookieSettings()}
}

// NewWithLogger returns a handler with the given HTTP settings.
func NewWithLogger(s Deps, logger *slog.Logger, csrfTokenCfg *middleware.CSRFTokenConfig, clientIP middleware.ClientIPConfig, cookies middleware.CookieSettings) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{services: s, log: logger, csrfTokenCfg: csrfTokenCfg, clientIP: clientIP, cookies: cookies}
}

// ip is the address to record for r — see middleware.ClientIP.
func (h *Handler) ip(r *http.Request) string {
	return middleware.ClientIP(r, h.clientIP)
}
