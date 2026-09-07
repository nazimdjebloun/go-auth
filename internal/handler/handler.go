package handler

import (
	"log/slog"
	"net/http"

	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/service"
)

type Services struct {
	Auth      *service.AuthService
	Password  *service.PasswordService
	Session   *service.SessionService
	Verify    *service.VerificationService
	Invite    *service.InviteService
	Admin     *service.AdminService
	OAuth     *service.OAuthService
	Org       *service.OrgService
	OrgInvite *service.OrgInviteService
	TwoFactor *service.TwoFactorService
	AuditLog  port.AuditLogRepository
}

type Handler struct {
	services     Services
	log          *slog.Logger
	csrfTokenCfg *middleware.CSRFTokenConfig
	// clientIP says how far to trust a forwarding header when recording the
	// address a login came from. Zero value trusts nothing and uses the
	// transport address, which is correct for a directly-exposed server.
	clientIP middleware.ClientIPConfig
}

func New(s Services) *Handler {
	return &Handler{services: s, log: slog.Default()}
}

func NewWithLogger(s Services, logger *slog.Logger, csrfTokenCfg *middleware.CSRFTokenConfig, clientIP middleware.ClientIPConfig) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{services: s, log: logger, csrfTokenCfg: csrfTokenCfg, clientIP: clientIP}
}

// ip is the address to record for r — see middleware.ClientIP.
func (h *Handler) ip(r *http.Request) string {
	return middleware.ClientIP(r, h.clientIP)
}
