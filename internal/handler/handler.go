package handler

import (
	"log/slog"

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
}

func New(s Services) *Handler {
	return &Handler{services: s, log: slog.Default()}
}

func NewWithLogger(s Services, logger *slog.Logger, csrfTokenCfg *middleware.CSRFTokenConfig) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{services: s, log: logger, csrfTokenCfg: csrfTokenCfg}
}
