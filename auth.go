package goauth

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/handler"
	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/midlware"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/postgres"
	"github.com/nazimdjebloun/go-auth/service"
	"github.com/nazimdjebloun/go-auth/token"
)

// Auth is the main library entry point.
type Auth struct {
	Config     Config
	DB         *sql.DB
	Services   Services
	Handlers   HandlerGroup
	Middleware MiddlewareGroup

	authService     *service.AuthService
	passwordService *service.PasswordService
	sessionService  *service.SessionService
	verifyService   *service.VerificationService
	inviteService   *service.InviteService
	adminService    *service.AdminService
}

type Services struct {
	Auth     *service.AuthService
	Password *service.PasswordService
	Session  *service.SessionService
	Verify   *service.VerificationService
	Invite   *service.InviteService
	Admin    *service.AdminService
}

type HandlerGroup struct {
	Register        http.HandlerFunc
	Login           http.HandlerFunc
	Logout          http.HandlerFunc
	ForgotPassword  http.HandlerFunc
	ResetPassword   http.HandlerFunc
	ChangePassword  http.HandlerFunc
	VerifyEmail     http.HandlerFunc
	ResendVerification http.HandlerFunc
	ListSessions    http.HandlerFunc
	RevokeSession   http.HandlerFunc
	RevokeAllSessions http.HandlerFunc
	InviteVerify    http.HandlerFunc
	InviteRegister  http.HandlerFunc
	ListUsers       http.HandlerFunc
	BanUser         http.HandlerFunc
	UnbanUser       http.HandlerFunc
	DeleteUser      http.HandlerFunc
	RevokeUserSessions http.HandlerFunc
	CreateInvite    http.HandlerFunc
	ListInvites     http.HandlerFunc
	RevokeInvite    http.HandlerFunc
	ResendInvite    http.HandlerFunc
}

type MiddlewareGroup struct {
	Authenticate func(http.Handler) http.Handler
	RequireAdmin func(http.Handler) http.Handler
	RateLimit    func(http.Handler) http.Handler
}

func New(config Config) (*Auth, error) {
	if config.AppName == "" {
		config.AppName = "App"
	}
	if config.SessionTTL == 0 {
		config.SessionTTL = 30 * 24 // hours
	}
	if config.TokenTTL == 0 {
		config.TokenTTL = 1 // hour
	}

	// Connect to database
	db, err := sql.Open("postgres", config.Database.DSN)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}

	// Run migrations if schema file provided
	if config.Database.Schema != "" {
		if err := runMigrations(db, config.Database.Schema); err != nil {
			return nil, err
		}
	}

	// Create implementations
	userRepo := postgres.NewUserRepository(db)
	sessionRepo := postgres.NewSessionRepository(db)
	tokenRepo := postgres.NewTokenRepository(db)
	inviteRepo := postgres.NewInviteRepository(db)

	hasherImpl := hasher.New(config.BcryptCost)
	genImpl := token.New(config.TokenLength)

	var emailSender port.EmailSender = nil
	if config.Email != nil {
		emailSender = NewSMTPEmailSender(config.Email.SMTP, config.Email.From)
	}

	serviceCfg := service.Config{
		AppName:             config.AppName,
		AdminEmails:         config.AdminEmails,
		InviteOnly:          config.InviteOnly,
		InviteTTL:           config.InviteTTL,
		VerificationCodeTTL: config.VerificationCodeTTL,
		SessionTTL:          config.SessionTTL * time.Hour,
		TokenTTL:            config.TokenTTL * time.Hour,
		BcryptCost:          config.BcryptCost,
		TokenLength:         config.TokenLength,
		EmailTemplates: service.EmailTemplates{
			VerifyEmail:   config.EmailTemplates.VerifyEmail,
			PasswordReset: config.EmailTemplates.PasswordReset,
			InviteEmail:   config.EmailTemplates.InviteEmail,
		},
	}

	authSvc := service.NewAuthService(userRepo, sessionRepo, tokenRepo, hasherImpl, genImpl, emailSender, serviceCfg)
	passSvc := service.NewPasswordService(userRepo, tokenRepo, hasherImpl, genImpl, emailSender, serviceCfg)
	sessSvc := service.NewSessionService(sessionRepo)
	verifySvc := service.NewVerificationService(userRepo, tokenRepo, genImpl, emailSender, serviceCfg)
	inviteSvc := service.NewInviteService(userRepo, sessionRepo, inviteRepo, tokenRepo, hasherImpl, genImpl, emailSender, serviceCfg)
	adminSvc := service.NewAdminService(userRepo, sessionRepo)

	// Create handlers
	h := handler.New(handler.Services{
		Auth:     authSvc,
		Password: passSvc,
		Session:  sessSvc,
		Verify:   verifySvc,
		Invite:   inviteSvc,
		Admin:    adminSvc,
	})

	// Middleware
	authMW := midlware.Authenticate(authSvc)
	adminMW := midlware.RequireAdmin()
	rateLimitMW := midlware.RateLimit(config.RateLimit)

	a := &Auth{
		Config:          config,
		DB:              db,
		authService:     authSvc,
		passwordService: passSvc,
		sessionService:  sessSvc,
		verifyService:   verifySvc,
		inviteService:   inviteSvc,
		adminService:    adminSvc,
		Services: Services{
			Auth:     authSvc,
			Password: passSvc,
			Session:  sessSvc,
			Verify:   verifySvc,
			Invite:   inviteSvc,
			Admin:    adminSvc,
		},
		Handlers: HandlerGroup{
			Register:           h.Register,
			Login:              h.Login,
			Logout:             h.Logout,
			ForgotPassword:     h.ForgotPassword,
			ResetPassword:      h.ResetPassword,
			ChangePassword:     h.ChangePassword,
			VerifyEmail:        h.VerifyEmail,
			ResendVerification: h.ResendVerification,
			ListSessions:       h.ListSessions,
			RevokeSession:      h.RevokeSession,
			RevokeAllSessions:  h.RevokeAllSessions,
			InviteVerify:       h.InviteVerify,
			InviteRegister:     h.InviteRegister,
			ListUsers:          h.ListUsers,
			BanUser:            h.BanUser,
			UnbanUser:          h.UnbanUser,
			DeleteUser:         h.DeleteUser,
			RevokeUserSessions: h.RevokeUserSessions,
			CreateInvite:       h.CreateInvite,
			ListInvites:        h.ListInvites,
			RevokeInvite:       h.RevokeInvite,
			ResendInvite:       h.ResendInvite,
		},
		Middleware: MiddlewareGroup{
			Authenticate: authMW,
			RequireAdmin: adminMW,
			RateLimit:    rateLimitMW,
		},
	}

	return a, nil
}

func (a *Auth) Mount(mux *http.ServeMux) {
	// Public routes
	mux.HandleFunc("POST /auth/register", a.Handlers.Register)
	mux.HandleFunc("POST /auth/login", a.Handlers.Login)
	mux.HandleFunc("POST /auth/forgot-password", a.Handlers.ForgotPassword)
	mux.HandleFunc("POST /auth/reset-password", a.Handlers.ResetPassword)
	mux.HandleFunc("POST /auth/verify-email", a.Handlers.VerifyEmail)
	mux.HandleFunc("POST /auth/invite/verify", a.Handlers.InviteVerify)
	mux.HandleFunc("POST /auth/invite/register", a.Handlers.InviteRegister)

	// Protected routes
	mux.Handle("POST /auth/logout", a.Middleware.Authenticate(a.Handlers.Logout))
	mux.Handle("GET /auth/sessions", a.Middleware.Authenticate(a.Handlers.ListSessions))
	mux.Handle("DELETE /auth/sessions/{id}", a.Middleware.Authenticate(http.HandlerFunc(a.Handlers.RevokeSession)))
	mux.Handle("DELETE /auth/sessions", a.Middleware.Authenticate(a.Handlers.RevokeAllSessions))
	mux.Handle("PUT /auth/password", a.Middleware.Authenticate(a.Handlers.ChangePassword))
	mux.Handle("POST /auth/resend-verification", a.Middleware.Authenticate(a.Handlers.ResendVerification))

	// Admin routes
	admin := func(next http.Handler) http.Handler {
		return a.Middleware.Authenticate(a.Middleware.RequireAdmin(next))
	}
	mux.Handle("GET /admin/users", admin(a.Handlers.ListUsers))
	mux.Handle("PATCH /admin/users/{id}/ban", admin(http.HandlerFunc(a.Handlers.BanUser)))
	mux.Handle("PATCH /admin/users/{id}/unban", admin(http.HandlerFunc(a.Handlers.UnbanUser)))
	mux.Handle("DELETE /admin/users/{id}", admin(http.HandlerFunc(a.Handlers.DeleteUser)))
	mux.Handle("DELETE /admin/users/{id}/sessions", admin(http.HandlerFunc(a.Handlers.RevokeUserSessions)))
	mux.Handle("POST /admin/invites", admin(a.Handlers.CreateInvite))
	mux.Handle("GET /admin/invites", admin(a.Handlers.ListInvites))
	mux.Handle("DELETE /admin/invites/{id}", admin(http.HandlerFunc(a.Handlers.RevokeInvite)))
	mux.Handle("POST /admin/invites/{id}/resend", admin(http.HandlerFunc(a.Handlers.ResendInvite)))
}

func (a *Auth) Register(ctx context.Context, input RegisterInput) (*RegisterResult, *domain.AuthError) {
	result, err := a.authService.Register(ctx, service.RegisterInput{
		Email:    input.Email,
		Password: input.Password,
		Name:     input.Name,
	})
	if err != nil {
		return nil, err
	}
	return &RegisterResult{
		User:         result.User,
		Session:      result.Session,
		SessionToken: result.SessionToken,
	}, nil
}

func (a *Auth) Login(ctx context.Context, input LoginInput) (*LoginResult, *domain.AuthError) {
	result, err := a.authService.Login(ctx, service.LoginInput{
		Email:     input.Email,
		Password:  input.Password,
		IP:        input.IP,
		UserAgent: input.UserAgent,
	})
	if err != nil {
		return nil, err
	}
	return &LoginResult{
		User:         result.User,
		Session:      result.Session,
		SessionToken: result.SessionToken,
	}, nil
}

func (a *Auth) VerifyInvite(ctx context.Context, input VerifyInviteInput) *domain.AuthError {
	return a.inviteService.VerifyInvite(ctx, service.VerifyInviteInput{
		Email: input.Email,
		Code:  input.Code,
	})
}

func (a *Auth) CompleteInviteRegistration(ctx context.Context, input CompleteInviteInput) (*CompleteInviteResult, *domain.AuthError) {
	result, err := a.inviteService.CompleteInviteRegistration(ctx, service.CompleteInviteInput{
		Email:            input.Email,
		VerificationCode: input.VerificationCode,
		Password:         input.Password,
		Name:             input.Name,
	})
	if err != nil {
		return nil, err
	}
	return &CompleteInviteResult{
		User:         result.User,
		Session:      result.Session,
		SessionToken: result.SessionToken,
	}, nil
}

func runMigrations(db *sql.DB, schema string) error {
	var schemaSQL string
	if schema == "embedded" {
		schemaSQL = EmbeddedSchema
	} else {
		data, err := os.ReadFile(filepath.Clean(schema))
		if err != nil {
			return err
		}
		schemaSQL = string(data)
	}

	statements := splitSQL(schemaSQL)
	for _, stmt := range statements {
		if _, err := db.Exec(stmt); err != nil {
			log.Printf("Migration statement failed: %s\nError: %v", stmt[:min(len(stmt), 100)], err)
			return err
		}
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
