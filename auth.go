package goauth

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/handler"
	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/service"
	"github.com/nazimdjebloun/go-auth/sessionrepo"
	"github.com/nazimdjebloun/go-auth/sqlstore"
	"github.com/nazimdjebloun/go-auth/token"
)

type Auth struct {
	Config     Config
	Pool       *pgxpool.Pool
	DB         *sqlstore.DB
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
	Register           http.HandlerFunc
	Login              http.HandlerFunc
	Logout             http.HandlerFunc
	ForgotPassword     http.HandlerFunc
	ResetPassword      http.HandlerFunc
	ChangePassword     http.HandlerFunc
	VerifyEmail        http.HandlerFunc
	ResendVerification http.HandlerFunc
	ListSessions       http.HandlerFunc
	RevokeSession      http.HandlerFunc
	RevokeAllSessions  http.HandlerFunc
	InviteRegister     http.HandlerFunc
	ListUsers          http.HandlerFunc
	BanUser            http.HandlerFunc
	UnbanUser          http.HandlerFunc
	DeleteUser         http.HandlerFunc
	RevokeUserSessions http.HandlerFunc
	CreateInvite       http.HandlerFunc
	ListInvites        http.HandlerFunc
	RevokeInvite       http.HandlerFunc
	ResendInvite       http.HandlerFunc
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
		config.SessionTTL = 30 * 24 * time.Hour
	}
	if config.TokenTTL == 0 {
		config.TokenTTL = 1 * time.Hour
	}

	var pool *pgxpool.Pool
	var sqlDB *sqlstore.DB
	var sessRepo *sessionrepo.SessionRepository

	if config.Database.Pool != nil {
		pool = config.Database.Pool
		rawDB := stdlib.OpenDBFromPool(pool)
		sqlDB = sqlstore.NewDB(rawDB, config.Database.Driver)
		sessRepo = sessionrepo.New(pool)
	} else if config.Database.DB != nil {
		sqlDB = sqlstore.NewDB(config.Database.DB, config.Database.Driver)
		sessRepo = sessionrepo.NewFromDB(config.Database.DB)
	} else {
		return nil, ErrNoDatabase
	}

	if config.Database.Driver == "" {
		config.Database.Driver = "postgres"
	}

	rawSchema, err := loadSchema(config.Database.Driver)
	if err != nil {
		return nil, err
	}
	if err := runMigrations(sqlDB, rawSchema); err != nil {
		return nil, err
	}

	userRepo := sqlstore.NewUserRepository(sqlDB)
	sessionRepoSQL := sqlstore.NewSessionRepository(sqlDB)
	tokenRepo := sqlstore.NewTokenRepository(sqlDB)
	inviteRepo := sqlstore.NewInviteRepository(sqlDB)

	hasherImpl := hasher.New(config.BcryptCost)
	genImpl := token.New()

	var mailer port.Mailer
	if config.Mailer != nil {
		mailer = config.Mailer
	} else if config.Email != nil {
		mailer = NewSMTPMailer(config.Email.SMTP, config.Email.From)
	}

	serviceCfg := service.Config{
		AppName:             config.AppName,
		AdminEmails:         config.AdminEmails,
		InviteOnly:          config.InviteOnly,
		InviteTTL:           config.InviteTTL,
		VerificationCodeTTL: config.VerificationCodeTTL,
		SessionTTL:          config.SessionTTL,
		TokenTTL:            config.TokenTTL,
		BcryptCost:          config.BcryptCost,
		TokenLength:         config.TokenLength,
	}

	sessionCfg := service.DefaultSessionConfig()
	sessionCfg.Duration = config.SessionTTL

	sessSvc := service.NewSessionService(sessRepo, genImpl, sessionCfg)

	authSvc := service.NewAuthService(userRepo, sessionRepoSQL, tokenRepo, hasherImpl, genImpl, mailer, serviceCfg, sessSvc)
	passSvc := service.NewPasswordService(userRepo, tokenRepo, hasherImpl, genImpl, mailer, serviceCfg)
	verifySvc := service.NewVerificationService(userRepo, tokenRepo, genImpl, mailer, serviceCfg)
	inviteSvc := service.NewInviteService(userRepo, sessionRepoSQL, inviteRepo, hasherImpl, genImpl, mailer, serviceCfg, sessSvc)
	adminSvc := service.NewAdminService(userRepo, sessionRepoSQL)

	h := handler.New(handler.Services{
		Auth:     authSvc,
		Password: passSvc,
		Session:  sessSvc,
		Verify:   verifySvc,
		Invite:   inviteSvc,
		Admin:    adminSvc,
	})

	authMW := middleware.AuthMiddleware(sessSvc, userRepo)
	adminMW := middleware.RequireRole(domain.RoleAdmin)
	rateLimitMW := middleware.RateLimit(config.RateLimit)

	return &Auth{
		Config:          config,
		Pool:            pool,
		DB:              sqlDB,
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
	}, nil
}

func (a *Auth) Close() {
	if a.Pool != nil {
		a.Pool.Close()
	}
}

func (a *Auth) Mount(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/register", a.Handlers.Register)
	mux.HandleFunc("POST /auth/login", a.Handlers.Login)
	mux.HandleFunc("POST /auth/forgot-password", a.Handlers.ForgotPassword)
	mux.HandleFunc("POST /auth/reset-password", a.Handlers.ResetPassword)
	mux.HandleFunc("POST /auth/verify-email", a.Handlers.VerifyEmail)
	mux.HandleFunc("POST /auth/invite/register", a.Handlers.InviteRegister)

	mux.Handle("POST /auth/logout", a.Middleware.Authenticate(a.Handlers.Logout))
	mux.Handle("GET /auth/sessions", a.Middleware.Authenticate(a.Handlers.ListSessions))
	mux.Handle("DELETE /auth/sessions/{id}", a.Middleware.Authenticate(http.HandlerFunc(a.Handlers.RevokeSession)))
	mux.Handle("DELETE /auth/sessions", a.Middleware.Authenticate(a.Handlers.RevokeAllSessions))
	mux.Handle("PUT /auth/password", a.Middleware.Authenticate(a.Handlers.ChangePassword))
	mux.Handle("POST /auth/resend-verification", a.Middleware.Authenticate(a.Handlers.ResendVerification))

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

func (a *Auth) CompleteInviteRegistration(ctx context.Context, input CompleteInviteInput) (*CompleteInviteResult, *domain.AuthError) {
	result, err := a.inviteService.CompleteInviteRegistration(ctx, service.CompleteInviteInput{
		Code:            input.Code,
		Name:            input.Name,
		Password:        input.Password,
		ConfirmPassword: input.ConfirmPassword,
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

func loadSchema(driver string) (string, error) {
	return GetSchema(driver)
}

func runMigrations(db *sqlstore.DB, schemaSQL string) error {
	statements := splitSQL(schemaSQL)
	for _, stmt := range statements {
		if _, err := db.ExecContext(context.Background(), stmt); err != nil {
			log.Printf("Migration failed: %s\nError: %v", stmt[:min(len(stmt), 100)], err)
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
