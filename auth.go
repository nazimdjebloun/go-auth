package goauth

import (
	"context"
	"database/sql"
	"fmt"
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
	CheckSession   http.HandlerFunc
	GetMe              http.HandlerFunc
	ChangeName         http.HandlerFunc
	DeleteAccount      http.HandlerFunc
	ListUsers          http.HandlerFunc
	UpdateUserRole     http.HandlerFunc
	BanUser            http.HandlerFunc
	UnbanUser          http.HandlerFunc
	DeleteUser         http.HandlerFunc
	RevokeUserSessions http.HandlerFunc
	AdminCreateUser    http.HandlerFunc
	AdminListUserSessions  http.HandlerFunc
	AdminRevokeUserSession http.HandlerFunc
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

	if config.Database.Driver == "" {
		config.Database.Driver = DriverPostgres
	}
	switch config.Database.Driver {
	case DriverPostgres, DriverMySQL, DriverSQLite:
	default:
		return nil, fmt.Errorf("go-auth: unsupported driver %q", config.Database.Driver)
	}

	switch {
	case config.Database.Pool != nil:
		pool = config.Database.Pool
		rawDB := stdlib.OpenDBFromPool(pool)
		sqlDB = sqlstore.NewDB(rawDB, string(config.Database.Driver))
		sessRepo = sessionrepo.New(pool)
	case config.Database.DB != nil:
		sqlDB = sqlstore.NewDB(config.Database.DB, string(config.Database.Driver))
		sessRepo = sessionrepo.NewFromDB(config.Database.DB)
	case config.Database.URL != "":
		driverName := sqlDriverName(config.Database.Driver)
		db, err := sql.Open(driverName, config.Database.URL)
		if err != nil {
			return nil, fmt.Errorf("go-auth: open database: %w", err)
		}
		if err := db.Ping(); err != nil {
			db.Close()
			return nil, fmt.Errorf("go-auth: ping database: %w", err)
		}
		config.Database.opened = true
		sqlDB = sqlstore.NewDB(db, string(config.Database.Driver))
		sessRepo = sessionrepo.NewFromDB(db)
		if config.Database.Driver == DriverPostgres {
			pool, err = pgxpool.New(context.Background(), config.Database.URL)
			if err != nil {
				db.Close()
				return nil, fmt.Errorf("go-auth: create connection pool: %w", err)
			}
			sessRepo = sessionrepo.New(pool)
		}
	default:
		return nil, ErrNoDatabase
	}

	rawSchema, err := loadSchema(string(config.Database.Driver))
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

	hasherImpl := hasher.New(bcryptCost)
	genImpl := token.New()

	var mailer port.Mailer
	if config.Mailer != nil {
		mailer = config.Mailer
	} else if config.Email != nil {
		mailer = NewSMTPMailer(config.Email.SMTP, config.Email.From)
	}

	serviceCfg := service.Config{
		AppName:             config.AppName,
		InviteOnly:          config.InviteOnly,
		RequireEmailVerification: config.RequireEmailVerification,
		InviteTTL:           config.InviteTTL,
		VerificationCodeTTL: config.VerificationCodeTTL,
		SessionTTL:          config.SessionTTL,
		TokenTTL:            config.TokenTTL,
		PasswordPolicy:      config.PasswordPolicy,
	}

	sessionCfg := service.DefaultSessionConfig()
	sessionCfg.Duration = config.SessionTTL
	sessionCfg.IdleTTL = config.SessionIdleTTL
	sessionCfg.CookieName = config.Cookie.Name
	sessionCfg.Domain = config.Cookie.Domain
	sessionCfg.Path = config.Cookie.Path
	sessionCfg.Secure = config.Cookie.Secure
	sessionCfg.SameSite = int(config.Cookie.SameSite)

	sessSvc := service.NewSessionService(sessRepo, genImpl, sessionCfg)

	authSvc := service.NewAuthService(userRepo, sessionRepoSQL, tokenRepo, hasherImpl, genImpl, mailer, serviceCfg, sessSvc)
	passSvc := service.NewPasswordService(userRepo, tokenRepo, hasherImpl, genImpl, mailer, sessionRepoSQL, serviceCfg)
	verifySvc := service.NewVerificationService(userRepo, tokenRepo, genImpl, mailer, serviceCfg)
	inviteSvc := service.NewInviteService(userRepo, sessionRepoSQL, inviteRepo, hasherImpl, genImpl, mailer, serviceCfg, sessSvc)
	adminSvc := service.NewAdminService(userRepo, sessionRepoSQL, hasherImpl, serviceCfg, sessSvc)

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
	csrfMW := middleware.OriginCheck(config.AllowedOrigins)

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
			Register:           csrfMW(http.HandlerFunc(h.Register)).ServeHTTP,
			Login:              csrfMW(http.HandlerFunc(h.Login)).ServeHTTP,
			Logout:             csrfMW(authMW(http.HandlerFunc(h.Logout))).ServeHTTP,
			ForgotPassword:     csrfMW(http.HandlerFunc(h.ForgotPassword)).ServeHTTP,
			ResetPassword:      csrfMW(http.HandlerFunc(h.ResetPassword)).ServeHTTP,
			ChangePassword:     csrfMW(authMW(http.HandlerFunc(h.ChangePassword))).ServeHTTP,
			VerifyEmail:        csrfMW(http.HandlerFunc(h.VerifyEmail)).ServeHTTP,
			ResendVerification: csrfMW(authMW(http.HandlerFunc(h.ResendVerification))).ServeHTTP,
			ListSessions:       authMW(http.HandlerFunc(h.ListSessions)).ServeHTTP,
			RevokeSession:      csrfMW(authMW(http.HandlerFunc(h.RevokeSession))).ServeHTTP,
			RevokeAllSessions:  csrfMW(authMW(http.HandlerFunc(h.RevokeAllSessions))).ServeHTTP,
			InviteRegister:     csrfMW(http.HandlerFunc(h.InviteRegister)).ServeHTTP,
			GetMe:              authMW(http.HandlerFunc(h.GetMe)).ServeHTTP,
		CheckSession:       http.HandlerFunc(h.CheckAuth).ServeHTTP,
			ChangeName:         csrfMW(authMW(http.HandlerFunc(h.ChangeName))).ServeHTTP,
			DeleteAccount:      csrfMW(authMW(http.HandlerFunc(h.DeleteAccount))).ServeHTTP,
			ListUsers:          authMW(adminMW(http.HandlerFunc(h.ListUsers))).ServeHTTP,
			UpdateUserRole:     csrfMW(authMW(adminMW(http.HandlerFunc(h.UpdateUserRole)))).ServeHTTP,
			BanUser:            csrfMW(authMW(adminMW(http.HandlerFunc(h.BanUser)))).ServeHTTP,
			UnbanUser:          csrfMW(authMW(adminMW(http.HandlerFunc(h.UnbanUser)))).ServeHTTP,
			DeleteUser:         csrfMW(authMW(adminMW(http.HandlerFunc(h.DeleteUser)))).ServeHTTP,
			RevokeUserSessions: csrfMW(authMW(adminMW(http.HandlerFunc(h.RevokeUserSessions)))).ServeHTTP,
			AdminCreateUser:    csrfMW(authMW(adminMW(http.HandlerFunc(h.AdminCreateUser)))).ServeHTTP,
			AdminListUserSessions:  authMW(adminMW(http.HandlerFunc(h.AdminListUserSessions))).ServeHTTP,
			AdminRevokeUserSession: csrfMW(authMW(adminMW(http.HandlerFunc(h.AdminRevokeUserSession)))).ServeHTTP,
			CreateInvite:       csrfMW(authMW(adminMW(http.HandlerFunc(h.CreateInvite)))).ServeHTTP,
			ListInvites:        authMW(adminMW(http.HandlerFunc(h.ListInvites))).ServeHTTP,
			RevokeInvite:       csrfMW(authMW(adminMW(http.HandlerFunc(h.RevokeInvite)))).ServeHTTP,
			ResendInvite:       csrfMW(authMW(adminMW(http.HandlerFunc(h.ResendInvite)))).ServeHTTP,
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
	if a.Config.Database.opened && a.DB != nil {
		a.DB.Close()
	}
}

func (a *Auth) Mount(mux *http.ServeMux) {
	// All middleware (csrf, auth, admin) is already baked into a.Handlers.
	mux.Handle("POST /auth/register", a.Handlers.Register)
	mux.Handle("POST /auth/signup", a.Handlers.Register)
	mux.Handle("POST /auth/login", a.Handlers.Login)
	mux.Handle("POST /auth/signin", a.Handlers.Login)
	mux.Handle("POST /auth/forgot-password", a.Handlers.ForgotPassword)
	mux.Handle("POST /auth/reset-password", a.Handlers.ResetPassword)
	mux.Handle("POST /auth/verify-email", a.Handlers.VerifyEmail)
	mux.Handle("POST /auth/invite/register", a.Handlers.InviteRegister)
	mux.Handle("POST /auth/logout", a.Handlers.Logout)
	mux.Handle("POST /auth/signout", a.Handlers.Logout)
	mux.Handle("GET /auth/me", a.Handlers.GetMe)
	mux.Handle("GET /auth/check", a.Handlers.CheckSession)
	mux.Handle("PUT /auth/name", a.Handlers.ChangeName)
	mux.Handle("GET /auth/sessions", a.Handlers.ListSessions)
	mux.Handle("DELETE /auth/sessions/{id}", a.Handlers.RevokeSession)
	mux.Handle("DELETE /auth/sessions", a.Handlers.RevokeAllSessions)
	mux.Handle("PUT /auth/password", a.Handlers.ChangePassword)
	mux.Handle("POST /auth/change-password", a.Handlers.ChangePassword)
	mux.Handle("DELETE /auth/account", a.Handlers.DeleteAccount)
	mux.Handle("POST /auth/resend-verification", a.Handlers.ResendVerification)
	mux.Handle("GET /admin/users", a.Handlers.ListUsers)
	mux.Handle("PATCH /admin/users/{id}/role", a.Handlers.UpdateUserRole)
	mux.Handle("PATCH /admin/users/{id}/ban", a.Handlers.BanUser)
	mux.Handle("PATCH /admin/users/{id}/unban", a.Handlers.UnbanUser)
	mux.Handle("DELETE /admin/users/{id}", a.Handlers.DeleteUser)
	mux.Handle("POST /admin/users", a.Handlers.AdminCreateUser)
	mux.Handle("GET /admin/users/{id}/sessions", a.Handlers.AdminListUserSessions)
	mux.Handle("DELETE /admin/users/{id}/sessions/{sessionId}", a.Handlers.AdminRevokeUserSession)
	mux.Handle("DELETE /admin/users/{id}/sessions", a.Handlers.RevokeUserSessions)
	mux.Handle("POST /admin/invites", a.Handlers.CreateInvite)
	mux.Handle("GET /admin/invites", a.Handlers.ListInvites)
	mux.Handle("DELETE /admin/invites/{id}", a.Handlers.RevokeInvite)
	mux.Handle("POST /admin/invites/{id}/resend", a.Handlers.ResendInvite)
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

// CheckSession validates a raw session token and returns whether it is valid.
// It checks the session exists, is not expired, and the associated user exists and is not banned.
func (a *Auth) CheckSession(ctx context.Context, tokenRaw string) bool {
	_, _, err := a.authService.ValidateSession(ctx, tokenRaw)
	return err == nil
}

// GetSession validates a raw session token and returns the associated user and session.
// Returns the user, session, and nil error on success.
// Returns nil, nil, error if the token is invalid, expired, or the user is banned.
func (a *Auth) GetSession(ctx context.Context, tokenRaw string) (*domain.User, *domain.Session, error) {
	user, session, err := a.authService.ValidateSession(ctx, tokenRaw)
	if err != nil {
		return nil, nil, err
	}
	return user, session, nil
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

func sqlDriverName(driver Driver) string {
	switch driver {
	case DriverPostgres:
		return "pgx"
	case DriverSQLite:
		return "sqlite3"
	default:
		return string(driver)
	}
}
