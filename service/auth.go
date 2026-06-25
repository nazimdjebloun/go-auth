package service

import (
	"context"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type AuthService struct {
	users    port.UserRepository
	sessions port.SessionRepository
	tokens   port.TokenRepository
	hasher   port.Hasher
	gen      port.TokenGenerator
	mailer   port.Mailer
	config   Config

	sessionSvc *SessionService
	verifySvc  *VerificationService
}

type Config struct {
	AppName                  string
	BaseURL                  string
	InviteOnly               bool
	RequireEmailVerification bool
	InviteTTL                time.Duration
	VerificationCodeTTL      time.Duration
	SessionTTL               time.Duration
	TokenTTL                 time.Duration
	PasswordPolicy           domain.PasswordPolicy
}

func NewAuthService(
	users port.UserRepository,
	sessions port.SessionRepository,
	tokens port.TokenRepository,
	hasher port.Hasher,
	gen port.TokenGenerator,
	mailer port.Mailer,
	config Config,
	sessionSvc *SessionService,
	verifySvc *VerificationService,
) *AuthService {
	if config.PasswordPolicy.MinLength == 0 {
		config.PasswordPolicy.MinLength = 8
	}
	if !config.PasswordPolicy.RequireDigit && !config.PasswordPolicy.RequireUppercase && !config.PasswordPolicy.RequireSpecial {
		config.PasswordPolicy.RequireDigit = true
	}
	return &AuthService{
		users:      users,
		sessions:   sessions,
		tokens:     tokens,
		hasher:     hasher,
		gen:        gen,
		mailer:     mailer,
		config:     config,
		sessionSvc: sessionSvc,
		verifySvc:  verifySvc,
	}
}

func (s *AuthService) Register(ctx context.Context, input RegisterInput) (*RegisterResult, *domain.AuthError) {
	if s.config.InviteOnly {
		return nil, domain.ErrForbidden
	}

	input.Email = strings.TrimSpace(strings.ToLower(input.Email))
	if err := validateEmail(input.Email); err != nil {
		return nil, err
	}
	if err := s.config.PasswordPolicy.Validate(input.Password); err != nil {
		return nil, err
	}
	if strings.TrimSpace(input.Name) == "" {
		return nil, domain.NewError("name_required", "Name is required", 400)
	}
	input.Name = strings.TrimSpace(input.Name)

	existing, _ := s.users.GetByEmail(ctx, input.Email)
	if existing != nil {
		return nil, domain.ErrEmailAlreadyExists
	}

	hash, err := s.hasher.Hash(input.Password)
	if err != nil {
		return nil, domain.NewError("internal_error", "Failed to process password", 500)
	}

	now := time.Now().UTC()

	user := &domain.User{
		ID:           uuid.New().String(),
		Email:        input.Email,
		PasswordHash: &hash,
		Name:         input.Name,
		Role:         domain.RoleUser,
		IsBanned:     false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.users.Create(ctx, user); err != nil {
		return nil, domain.NewError("internal_error", "Failed to create user", 500)
	}

	if s.config.RequireEmailVerification {
		if err := s.verifySvc.SendVerification(ctx, user); err != nil {
			return nil, err
		}
	}

	session, rawToken, refreshToken, err := s.sessionSvc.Create(ctx, user.ID, "", "")
	if err != nil {
		return nil, domain.NewError("internal_error", "Failed to create session", 500)
	}

	return &RegisterResult{
		User:         user,
		Session:      session,
		SessionToken: rawToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *AuthService) Login(ctx context.Context, input LoginInput) (*LoginResult, *domain.AuthError) {
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))

	user, err := s.users.GetByEmail(ctx, input.Email)
	if err != nil || user == nil {
		return nil, domain.ErrInvalidCredentials
	}

	if user.IsBanned {
		return nil, domain.ErrUserBanned
	}

	if s.config.RequireEmailVerification && !user.IsVerified && user.Role != domain.RoleAdmin {
		return nil, domain.ErrEmailNotVerified
	}

	if !user.HasPassword() {
		return nil, domain.NewError("no_password", "No password set for this account. Use OAuth to sign in.", 400)
	}
	if err := s.hasher.Compare(input.Password, *user.PasswordHash); err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	session, rawToken, refreshToken, err := s.sessionSvc.Create(ctx, user.ID, input.IP, input.UserAgent)
	if err != nil {
		return nil, domain.NewError("internal_error", "Failed to create session", 500)
	}

	return &LoginResult{
		User:         user,
		Session:      session,
		SessionToken: rawToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *AuthService) ValidateSession(ctx context.Context, tokenRaw string) (*domain.User, *domain.Session, *domain.AuthError) {
	session, err := s.sessionSvc.Validate(ctx, tokenRaw)
	if err != nil {
		return nil, nil, domain.ErrSessionExpired
	}

	user, err := s.users.GetByID(ctx, session.UserID)
	if err != nil || user == nil {
		return nil, nil, domain.ErrSessionExpired
	}
	if user.IsBanned {
		return nil, nil, domain.ErrUserBanned
	}

	return user, session, nil
}

func (s *AuthService) Logout(ctx context.Context, sessionID string) *domain.AuthError {
	if err := s.sessionSvc.RevokeByID(ctx, sessionID); err != nil {
		return domain.NewError("internal_error", "Failed to revoke session", 500)
	}
	return nil
}

func (s *AuthService) ChangeName(ctx context.Context, userID, newName string) *domain.AuthError {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}
	if newName == "" {
		return domain.NewError("validation_error", "Name cannot be empty", 400)
	}
	user.Name = newName
	user.UpdatedAt = time.Now().UTC()
	if err := s.users.Update(ctx, user); err != nil {
		return domain.NewError("internal_error", "Failed to update name", 500)
	}
	return nil
}

func (s *AuthService) DeleteAccount(ctx context.Context, userID string, password string) *domain.AuthError {
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return domain.ErrUserNotFound
	}

	if !user.HasPassword() {
		return domain.NewError("password_required", "Password is required to delete account", http.StatusBadRequest)
	}
	if err := s.hasher.Compare(password, *user.PasswordHash); err != nil {
		return domain.NewError("wrong_password", "Password is incorrect", http.StatusBadRequest)
	}

	if err := s.sessions.DeleteAllForUser(ctx, userID); err != nil {
		return domain.NewError("internal_error", "Failed to revoke sessions", 500)
	}

	if err := s.users.Delete(ctx, userID); err != nil {
		return domain.NewError("internal_error", "Failed to delete account", 500)
	}

	return nil
}

func validateEmail(email string) *domain.AuthError {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return domain.ErrInvalidEmail
	}
	return nil
}
