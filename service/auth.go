package service

import (
	"context"
	"net/http"
	"net/mail"
	"strings"
	"time"
	"unicode"

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
}

type Config struct {
	AppName             string
	AdminEmails         []string
	InviteOnly          bool
	RequireEmailVerification bool
	InviteTTL           time.Duration
	VerificationCodeTTL time.Duration
	SessionTTL          time.Duration
	TokenTTL            time.Duration
	BcryptCost          int
	TokenLength         int
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
) *AuthService {
	return &AuthService{
		users:      users,
		sessions:   sessions,
		tokens:     tokens,
		hasher:     hasher,
		gen:        gen,
		mailer:     mailer,
		config:     config,
		sessionSvc: sessionSvc,
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
	if err := validatePassword(input.Password); err != nil {
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
	role := domain.RoleUser
	for _, adminEmail := range s.config.AdminEmails {
		if strings.EqualFold(input.Email, adminEmail) {
			role = domain.RoleAdmin
			break
		}
	}

	user := &domain.User{
		ID:           uuid.New().String(),
		Email:        input.Email,
		PasswordHash: hash,
		Name:         input.Name,
		Role:         role,
		IsVerified:   !s.config.RequireEmailVerification,
		IsBanned:     false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if !s.config.RequireEmailVerification {
		user.VerifiedAt = &now
	}

	if err := s.users.Create(ctx, user); err != nil {
		return nil, domain.NewError("internal_error", "Failed to create user", 500)
	}

	session, rawToken, err := s.sessionSvc.Create(ctx, user.ID, "", "")
	if err != nil {
		return nil, domain.NewError("internal_error", "Failed to create session", 500)
	}

	return &RegisterResult{
		User:         user,
		Session:      session,
		SessionToken: rawToken,
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

	if s.config.RequireEmailVerification && !user.IsVerified && !isAdmin(user, s.config.AdminEmails) {
		return nil, domain.ErrEmailNotVerified
	}

	if err := s.hasher.Compare(input.Password, user.PasswordHash); err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	session, rawToken, err := s.sessionSvc.Create(ctx, user.ID, input.IP, input.UserAgent)
	if err != nil {
		return nil, domain.NewError("internal_error", "Failed to create session", 500)
	}

	return &LoginResult{
		User:         user,
		Session:      session,
		SessionToken: rawToken,
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

func (s *AuthService) sendVerificationEmail(ctx context.Context, user *domain.User) *domain.AuthError {
	raw, err := s.gen.Generate()
	if err != nil {
		return domain.NewError("internal_error", "Failed to generate token", 500)
	}

	// For verification tokens we store the token directly (stateless verification uses code)
	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:        uuid.New().String(),
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hashToken(raw),
		Type:      domain.TokenVerifyEmail,
		ExpiresAt: now.Add(s.config.TokenTTL),
	}

	if err := s.tokens.Create(ctx, token); err != nil {
		return domain.NewError("internal_error", "Failed to store token", 500)
	}

	if s.mailer == nil {
		return nil
	}

	body := "Your verification code: " + raw + "\n\nExpires in: " + s.config.TokenTTL.String()

	if err := s.mailer.Send(ctx, user.Email, "Verify your email - "+s.config.AppName, body); err != nil {
		return domain.NewError("email_failed", "Failed to send verification email", 500)
	}

	return nil
}

func isAdmin(user *domain.User, adminEmails []string) bool {
	for _, e := range adminEmails {
		if strings.EqualFold(user.Email, e) {
			return true
		}
	}
	return false
}

func validateEmail(email string) *domain.AuthError {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return domain.ErrInvalidEmail
	}
	return nil
}

func validatePassword(password string) *domain.AuthError {
	if len(password) < 8 {
		return domain.ErrWeakPassword
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSpecial = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return domain.NewError("weak_password", "Password must be at least 8 characters with uppercase, lowercase, digit, and special character", http.StatusBadRequest)
	}
	return nil
}
