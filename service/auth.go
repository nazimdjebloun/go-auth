package service

import (
	"context"
	"net/mail"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type AuthService struct {
	users    port.UserRepository
	sessions port.SessionRepository
	tokens   port.TokenRepository
	hasher   port.Hasher
	gen      port.TokenGenerator
	email    port.EmailSender
	config   Config
}

type Config struct {
	AppName             string
	AdminEmails         []string
	InviteOnly          bool
	InviteTTL           time.Duration
	VerificationCodeTTL time.Duration
	SessionTTL          time.Duration
	TokenTTL            time.Duration
	BcryptCost          int
	TokenLength         int
	EmailTemplates      EmailTemplates
}

type EmailTemplates struct {
	VerifyEmail   string
	PasswordReset string
	InviteEmail   string
}

func NewAuthService(
	users port.UserRepository,
	sessions port.SessionRepository,
	tokens port.TokenRepository,
	hasher port.Hasher,
	gen port.TokenGenerator,
	email port.EmailSender,
	config Config,
) *AuthService {
	return &AuthService{
		users:    users,
		sessions: sessions,
		tokens:   tokens,
		hasher:   hasher,
		gen:      gen,
		email:    email,
		config:   config,
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
	if input.Name == "" {
		input.Name = input.Email[:strings.Index(input.Email, "@")]
	}

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
		ID:           generateID(),
		Email:        input.Email,
		PasswordHash: hash,
		Name:         input.Name,
		Role:         role,
		IsVerified:   false,
		IsBanned:     false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.users.Create(ctx, user); err != nil {
		return nil, domain.NewError("internal_error", "Failed to create user", 500)
	}

	raw, tokenHash, err := s.gen.Generate()
	if err != nil {
		s.users.Delete(ctx, user.ID)
		return nil, domain.NewError("internal_error", "Failed to generate session", 500)
	}

	session := &domain.Session{
		ID:         generateID(),
		UserID:     user.ID,
		TokenHash:  tokenHash,
		ExpiresAt:  now.Add(s.config.SessionTTL),
		CreatedAt:  now,
		LastUsedAt: now,
	}

	if err := s.sessions.Create(ctx, session); err != nil {
		s.users.Delete(ctx, user.ID)
		return nil, domain.NewError("internal_error", "Failed to create session", 500)
	}

	// send verification email
	if err := s.sendVerificationEmail(ctx, user); err != nil {
		// non-fatal: log in production
	}

	return &RegisterResult{
		User:         user,
		Session:      session,
		SessionToken: raw,
	}, nil
}

func (s *AuthService) Login(ctx context.Context, input LoginInput) (*LoginResult, *domain.AuthError) {
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))

	user, err := s.users.GetByEmail(ctx, input.Email)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}
	if user == nil {
		return nil, domain.ErrInvalidCredentials
	}

	if user.IsBanned {
		return nil, domain.ErrUserBanned
	}

	if err := s.hasher.Compare(input.Password, user.PasswordHash); err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	now := time.Now().UTC()

	raw, tokenHash, err := s.gen.Generate()
	if err != nil {
		return nil, domain.NewError("internal_error", "Failed to generate session", 500)
	}

	session := &domain.Session{
		ID:         generateID(),
		UserID:     user.ID,
		TokenHash:  tokenHash,
		IPAddress:  input.IP,
		UserAgent:  input.UserAgent,
		ExpiresAt:  now.Add(s.config.SessionTTL),
		CreatedAt:  now,
		LastUsedAt: now,
	}

	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, domain.NewError("internal_error", "Failed to create session", 500)
	}

	return &LoginResult{
		User:         user,
		Session:      session,
		SessionToken: raw,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, sessionID string) *domain.AuthError {
	if err := s.sessions.Revoke(ctx, sessionID); err != nil {
		return domain.NewError("internal_error", "Failed to revoke session", 500)
	}
	return nil
}

func (s *AuthService) ValidateSession(ctx context.Context, tokenRaw string) (*domain.User, *domain.Session, *domain.AuthError) {
	tokenHash := s.gen.Hash(tokenRaw)

	session, err := s.sessions.GetByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, nil, domain.ErrSessionExpired
	}
	if session == nil {
		return nil, nil, domain.ErrSessionExpired
	}
	if session.IsRevoked {
		return nil, nil, domain.ErrSessionExpired
	}
	if time.Now().UTC().After(session.ExpiresAt) {
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

func (s *AuthService) sendVerificationEmail(ctx context.Context, user *domain.User) *domain.AuthError {
	raw, hash, err := s.gen.Generate()
	if err != nil {
		return domain.NewError("internal_error", "Failed to generate token", 500)
	}

	now := time.Now().UTC()
	token := &domain.VerificationToken{
		ID:        generateID(),
		UserID:    &user.ID,
		Email:     user.Email,
		TokenHash: hash,
		Type:      domain.TokenVerifyEmail,
		ExpiresAt: now.Add(s.config.TokenTTL),
	}

	if err := s.tokens.Create(ctx, token); err != nil {
		return domain.NewError("internal_error", "Failed to store token", 500)
	}

	if s.email == nil {
		return nil
	}

	data := map[string]any{
		"Code":      raw,
		"Email":     user.Email,
		"AppName":   s.config.AppName,
		"ExpiresIn": s.config.TokenTTL.String(),
	}

	if err := s.email.Send(ctx, port.EmailData{
		To:           user.Email,
		Subject:      "Verify your email",
		TemplateName: "verify_email",
		TemplateData: data,
	}); err != nil {
		return domain.NewError("email_failed", "Failed to send verification email", 500)
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

func validatePassword(password string) *domain.AuthError {
	if len(password) < 8 {
		return domain.ErrWeakPassword
	}
	return nil
}
