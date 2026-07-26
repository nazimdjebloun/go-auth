package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type OAuthService struct {
	providers    map[string]port.OAuthProvider
	providerRepo port.ProviderAccountRepository
	userRepo     port.UserRepository
	tokenRepo    port.TokenRepository
	hasher       port.Hasher
	gen          port.TokenGenerator
	sessionSvc   *SessionService
	verifySvc    *VerificationService
	config       OAuthServiceConfig
	log          *slog.Logger
}

type OAuthServiceConfig struct {
	AppName                  string
	BaseURL                  string
	SessionTTL               time.Duration
	TokenTTL                 time.Duration
	CookieName               string
	CookieDomain             string
	CookiePath               string
	CookieSecure             bool
	CookieSameSite           http.SameSite
	RequireEmailVerification bool
	Logger                   *slog.Logger
}

func NewOAuthService(
	providers map[string]port.OAuthProvider,
	providerRepo port.ProviderAccountRepository,
	userRepo port.UserRepository,
	tokenRepo port.TokenRepository,
	hasher port.Hasher,
	gen port.TokenGenerator,
	sessionSvc *SessionService,
	verifySvc *VerificationService,
	config OAuthServiceConfig,
) *OAuthService {
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &OAuthService{
		providers:    providers,
		providerRepo: providerRepo,
		userRepo:     userRepo,
		tokenRepo:    tokenRepo,
		hasher:       hasher,
		gen:          gen,
		sessionSvc:   sessionSvc,
		verifySvc:    verifySvc,
		config:       config,
		log:          logger,
	}
}

func generateStateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// generateCodeVerifier returns a cryptographically random 64-byte value
// encoded as a base64url string (no padding) per RFC 7636 §4.1.
func generateCodeVerifier() (string, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// codeChallengeS256 returns the S256 code_challenge for a given verifier
// per RFC 7636 §4.2: base64url(sha256(verifier)).
func codeChallengeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func (s *OAuthService) getProvider(name string) (port.OAuthProvider, *domain.AuthError) {
	p, ok := s.providers[name]
	if !ok {
		return nil, domain.ErrProviderNotFound
	}
	return p, nil
}

// Initiate starts an OAuth login flow.
// Returns the provider's authorize URL for frontend redirect.
func (s *OAuthService) Initiate(ctx context.Context, providerName string) (string, *domain.AuthError) {
	p, err := s.getProvider(providerName)
	if err != nil {
		return "", err
	}

	stateRaw := generateStateToken()
	now := time.Now().UTC()

	codeVerifier, verifierErr := generateCodeVerifier()
	if verifierErr != nil {
		s.log.Error("failed to generate PKCE verifier", "err", verifierErr)
		return "", domain.NewError("internal_error", "Internal server error", 500)
	}

	stateToken := &domain.VerificationToken{
		ID:           uuid.New().String(),
		TokenHash:    hashToken(stateRaw),
		Type:         domain.TokenOAuthState,
		ExpiresAt:    now.Add(10 * time.Minute),
		CodeVerifier: &codeVerifier,
	}

	if err := s.tokenRepo.Create(ctx, stateToken); err != nil {
		s.log.Error("failed to store state token", "err", err, "provider", providerName)
		return "", domain.NewError("internal_error", "Internal server error", 500)
	}

	codeChallenge := codeChallengeS256(codeVerifier)
	return p.AuthURL(stateRaw, codeChallenge), nil
}

// InitiateLink starts an OAuth link flow for an authenticated user.
// Stores the userID in the state token to distinguish from login flow.
func (s *OAuthService) InitiateLink(ctx context.Context, providerName, userID string) (string, *domain.AuthError) {
	p, err := s.getProvider(providerName)
	if err != nil {
		return "", err
	}

	stateRaw := generateStateToken()
	now := time.Now().UTC()

	codeVerifier, verifierErr := generateCodeVerifier()
	if verifierErr != nil {
		s.log.Error("failed to generate PKCE verifier", "err", verifierErr)
		return "", domain.NewError("internal_error", "Internal server error", 500)
	}

	stateToken := &domain.VerificationToken{
		ID:           uuid.New().String(),
		UserID:       &userID,
		TokenHash:    hashToken(stateRaw),
		Type:         domain.TokenOAuthState,
		ExpiresAt:    now.Add(10 * time.Minute),
		CodeVerifier: &codeVerifier,
	}

	if err := s.tokenRepo.Create(ctx, stateToken); err != nil {
		s.log.Error("failed to store state token", "err", err, "provider", providerName, "user_id", userID)
		return "", domain.NewError("internal_error", "Internal server error", 500)
	}

	codeChallenge := codeChallengeS256(codeVerifier)
	return p.AuthURL(stateRaw, codeChallenge), nil
}

// Callback handles the OAuth callback for both login and link flows.
func (s *OAuthService) Callback(ctx context.Context, providerName, code, rawState, ip, userAgent string) (string, string, bool, bool, string, *domain.AuthError) {
	p, err := s.getProvider(providerName)
	if err != nil {
		return "", "", false, false, "", err
	}

	stateHash := hashToken(rawState)
	stateToken, repoErr := s.tokenRepo.GetByHash(ctx, stateHash)
	if repoErr != nil || stateToken == nil || stateToken.Type != domain.TokenOAuthState {
		return "", "", false, false, "", domain.NewError("invalid_state", "Invalid or expired OAuth state", 400)
	}

	if stateToken.UsedAt != nil {
		return "", "", false, false, "", domain.NewError("state_used", "OAuth state token already used", 400)
	}

	if time.Now().UTC().After(stateToken.ExpiresAt) {
		return "", "", false, false, "", domain.NewError("state_expired", "OAuth state token has expired", 400)
	}

	if markErr := s.tokenRepo.MarkUsed(ctx, stateToken.ID); markErr != nil {
		s.log.Error("failed to mark state token used", "err", markErr)
		return "", "", false, false, "", domain.NewError("internal_error", "Internal server error", 500)
	}

	codeVerifier := ""
	if stateToken.CodeVerifier != nil {
		codeVerifier = *stateToken.CodeVerifier
	}

	info, exchangeErr := p.Exchange(ctx, code, codeVerifier)
	if exchangeErr != nil {
		s.log.Error("provider exchange failed", "err", exchangeErr, "provider", providerName)
		return "", "", false, false, "", domain.NewError("provider_error", "Failed to authenticate with provider", 502)
	}

	existing, lookupErr := s.providerRepo.GetByProvider(ctx, providerName, info.ProviderUserID)
	if lookupErr != nil {
		s.log.Error("failed to look up provider account", "err", lookupErr, "provider", providerName)
		return "", "", false, false, "", domain.NewError("internal_error", "Internal server error", 500)
	}

	userID := stateToken.UserID

	if userID != nil {
		if existing != nil {
			if existing.UserID == *userID {
				return "", "", false, false, "", domain.NewError("already_linked", "This provider is already linked to your account", 409)
			}
			return "", "", false, false, "", domain.ErrProviderAccountExists
		}

		_, linkErr := s.createProviderAccount(ctx, *userID, info)
		if linkErr != nil {
			return "", "", false, false, "", linkErr
		}
		s.log.Info("provider linked", "user_id", *userID, "provider", providerName)
		return "", "", false, false, "", nil
	}

	if existing != nil {
		user, userErr := s.userRepo.GetByID(ctx, existing.UserID)
		if userErr != nil || user == nil {
			s.log.Error("failed to find linked user", "err", userErr, "user_id", existing.UserID)
			return "", "", false, false, "", domain.NewError("internal_error", "Internal server error", 500)
		}
		if user.IsBanned {
			return "", "", false, false, "", domain.ErrUserBanned
		}

		// Upgrade verification status if the provider confirms the email.
		if info.EmailVerified && !user.IsVerified {
			now := time.Now().UTC()
			user.IsVerified = true
			user.VerifiedAt = &now
			user.UpdatedAt = now
			s.userRepo.Update(ctx, user)
		}

		if s.config.RequireEmailVerification && !user.IsVerified {
			if err := s.verifySvc.SendVerification(ctx, user); err != nil {
				return "", "", false, false, "", err
			}
			return "", "", false, true, user.Email, nil
		}

		session, rawToken, refreshToken, sessionErr := s.sessionSvc.Create(ctx, user.ID, ip, userAgent)
		if sessionErr != nil {
			s.log.Error("failed to create session", "err", sessionErr, "user_id", user.ID)
			return "", "", false, false, "", domain.NewError("internal_error", "Internal server error", 500)
		}
		s.log.Info("oauth login", "user_id", user.ID, "provider", providerName, "ip", ip)
		_ = session
		_ = refreshToken
		return rawToken, refreshToken, false, false, "", nil
	}

	existingUser, userErr := s.userRepo.GetByEmail(ctx, info.Email)
	if userErr != nil || existingUser != nil {
		return "", "", false, false, "", domain.ErrEmailAlreadyExists
	}

	now := time.Now().UTC()
	newUser := &domain.User{
		ID:         uuid.New().String(),
		Email:      info.Email,
		Name:       info.Name,
		Role:       domain.RoleUser,
		IsVerified: info.EmailVerified,
		IsBanned:   false,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if info.EmailVerified {
		newUser.VerifiedAt = &now
	}

	if err := s.userRepo.Create(ctx, newUser); err != nil {
		s.log.Error("failed to create user", "err", err, "email", info.Email)
		return "", "", false, false, "", domain.NewError("internal_error", "Internal server error", 500)
	}

	if _, linkErr := s.createProviderAccount(ctx, newUser.ID, info); linkErr != nil {
		return "", "", false, false, "", linkErr
	}

	s.log.Info("oauth register", "user_id", newUser.ID, "provider", providerName, "email_verified", info.EmailVerified)

	// Only send verification email if the provider did NOT verify the email
	// and email verification is required.
	if s.config.RequireEmailVerification && !newUser.IsVerified {
		if err := s.verifySvc.SendVerification(ctx, newUser); err != nil {
			return "", "", false, false, "", err
		}
		return "", "", true, true, newUser.Email, nil
	}

	session, rawToken, refreshToken, sessionErr := s.sessionSvc.Create(ctx, newUser.ID, ip, userAgent)
	if sessionErr != nil {
		s.log.Error("failed to create session", "err", sessionErr, "user_id", newUser.ID)
		return "", "", false, false, "", domain.NewError("internal_error", "Internal server error", 500)
	}
	_ = session

	return rawToken, refreshToken, true, false, "", nil
}

// Link connects a provider to an existing user.
func (s *OAuthService) Link(ctx context.Context, userID, providerName, code, rawState string) *domain.AuthError {
	_, _, _, _, _, err := s.Callback(ctx, providerName, code, rawState, "", "")
	return err
}

func (s *OAuthService) Unlink(ctx context.Context, userID, providerName string) *domain.AuthError {
	accounts, err := s.providerRepo.ListByUserID(ctx, userID)
	if err != nil {
		s.log.Error("failed to list provider accounts", "err", err, "user_id", userID)
		return domain.NewError("internal_error", "Internal server error", 500)
	}

	user, userErr := s.userRepo.GetByID(ctx, userID)
	if userErr != nil || user == nil {
		return domain.ErrUserNotFound
	}

	hasPassword := user.HasPassword()
	if len(accounts) <= 1 && !hasPassword {
		return domain.ErrCannotUnlinkLastProvider
	}

	if err := s.providerRepo.Delete(ctx, userID, providerName); err != nil {
		s.log.Error("failed to unlink provider", "err", err, "user_id", userID, "provider", providerName)
		return domain.NewError("internal_error", "Internal server error", 500)
	}

	s.log.Info("provider unlinked", "user_id", userID, "provider", providerName)
	return nil
}

func (s *OAuthService) ListConnected(ctx context.Context, userID string) ([]domain.ProviderAccount, *domain.AuthError) {
	accounts, err := s.providerRepo.ListByUserID(ctx, userID)
	if err != nil {
		s.log.Error("failed to list provider accounts", "err", err, "user_id", userID)
		return nil, domain.NewError("internal_error", "Internal server error", 500)
	}
	return accounts, nil
}

func (s *OAuthService) createProviderAccount(ctx context.Context, userID string, info *port.OAuthProfile) (*domain.ProviderAccount, *domain.AuthError) {
	now := time.Now().UTC()
	pa := &domain.ProviderAccount{
		ID:             uuid.New().String(),
		UserID:         userID,
		Provider:       info.Provider,
		ProviderUserID: info.ProviderUserID,
		ProviderEmail:  info.Email,
		ProviderName:   info.Name,
		AvatarURL:      info.AvatarURL,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.providerRepo.Create(ctx, pa); err != nil {
		s.log.Error("failed to store provider account", "err", err, "user_id", userID, "provider", info.Provider)
		return nil, domain.NewError("internal_error", "Internal server error", 500)
	}
	return pa, nil
}
