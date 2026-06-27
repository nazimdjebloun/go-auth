package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type OAuthService struct {
	providers    map[string]port.Provider
	providerRepo port.ProviderAccountRepository
	userRepo     port.UserRepository
	tokenRepo    port.TokenRepository
	hasher       port.Hasher
	gen          port.TokenGenerator
	sessionSvc   *SessionService
	config       OAuthServiceConfig
}

type OAuthServiceConfig struct {
	AppName        string
	BaseURL        string
	SessionTTL     time.Duration
	TokenTTL       time.Duration
	CookieName     string
	CookieDomain   string
	CookiePath     string
	CookieSecure   bool
	CookieSameSite http.SameSite
}

func NewOAuthService(
	providers map[string]port.Provider,
	providerRepo port.ProviderAccountRepository,
	userRepo port.UserRepository,
	tokenRepo port.TokenRepository,
	hasher port.Hasher,
	gen port.TokenGenerator,
	sessionSvc *SessionService,
	config OAuthServiceConfig,
) *OAuthService {
	return &OAuthService{
		providers:    providers,
		providerRepo: providerRepo,
		userRepo:     userRepo,
		tokenRepo:    tokenRepo,
		hasher:       hasher,
		gen:          gen,
		sessionSvc:   sessionSvc,
		config:       config,
	}
}

func generateStateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *OAuthService) getProvider(name string) (port.Provider, *domain.AuthError) {
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

	stateToken := &domain.VerificationToken{
		ID:        uuid.New().String(),
		TokenHash: hashToken(stateRaw),
		Type:      domain.TokenOAuthState,
		ExpiresAt: now.Add(10 * time.Minute),
	}

	if err := s.tokenRepo.Create(ctx, stateToken); err != nil {
		return "", domain.NewError("internal_error", "Failed to store state token", 500)
	}

	return p.GetAuthorizeURL(stateRaw), nil
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

	stateToken := &domain.VerificationToken{
		ID:        uuid.New().String(),
		UserID:    &userID,
		TokenHash: hashToken(stateRaw),
		Type:      domain.TokenOAuthState,
		ExpiresAt: now.Add(10 * time.Minute),
	}

	if err := s.tokenRepo.Create(ctx, stateToken); err != nil {
		return "", domain.NewError("internal_error", "Failed to store state token", 500)
	}

	return p.GetAuthorizeURL(stateRaw), nil
}

// Callback handles the OAuth callback for both login and link flows.
// If the state token has a UserID, it's a link flow (no session created).
// If no UserID, it's a login flow (user may be created or logged in).
// Returns (sessionToken, isNewUser, authErr). sessionToken is empty for link flow.
func (s *OAuthService) Callback(ctx context.Context, providerName, code, rawState, ip, userAgent string) (string, string, bool, *domain.AuthError) {
	p, err := s.getProvider(providerName)
	if err != nil {
		return "", "", false, err
	}

	stateHash := hashToken(rawState)
	stateToken, repoErr := s.tokenRepo.GetByHash(ctx, stateHash)
	if repoErr != nil || stateToken == nil || stateToken.Type != domain.TokenOAuthState {
		return "", "", false, domain.NewError("invalid_state", "Invalid or expired OAuth state", 400)
	}

	if stateToken.UsedAt != nil {
		return "", "", false, domain.NewError("state_used", "OAuth state token already used", 400)
	}

	if time.Now().UTC().After(stateToken.ExpiresAt) {
		return "", "", false, domain.NewError("state_expired", "OAuth state token has expired", 400)
	}

	if markErr := s.tokenRepo.MarkUsed(ctx, stateToken.ID); markErr != nil {
		return "", "", false, domain.NewError("internal_error", "Failed to consume state token", 500)
	}

	info, exchangeErr := p.ExchangeCode(ctx, code)
	if exchangeErr != nil {
		return "", "", false, domain.NewError("provider_error", "Failed to authenticate with provider", 502)
	}

	if !info.EmailVerified {
		return "", "", false, domain.ErrProviderEmailUnverified
	}

	existing, lookupErr := s.providerRepo.GetByProvider(ctx, providerName, info.ProviderID)
	if lookupErr != nil {
		return "", "", false, domain.NewError("internal_error", "Failed to look up provider account", 500)
	}

	userID := stateToken.UserID

	if userID != nil {
		if existing != nil {
			if existing.UserID == *userID {
				return "", "", false, domain.NewError("already_linked", "This provider is already linked to your account", 409)
			}
			return "", "", false, domain.ErrProviderAccountExists
		}

		_, linkErr := s.createProviderAccount(ctx, *userID, info)
		if linkErr != nil {
			return "", "", false, linkErr
		}
		return "", "", false, nil
	}

	if existing != nil {
		user, userErr := s.userRepo.GetByID(ctx, existing.UserID)
		if userErr != nil || user == nil {
			return "", "", false, domain.NewError("internal_error", "Failed to find linked user", 500)
		}
		if user.IsBanned {
			return "", "", false, domain.ErrUserBanned
		}

		session, rawToken, refreshToken, sessionErr := s.sessionSvc.Create(ctx, user.ID, ip, userAgent)
		if sessionErr != nil {
			return "", "", false, domain.NewError("internal_error", "Failed to create session", 500)
		}
		_ = session
		_ = refreshToken
		return rawToken, refreshToken, false, nil
	}

	existingUser, userErr := s.userRepo.GetByEmail(ctx, info.Email)
	if userErr != nil || existingUser != nil {
		return "", "", false, domain.ErrEmailAlreadyExists
	}

	now := time.Now().UTC()
	newUser := &domain.User{
		ID:        uuid.New().String(),
		Email:     info.Email,
		Name:      info.Name,
		Role:      domain.RoleUser,
		IsBanned:  false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.userRepo.Create(ctx, newUser); err != nil {
		return "", "", false, domain.NewError("internal_error", "Failed to create user", 500)
	}

	if _, linkErr := s.createProviderAccount(ctx, newUser.ID, info); linkErr != nil {
		return "", "", false, linkErr
	}

	session, rawToken, refreshToken, sessionErr := s.sessionSvc.Create(ctx, newUser.ID, ip, userAgent)
	if sessionErr != nil {
		return "", "", false, domain.NewError("internal_error", "Failed to create session", 500)
	}
	_ = session

	return rawToken, refreshToken, true, nil
}

// Link connects a provider to an existing user.
// Used when the callback returns link flow (userID from state token).
func (s *OAuthService) Link(ctx context.Context, userID, providerName, code, rawState string) *domain.AuthError {
	_, _, _, err := s.Callback(ctx, providerName, code, rawState, "", "")
	return err
}

func (s *OAuthService) Unlink(ctx context.Context, userID, providerName string) *domain.AuthError {
	accounts, err := s.providerRepo.ListByUserID(ctx, userID)
	if err != nil {
		return domain.NewError("internal_error", "Failed to list provider accounts", 500)
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
		return domain.NewError("internal_error", "Failed to unlink provider", 500)
	}

	return nil
}

func (s *OAuthService) ListConnected(ctx context.Context, userID string) ([]domain.ProviderAccount, *domain.AuthError) {
	accounts, err := s.providerRepo.ListByUserID(ctx, userID)
	if err != nil {
		return nil, domain.NewError("internal_error", "Failed to list provider accounts", 500)
	}
	return accounts, nil
}

func (s *OAuthService) createProviderAccount(ctx context.Context, userID string, info *port.ProviderUserInfo) (*domain.ProviderAccount, *domain.AuthError) {
	now := time.Now().UTC()
	pa := &domain.ProviderAccount{
		ID:             uuid.New().String(),
		UserID:         userID,
		Provider:       info.Provider,
		ProviderUserID: info.ProviderID,
		ProviderEmail:  info.Email,
		ProviderName:   info.Name,
		AvatarURL:      info.AvatarURL,
		AccessToken:    info.AccessToken,
		RefreshToken:   info.RefreshToken,
		TokenExpiresAt: info.TokenExpiresAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.providerRepo.Create(ctx, pa); err != nil {
		return nil, domain.NewError("internal_error", "Failed to store provider account", 500)
	}
	return pa, nil
}
