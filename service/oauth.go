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
	providers    map[string]port.OAuthProvider
	providerRepo port.ProviderAccountRepository
	userRepo     port.UserRepository
	tokenRepo    port.TokenRepository
	hasher       port.Hasher
	gen          port.TokenGenerator
	sessionSvc   *SessionService
	verifySvc    *VerificationService
	config       OAuthServiceConfig
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
	}
}

func generateStateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
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

	stateToken := &domain.VerificationToken{
		ID:        uuid.New().String(),
		TokenHash: hashToken(stateRaw),
		Type:      domain.TokenOAuthState,
		ExpiresAt: now.Add(10 * time.Minute),
	}

	if err := s.tokenRepo.Create(ctx, stateToken); err != nil {
		return "", domain.NewError("internal_error", "Failed to store state token", 500)
	}

	return p.AuthURL(stateRaw), nil
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

	return p.AuthURL(stateRaw), nil
}

// Callback handles the OAuth callback for both login and link flows.
// If the state token has a UserID, it's a link flow (no session created).
// If no UserID, it's a login flow (user may be created or logged in).
// Returns (sessionToken, isNewUser, authErr). sessionToken is empty for link flow.
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
		return "", "", false, false, "", domain.NewError("internal_error", "Failed to consume state token", 500)
	}

	info, exchangeErr := p.Exchange(ctx, code)
	if exchangeErr != nil {
		return "", "", false, false, "", domain.NewError("provider_error", "Failed to authenticate with provider", 502)
	}

	existing, lookupErr := s.providerRepo.GetByProvider(ctx, providerName, info.ProviderUserID)
	if lookupErr != nil {
		return "", "", false, false, "", domain.NewError("internal_error", "Failed to look up provider account", 500)
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
		return "", "", false, false, "", nil
	}

	if existing != nil {
		user, userErr := s.userRepo.GetByID(ctx, existing.UserID)
		if userErr != nil || user == nil {
			return "", "", false, false, "", domain.NewError("internal_error", "Failed to find linked user", 500)
		}
		if user.IsBanned {
			return "", "", false, false, "", domain.ErrUserBanned
		}

		if s.config.RequireEmailVerification && !user.IsVerified {
			if err := s.verifySvc.SendVerification(ctx, user); err != nil {
				return "", "", false, false, "", err
			}
			return "", "", false, true, user.Email, nil
		}

		session, rawToken, refreshToken, sessionErr := s.sessionSvc.Create(ctx, user.ID, ip, userAgent)
		if sessionErr != nil {
			return "", "", false, false, "", domain.NewError("internal_error", "Failed to create session", 500)
		}
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
		ID:        uuid.New().String(),
		Email:     info.Email,
		Name:      info.Name,
		Role:      domain.RoleUser,
		IsBanned:  false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.userRepo.Create(ctx, newUser); err != nil {
		return "", "", false, false, "", domain.NewError("internal_error", "Failed to create user", 500)
	}

	if _, linkErr := s.createProviderAccount(ctx, newUser.ID, info); linkErr != nil {
		return "", "", false, false, "", linkErr
	}

	if s.config.RequireEmailVerification {
		if err := s.verifySvc.SendVerification(ctx, newUser); err != nil {
			return "", "", false, false, "", err
		}
		return "", "", true, true, newUser.Email, nil
	}

	session, rawToken, refreshToken, sessionErr := s.sessionSvc.Create(ctx, newUser.ID, ip, userAgent)
	if sessionErr != nil {
		return "", "", false, false, "", domain.NewError("internal_error", "Failed to create session", 500)
	}
	_ = session

	return rawToken, refreshToken, true, false, "", nil
}

// Link connects a provider to an existing user.
// Used when the callback returns link flow (userID from state token).
func (s *OAuthService) Link(ctx context.Context, userID, providerName, code, rawState string) *domain.AuthError {
	_, _, _, _, _, err := s.Callback(ctx, providerName, code, rawState, "", "")
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

func (s *OAuthService) createProviderAccount(ctx context.Context, userID string, info *port.OAuthProfile) (*domain.ProviderAccount, *domain.AuthError) {
	now := time.Now().UTC()
	// Intentionally do not persist provider access/refresh tokens.
	// A DB leak would otherwise grant API access to the linked provider
	// account. Identity linkage only needs provider + provider_user_id.
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
		return nil, domain.NewError("internal_error", "Failed to store provider account", 500)
	}
	return pa, nil
}
