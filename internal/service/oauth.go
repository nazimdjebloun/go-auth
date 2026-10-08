package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/crypto"
	"github.com/nazimdjebloun/go-auth/port"
)

// OAuthService manages OAuth login and account linking.
type OAuthService struct {
	providers    map[string]port.OAuthProvider
	providerRepo port.ProviderAccountRepository
	userRepo     port.UserRepository
	tokenRepo    port.TokenRepository
	hasher       port.Hasher
	gen          port.TokenGenerator
	sessionSvc   *SessionService
	verifySvc    *VerificationService
	twoFactorSvc *TwoFactorService
	txManager    port.TxManager
	encryptor    *crypto.Encryptor
	config       OAuthServiceConfig
	log          *slog.Logger
	audit        AuditPublisher
}

// OAuthServiceConfig has no cookie settings — cookies are written by the
// HTTP layer (see middleware.SetSessionCookie / auth.go's Mount wiring)
// using the top-level CookieConfig, not by OAuthService itself.
type OAuthServiceConfig struct {
	CommonConfig
	AppPermissions *AppPermissionsService

	RequireEmailVerification bool
	EnableOAuth              bool
	InviteOnly               bool
	Encryptor                *crypto.Encryptor
	DisableAdminTwoFactor    bool
}

// AttachTwoFactor wires admin OAuth challenges before requests are served.
func (s *OAuthService) AttachTwoFactor(twoFactor *TwoFactorService) { s.twoFactorSvc = twoFactor }

// NewOAuthService returns an OAuth service.
func NewOAuthService(
	providers map[string]port.OAuthProvider,
	providerRepo port.ProviderAccountRepository,
	userRepo port.UserRepository,
	tokenRepo port.TokenRepository,
	hasher port.Hasher,
	gen port.TokenGenerator,
	sessionSvc *SessionService,
	verifySvc *VerificationService,
	txManager port.TxManager,
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
		txManager:    txManager,
		encryptor:    config.Encryptor,
		config:       config,
		log:          logger,
		audit:        config.Audit,
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

func (s *OAuthService) getProvider(name string) (port.OAuthProvider, error) {
	p, ok := s.providers[name]
	if !ok {
		return nil, domain.ErrProviderNotFound
	}
	return p, nil
}

// Initiate starts an OAuth login flow.
func (s *OAuthService) Initiate(ctx context.Context, providerName string) (*api.OAuthInitiation, error) {
	p, err := s.getProvider(providerName)
	if err != nil {
		return nil, err
	}

	stateRaw := generateStateToken()
	now := time.Now().UTC()

	codeVerifier, verifierErr := generateCodeVerifier()
	if verifierErr != nil {
		s.log.Error("failed to generate PKCE verifier", "err", verifierErr)
		return nil, domain.ErrInternal
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
		return nil, domain.ErrInternal
	}

	codeChallenge := codeChallengeS256(codeVerifier)
	return &api.OAuthInitiation{URL: p.AuthURL(stateRaw, codeChallenge), State: stateRaw}, nil
}

// InitiateLink starts an OAuth link flow for an authenticated user.
// The state stores the initiating session's token hash in its otherwise unused
// Email field, so callback must present that same live session. OAuth state
// rows never represent an email address.
func (s *OAuthService) InitiateLink(ctx context.Context, input api.OAuthLinkInput) (*api.OAuthInitiation, error) {
	p, err := s.getProvider(input.Provider)
	if err != nil {
		return nil, err
	}
	if input.UserID == "" || input.SessionTokenHash == "" {
		return nil, domain.NewError("unauthorized", "Authentication required")
	}

	stateRaw := generateStateToken()
	now := time.Now().UTC()

	codeVerifier, verifierErr := generateCodeVerifier()
	if verifierErr != nil {
		s.log.Error("failed to generate PKCE verifier", "err", verifierErr)
		return nil, domain.ErrInternal
	}

	stateToken := &domain.VerificationToken{
		ID:           uuid.New().String(),
		UserID:       &input.UserID,
		Email:        input.SessionTokenHash,
		TokenHash:    hashToken(stateRaw),
		Type:         domain.TokenOAuthState,
		ExpiresAt:    now.Add(10 * time.Minute),
		CodeVerifier: &codeVerifier,
	}

	if err := s.tokenRepo.Create(ctx, stateToken); err != nil {
		s.log.Error("failed to store state token", "err", err, "provider", input.Provider, "user_id", input.UserID)
		return nil, domain.ErrInternal
	}

	codeChallenge := codeChallengeS256(codeVerifier)
	return &api.OAuthInitiation{URL: p.AuthURL(stateRaw, codeChallenge), State: stateRaw}, nil
}

// Callback completes an OAuth login or account link.
func (s *OAuthService) Callback(ctx context.Context, input api.OAuthCallbackInput) (*api.OAuthCallbackResult, error) {
	p, err := s.getProvider(input.Provider)
	if err != nil {
		return nil, err
	}
	if input.State == "" || subtle.ConstantTimeCompare([]byte(input.State), []byte(input.BrowserState)) != 1 {
		return nil, domain.NewError("invalid_state", "Invalid or expired OAuth state")
	}

	stateHash := hashToken(input.State)
	stateToken, repoErr := s.tokenRepo.GetByHash(ctx, stateHash)
	if repoErr != nil {
		return nil, fmt.Errorf("oauth callback: look up state: %w", repoErr)
	}
	if stateToken == nil || stateToken.Type != domain.TokenOAuthState {
		return nil, domain.NewError("invalid_state", "Invalid or expired OAuth state")
	}

	if stateToken.UsedAt != nil {
		return nil, domain.ErrOAuthStateUsed
	}

	if time.Now().UTC().After(stateToken.ExpiresAt) {
		return nil, domain.NewError("state_expired", "OAuth state token has expired")
	}
	if stateToken.UserID != nil {
		if input.SessionToken == "" || stateToken.Email == "" || subtle.ConstantTimeCompare([]byte(hashToken(input.SessionToken)), []byte(stateToken.Email)) != 1 {
			return nil, domain.NewError("unauthorized", "Authentication required")
		}
		session, user, validateErr := s.sessionSvc.ValidateWithUser(ctx, input.SessionToken)
		if validateErr != nil && !isSessionValidationRejection(validateErr) {
			return nil, fmt.Errorf("oauth callback: validate linking session: %w", validateErr)
		}
		if validateErr != nil || session == nil || user == nil || user.ID != *stateToken.UserID {
			return nil, domain.NewError("unauthorized", "Authentication required")
		}
		if user.IsBanned {
			return nil, domain.ErrUserBanned
		}
	}

	claimed, markErr := s.tokenRepo.MarkUsedIfUnused(ctx, stateToken.ID)
	if markErr != nil {
		s.log.Error("failed to mark state token used", "err", markErr)
		return nil, domain.ErrInternal
	}
	if !claimed {
		return nil, domain.ErrOAuthStateUsed
	}

	codeVerifier := ""
	if stateToken.CodeVerifier != nil {
		codeVerifier = *stateToken.CodeVerifier
	}

	info, exchangeErr := p.Exchange(ctx, input.Code, codeVerifier)
	if exchangeErr != nil {
		s.log.Error("provider exchange failed", "err", exchangeErr, "provider", input.Provider)
		return nil, domain.NewError("provider_error", "Failed to authenticate with provider")
	}
	if info == nil || info.Provider != input.Provider || strings.TrimSpace(info.ProviderUserID) == "" {
		s.log.Error("provider returned an invalid identity", "provider", input.Provider)
		return nil, domain.NewError("provider_error", "Failed to authenticate with provider")
	}

	existing, lookupErr := s.providerRepo.GetByProvider(ctx, input.Provider, info.ProviderUserID)
	if lookupErr != nil {
		s.log.Error("failed to look up provider account", "err", lookupErr, "provider", input.Provider)
		return nil, domain.ErrInternal
	}

	userID := stateToken.UserID

	if userID != nil {
		if existing != nil {
			if existing.UserID == *userID {
				return nil, domain.NewError("already_linked", "This provider is already linked to your account")
			}
			return nil, domain.ErrProviderAccountExists
		}

		_, linkErr := s.createProviderAccount(ctx, *userID, info)
		if linkErr != nil {
			return nil, linkErr
		}
		s.log.Info("provider linked", "user_id", *userID, "provider", input.Provider)
		if s.audit != nil {
			// attachOAuthLink is a non-transactional helper: the record
			// autocommits. Fail-closed degrades to fail-open here (nothing
			// to roll back), so this cannot fail the link.
			if err := s.audit.Record(ctx, audit.NewOAuthEvent(audit.EventOAuthLinked, *userID, input.Provider, net.ParseIP(input.IP), input.UserAgent)); err != nil {
				s.log.Error("oauth link audit record failed", "err", err, "user_id", *userID)
			}
		}
		return &api.OAuthCallbackResult{IsLink: true}, nil
	}

	if existing != nil {
		user, userErr := s.userRepo.GetByID(ctx, existing.UserID)
		if userErr != nil || user == nil {
			s.log.Error("failed to find linked user", "err", userErr, "user_id", existing.UserID)
			return nil, domain.ErrInternal
		}
		if user.IsBanned {
			return nil, domain.ErrUserBanned
		}

		// Provider verification only proves ownership of the matching address.
		if info.EmailVerified && info.Email == user.Email && !user.IsVerified {
			now := time.Now().UTC()
			updated, err := verifyUserEmail(ctx, s.userRepo, user, info.Email, now)
			if err != nil || !updated {
				s.log.Error("failed to persist provider email verification", "err", err, "user_id", user.ID)
				return nil, domain.ErrInternal
			}
			verified := *user
			verified.IsVerified, verified.VerifiedAt, verified.UpdatedAt = true, &now, now
			user = &verified
		}

		if s.config.RequireEmailVerification && !user.IsVerified {
			if _, err := s.verifySvc.SendVerification(ctx, user); err != nil {
				return nil, err
			}
			return &api.OAuthCallbackResult{RequiresVerification: true, VerifyEmail: user.Email}, nil
		}

		admin, err := appProtectedIdentity(ctx, s.config.AppPermissions, user)
		if err != nil {
			return nil, err
		}
		if admin {
			if s.twoFactorSvc == nil && !s.config.DisableAdminTwoFactor {
				return nil, domain.ErrInternal
			}
			required := false
			if s.twoFactorSvc != nil {
				required, err = s.twoFactorSvc.EnforceContext(ctx, user)
				if err != nil {
					return nil, err
				}
			}
			if required {
				challenge, err := s.twoFactorSvc.Challenge(ctx, user.ID)
				if err != nil {
					return nil, err
				}
				return api.NewOAuthCallbackResult(api.OAuthCallbackResult{
					RequiresTwoFactor: true, CodeSent: challenge.Sent,
					TwoFactorChallenge: challenge.ID, TwoFactorExpiresAt: challenge.ExpiresAt,
				}, challenge.BindingToken), nil
			}
		}

		sessResult, sessionErr := s.sessionSvc.Create(ctx, api.CreateSessionInput{
			UserID:    user.ID,
			IP:        input.IP,
			UserAgent: input.UserAgent,
		})
		if sessionErr != nil {
			s.log.Error("failed to create session", "err", sessionErr, "user_id", user.ID)
			return nil, domain.ErrInternal
		}
		s.log.Info("oauth login", "user_id", user.ID, "provider", input.Provider, "ip", input.IP)
		if s.audit != nil {
			if err := s.audit.Record(ctx, audit.NewOAuthEvent(audit.EventOAuthLogin, user.ID, input.Provider, net.ParseIP(input.IP), input.UserAgent)); err != nil {
				return nil, err
			}
		}
		return &api.OAuthCallbackResult{SessionToken: sessResult.SessionToken, RefreshToken: sessResult.RefreshToken}, nil
	}

	if !s.config.EnableOAuth {
		return nil, domain.ErrMethodDisabled
	}
	if s.config.InviteOnly {
		return nil, domain.ErrForbidden
	}

	if err := validateEmail(info.Email); err != nil {
		return nil, domain.NewError("provider_error", "Failed to authenticate with provider")
	}
	existingUser, userErr := s.userRepo.GetByEmail(ctx, info.Email)
	if userErr != nil {
		return nil, fmt.Errorf("oauth callback: look up email: %w", userErr)
	}
	if existingUser != nil {
		return nil, domain.ErrEmailAlreadyExists
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

	// Create the user and its provider link in one transaction: a
	// provider-account insert failure must not leave a passwordless user
	// row behind that subsequent retries reject as an existing email.
	if err := s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if err := s.userRepo.Create(txCtx, newUser); err != nil {
			if errors.Is(err, port.ErrDuplicateKey) {
				return domain.ErrEmailAlreadyExists
			}
			s.log.Error("failed to create user", "err", err, "email", info.Email)
			return domain.ErrInternal
		}
		if s.config.AppPermissions != nil {
			if err := s.config.AppPermissions.AssignBaseline(txCtx, newUser); err != nil {
				return err
			}
		}
		if _, err := s.createProviderAccount(txCtx, newUser.ID, info); err != nil {
			return err
		}
		// Inside the transaction: the record commits with the account and
		// provider link it describes.
		if s.audit != nil {
			if err := s.audit.Record(txCtx, audit.NewUserRegisteredEvent(newUser.ID, net.ParseIP(input.IP), input.UserAgent)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	s.log.Info("oauth register", "user_id", newUser.ID, "provider", input.Provider, "email_verified", info.EmailVerified)

	// Only send verification email if the provider did NOT verify the email
	// and email verification is required.
	if s.config.RequireEmailVerification && !newUser.IsVerified {
		if _, err := s.verifySvc.SendVerification(ctx, newUser); err != nil {
			return nil, err
		}
		return &api.OAuthCallbackResult{IsNewUser: true, RequiresVerification: true, VerifyEmail: newUser.Email}, nil
	}

	sessResult, sessionErr := s.sessionSvc.Create(ctx, api.CreateSessionInput{
		UserID:    newUser.ID,
		IP:        input.IP,
		UserAgent: input.UserAgent,
	})
	if sessionErr != nil {
		s.log.Error("failed to create session", "err", sessionErr, "user_id", newUser.ID)
		return nil, domain.ErrInternal
	}

	return &api.OAuthCallbackResult{SessionToken: sessResult.SessionToken, RefreshToken: sessResult.RefreshToken, IsNewUser: true}, nil
}

// Unlink removes a linked OAuth provider.
func (s *OAuthService) Unlink(ctx context.Context, input api.OAuthUnlinkInput) error {
	err := s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		// Serialize concurrent unlinks on this user's provider rows before
		// reading them: without the lock, two parallel requests can each
		// observe two linked providers, both pass the guard below, and both
		// delete — leaving a passwordless user with no way to authenticate.
		if err := s.providerRepo.LockByUserID(txCtx, input.UserID); err != nil {
			s.log.Error("failed to lock provider accounts", "err", err, "user_id", input.UserID)
			return domain.ErrInternal
		}

		user, userErr := s.userRepo.GetByID(txCtx, input.UserID)
		if userErr != nil || user == nil {
			return domain.ErrUserNotFound
		}

		accounts, err := s.providerRepo.ListByUserID(txCtx, input.UserID)
		if err != nil {
			s.log.Error("failed to list provider accounts", "err", err, "user_id", input.UserID)
			return domain.ErrInternal
		}

		// Delete removes every identity for this provider. Multiple accounts
		// under the same provider are one removable group, not surviving methods.
		hasRemainingMethod := user.HasPassword()
		for _, account := range accounts {
			if account.Provider != input.Provider {
				hasRemainingMethod = true
				break
			}
		}
		if !hasRemainingMethod {
			return domain.ErrCannotUnlinkLastProvider
		}

		if err := s.providerRepo.Delete(txCtx, input.UserID, input.Provider); err != nil {
			s.log.Error("failed to unlink provider", "err", err, "user_id", input.UserID, "provider", input.Provider)
			return domain.ErrInternal
		}
		// Inside the transaction: the record commits with the unlink it
		// describes.
		if s.audit != nil {
			if err := s.audit.Record(txCtx, audit.NewOAuthEvent(audit.EventOAuthUnlinked, input.UserID, input.Provider, nil, "")); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	s.log.Info("provider unlinked", "user_id", input.UserID, "provider", input.Provider)
	return nil
}

// ListConnected returns a user's linked OAuth providers.
func (s *OAuthService) ListConnected(ctx context.Context, userID string) ([]domain.ProviderAccount, error) {
	accounts, err := s.providerRepo.ListByUserID(ctx, userID)
	if err != nil {
		s.log.Error("failed to list provider accounts", "err", err, "user_id", userID)
		return nil, domain.ErrInternal
	}
	return accounts, nil
}

func (s *OAuthService) createProviderAccount(ctx context.Context, userID string, info *port.OAuthProfile) (*domain.ProviderAccount, error) {
	accessToken := info.AccessToken
	refreshToken := info.RefreshToken
	if s.encryptor != nil {
		if accessToken != "" {
			enc, err := s.encryptor.Encrypt(accessToken)
			if err != nil {
				s.log.Error("failed to encrypt access token", "err", err, "user_id", userID)
				return nil, domain.ErrInternal
			}
			accessToken = enc
		}
		if refreshToken != "" {
			enc, err := s.encryptor.Encrypt(refreshToken)
			if err != nil {
				s.log.Error("failed to encrypt refresh token", "err", err, "user_id", userID)
				return nil, domain.ErrInternal
			}
			refreshToken = enc
		}
	}

	now := time.Now().UTC()
	pa := &domain.ProviderAccount{
		ID:             uuid.New().String(),
		UserID:         userID,
		Provider:       info.Provider,
		ProviderUserID: info.ProviderUserID,
		ProviderEmail:  info.Email,
		ProviderName:   info.Name,
		AvatarURL:      info.AvatarURL,
		AccessToken:    accessToken,
		RefreshToken:   refreshToken,
		TokenExpiresAt: info.TokenExpiresAt,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := s.providerRepo.Create(ctx, pa); err != nil {
		if errors.Is(err, port.ErrDuplicateKey) {
			return nil, domain.ErrProviderAccountExists
		}
		s.log.Error("failed to store provider account", "err", err, "user_id", userID, "provider", info.Provider)
		return nil, domain.ErrInternal
	}
	return pa, nil
}
