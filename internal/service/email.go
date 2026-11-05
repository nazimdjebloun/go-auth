package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/otp"
	"github.com/nazimdjebloun/go-auth/internal/sessioncontext"
	"github.com/nazimdjebloun/go-auth/port"
)

const (
	emailChangeTTL      = 10 * time.Minute
	emailChangeCooldown = time.Minute
	emailChangeAttempts = 5
	emailChangeResends  = 3
	emailChangeStarts   = 3
)

type emailUsers interface {
	GetByID(context.Context, string) (*domain.User, error)
	GetByIDForUpdate(context.Context, string) (*domain.User, error)
}

type emailSessions interface {
	LockByID(context.Context, string) (*domain.Session, error)
	DeleteAllForUser(context.Context, string) error
}

// EmailService changes login/recovery addresses only after dual mailbox proof.
type EmailService struct {
	tx         port.TxManager
	users      emailUsers
	sessions   emailSessions
	store      port.EmailChangeStore
	notices    port.RecoveryEnqueuer
	sessionSvc *SessionService
	twoFactor  *TwoFactorService
	hasher     port.Hasher
	mailer     port.Mailer
	templates  port.TemplateProvider
	config     Config
	now        func() time.Time
	code       func() (string, error)
}

// NewEmailService reuses the credential pipeline, live sessions and durable queue.
func NewEmailService(tx port.TxManager, users emailUsers, sessions emailSessions, store port.EmailChangeStore,
	notices port.RecoveryEnqueuer, sessionSvc *SessionService, twoFactor *TwoFactorService,
	hasher port.Hasher, mailer port.Mailer, config Config) *EmailService {
	requireTxManager(tx)
	return &EmailService{tx: tx, users: users, sessions: sessions, store: store, notices: notices,
		sessionSvc: sessionSvc, twoFactor: twoFactor, hasher: hasher, mailer: mailer,
		templates: resolveTemplates(config.TemplateProvider, config.URLValidator), config: config, now: time.Now,
		code: func() (string, error) { return otp.Generate(8) }}
}

func (s *EmailService) actor(ctx context.Context, actor api.EmailChangeActor) (*domain.User, error) {
	if actor.UserID == "" || actor.SessionID == "" {
		return nil, domain.ErrInvalidCredentials
	}
	u, err := s.users.GetByIDForUpdate(ctx, actor.UserID)
	if err != nil {
		return nil, err
	}
	if err := s.sessionSvc.checkUserAccess(u); err != nil {
		return nil, err
	}
	session, err := s.sessions.LockByID(ctx, actor.SessionID)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, domain.ErrInvalidCredentials
	}
	if err := s.sessionSvc.checkSession(session); err != nil {
		return nil, err
	}
	if session.UserID != u.ID {
		return nil, domain.ErrInvalidCredentials
	}
	required, err := s.twoFactor.EnforceContext(ctx, u)
	if err != nil {
		return nil, err
	}
	if required && (session.TwoFactorVerifiedAt == nil || session.TwoFactorVerifiedAt.IsZero()) {
		return nil, domain.ErrTwoFactorRequired
	}
	return u, nil
}

// identity binds pending requests to password and authentication metadata without
// retaining password verifiers. A credential change invalidates even a kept session.
func (s *EmailService) identity(u *domain.User) string {
	data, _ := json.Marshal(struct {
		Email               string
		Password            *string
		Pepper              *uint32
		Verified, TwoFactor bool
		Role                domain.Role
		AppRole             *string
		Revision            uint64
	}{u.Email, u.PasswordHash, u.PasswordPepperVersion, u.IsVerified, u.TwoFactorEnabled, u.Role, u.AppRoleID, u.AppRoleAssignmentRevision})
	return hashOTP("email-change:identity:"+string(data), s.config.OTPPepper)
}

func emailCodeInput(id, destination, code string) string {
	return "email-change:" + id + ":" + destination + ":" + code
}

func (s *EmailService) run(ctx context.Context, fn func(context.Context) error) error {
	if len(s.config.OTPPepper) == 0 || s.mailer == nil || s.notices == nil {
		return domain.ErrEmailNotConfigured
	}
	err := s.tx.WithTx(ctx, fn)
	if err == nil {
		return nil
	}
	var authErr *domain.AuthError
	if errors.As(err, &authErr) {
		return err
	}
	return fmt.Errorf("email change: %w: %w", domain.ErrInternal, err)
}

// RequestEmailChange sends both proofs after persisting one account-bound lineage.
func (s *EmailService) RequestEmailChange(ctx context.Context, input api.RequestEmailChangeInput) (*api.EmailChangeResult, error) {
	input.NewEmail = strings.ToLower(strings.TrimSpace(input.NewEmail))
	if len(input.NewEmail) > 254 || validateEmail(input.NewEmail) != nil {
		return nil, domain.ErrInvalidEmail
	}
	if input.Actor.UserID == "" || input.Actor.SessionID == "" {
		return nil, domain.ErrInvalidCredentials
	}
	expected, err := s.users.GetByID(ctx, input.Actor.UserID)
	if err != nil {
		return nil, fmt.Errorf("email change lookup: %w: %w", domain.ErrInternal, err)
	}
	if expected == nil {
		return nil, domain.ErrInvalidCredentials
	}
	if expected.HasPassword() && !s.config.PasswordAuthenticationDisabled {
		if err := comparePassword(s.hasher, input.Password, *expected.PasswordHash, expected.PasswordPepperVersion); err != nil {
			return nil, passwordCompareError(err, domain.ErrInvalidCredentials)
		}
	}
	currentCode, err := s.code()
	if err != nil {
		return nil, domain.ErrInternal
	}
	newCode, err := s.differentCode(func(candidate string) bool { return candidate == currentCode })
	if err != nil {
		return nil, domain.ErrInternal
	}
	var request *port.EmailChangeRequest
	err = s.run(ctx, func(ctx context.Context) error {
		u, err := s.actor(ctx, input.Actor)
		if err != nil {
			return err
		}
		if s.identity(u) != s.identity(expected) {
			return domain.ErrInvalidCredentials
		}
		if u.Email == input.NewEmail {
			return domain.ErrEmailChangeUnavailable
		}
		previous, err := s.store.Load(ctx, u.ID)
		if err != nil {
			return err
		}
		now := s.now().UTC().Truncate(time.Microsecond)
		budget, starts := now, 0
		if previous != nil && now.Before(previous.BudgetStartedAt.Add(time.Hour)) {
			budget, starts = previous.BudgetStartedAt, previous.Starts
		}
		if starts >= emailChangeStarts {
			return domain.ErrRateLimitExceeded
		}
		id := generateID()
		request = &port.EmailChangeRequest{UserID: u.ID, ID: id, SessionID: input.Actor.SessionID, Scope: string(sessioncontext.Current(ctx)),
			CurrentEmail: u.Email, NewEmail: input.NewEmail, IdentityHash: s.identity(u), Status: "pending", CreatedAt: now, ExpiresAt: now.Add(emailChangeTTL),
			BudgetStartedAt: budget, Starts: starts + 1, CurrentSentAt: now, NewSentAt: now,
			CurrentCodeHash: hashOTP(emailCodeInput(id, "current", currentCode), s.config.OTPPepper), NewCodeHash: hashOTP(emailCodeInput(id, "new", newCode), s.config.OTPPepper)}
		if err := s.store.Save(ctx, request); err != nil {
			return err
		}
		return s.record(ctx, audit.EventEmailChangeRequested, input.Actor)
	})
	if err != nil {
		return nil, err
	}
	if err := s.deliver(ctx, request, "current", currentCode); err != nil {
		return nil, s.deliveryFailure(ctx, request, err)
	}
	if err := s.deliver(ctx, request, "new", newCode); err != nil {
		return nil, s.deliveryFailure(ctx, request, err)
	}
	return &api.EmailChangeResult{RequestID: request.ID, ExpiresAt: request.ExpiresAt}, nil
}

func (s *EmailService) pending(ctx context.Context, actor api.EmailChangeActor, requestID string) (*port.EmailChangeRequest, error) {
	u, err := s.actor(ctx, actor)
	if err != nil {
		return nil, err
	}
	v, err := s.store.Load(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	if v == nil || v.ID != requestID || v.Status != "pending" || v.SessionID != actor.SessionID || v.Scope != string(sessioncontext.Current(ctx)) || v.CurrentEmail != u.Email || v.IdentityHash != s.identity(u) {
		return nil, domain.ErrEmailChangeInvalid
	}
	if !s.now().UTC().Before(v.ExpiresAt) || stalePepper(v.CreatedAt, s.config.SecretRotatedAt) {
		return nil, domain.ErrEmailChangeExpired
	}
	if v.Attempts >= emailChangeAttempts {
		return nil, domain.ErrEmailChangeInvalid
	}
	return v, nil
}

// ConfirmEmailChange commits both proofs, the address and all revocations together.
func (s *EmailService) ConfirmEmailChange(ctx context.Context, input api.ConfirmEmailChangeInput) error {
	var proofErr error
	err := s.run(ctx, func(ctx context.Context) error {
		v, err := s.pending(ctx, input.Actor, input.RequestID)
		if err != nil {
			return err
		}
		currentOK := verifyOTP(emailCodeInput(v.ID, "current", input.CurrentEmailCode), v.CurrentCodeHash, s.config.OTPPepper)
		newOK := verifyOTP(emailCodeInput(v.ID, "new", input.NewEmailCode), v.NewCodeHash, s.config.OTPPepper)
		if !currentOK || !newOK {
			v.Attempts++
			if v.Attempts >= emailChangeAttempts {
				v.CurrentCodeHash, v.NewCodeHash = "", ""
			}
			if err := s.store.Save(ctx, v); err != nil {
				return err
			}
			proofErr = domain.ErrEmailChangeInvalid
			return nil // Commit the failed guess, not the API error.
		}
		now := s.now().UTC()
		if !now.Before(v.ExpiresAt) {
			return domain.ErrEmailChangeExpired
		}
		changed, err := s.store.ChangeAddress(ctx, v.UserID, v.CurrentEmail, v.NewEmail, now)
		if errors.Is(err, port.ErrDuplicateKey) {
			return domain.ErrEmailChangeUnavailable
		}
		if err != nil {
			return err
		}
		if !changed {
			return domain.ErrEmailChangeInvalid
		}
		v.Status, v.CurrentCodeHash, v.NewCodeHash = "used", "", ""
		if err := s.store.Save(ctx, v); err != nil {
			return err
		}
		if err := s.sessions.DeleteAllForUser(ctx, v.UserID); err != nil {
			return err
		}
		if err := s.store.InvalidateCredentials(ctx, v.UserID); err != nil {
			return err
		}
		for _, email := range []string{v.CurrentEmail, v.NewEmail} {
			if err := s.notices.Enqueue(ctx, port.RecoveryEmailChanged, email); err != nil {
				return err
			}
		}
		return s.record(ctx, audit.EventEmailChanged, input.Actor)
	})
	if err != nil {
		return err
	}
	return proofErr
}

// ResendEmailChange preserves the lifetime and total failed-guess budget.
func (s *EmailService) ResendEmailChange(ctx context.Context, input api.ResendEmailChangeInput) (*api.EmailChangeResult, error) {
	if input.Destination != "current" && input.Destination != "new" {
		return nil, domain.ErrEmailChangeInvalid
	}
	code, err := s.code()
	if err != nil {
		return nil, domain.ErrInternal
	}
	var v *port.EmailChangeRequest
	err = s.run(ctx, func(ctx context.Context) error {
		var err error
		v, err = s.pending(ctx, input.Actor, input.RequestID)
		if err != nil {
			return err
		}
		sent, resends := &v.CurrentSentAt, &v.CurrentResends
		hash := &v.CurrentCodeHash
		if input.Destination == "new" {
			sent, resends, hash = &v.NewSentAt, &v.NewResends, &v.NewCodeHash
		}
		now := s.now().UTC()
		if *resends >= emailChangeResends || now.Before(sent.Add(emailChangeCooldown)) {
			return domain.ErrRateLimitExceeded
		}
		otherDestination, otherHash := "new", v.NewCodeHash
		if input.Destination == "new" {
			otherDestination, otherHash = "current", v.CurrentCodeHash
		}
		collides := func(candidate string) bool {
			return verifyOTP(emailCodeInput(v.ID, input.Destination, candidate), *hash, s.config.OTPPepper) ||
				verifyOTP(emailCodeInput(v.ID, otherDestination, candidate), otherHash, s.config.OTPPepper)
		}
		if collides(code) {
			code, err = s.differentCode(collides)
			if err != nil {
				return err
			}
		}
		*sent = now
		*resends += 1
		*hash = hashOTP(emailCodeInput(v.ID, input.Destination, code), s.config.OTPPepper)
		return s.store.Save(ctx, v)
	})
	if err != nil {
		return nil, err
	}
	if err := s.deliver(ctx, v, input.Destination, code); err != nil {
		return nil, s.deliveryFailure(ctx, v, err)
	}
	return &api.EmailChangeResult{RequestID: v.ID, ExpiresAt: v.ExpiresAt}, nil
}

// A coincidentally equal pair would reduce dual-mailbox proof to one code.
// Likewise a resend must actually replace its previous code. Bound retries so
// even a broken random source fails closed rather than holding locks forever.
func (s *EmailService) differentCode(reject func(string) bool) (string, error) {
	for range 16 {
		code, err := s.code()
		if err != nil {
			return "", domain.ErrInternal
		}
		if !reject(code) {
			return code, nil
		}
	}
	return "", domain.ErrInternal
}

// CancelEmailChange cancels a lineage without resetting its start budget.
func (s *EmailService) CancelEmailChange(ctx context.Context, input api.CancelEmailChangeInput) error {
	return s.run(ctx, func(ctx context.Context) error {
		// Cancellation remains available after expiry or attempt exhaustion.
		if _, err := s.actor(ctx, input.Actor); err != nil {
			return err
		}
		v, err := s.store.Load(ctx, input.Actor.UserID)
		if err != nil {
			return err
		}
		if v == nil || v.ID != input.RequestID || v.SessionID != input.Actor.SessionID || v.Scope != string(sessioncontext.Current(ctx)) || v.Status != "pending" {
			return domain.ErrEmailChangeInvalid
		}
		v.Status, v.CurrentCodeHash, v.NewCodeHash = "cancelled", "", ""
		return s.store.Save(ctx, v)
	})
}

func (s *EmailService) deliver(ctx context.Context, v *port.EmailChangeRequest, destination, code string) error {
	email := v.CurrentEmail
	if destination == "new" {
		email = v.NewEmail
	}
	message, err := s.templates.Render(port.EmailChangeData{AppName: s.config.AppName, Code: code, NewEmail: v.NewEmail, Destination: destination, ExpiresIn: v.ExpiresAt.Sub(s.now())})
	if err != nil {
		return err
	}
	deliveryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.mailer.Send(deliveryCtx, email, message.Subject, message.HTML, message.Text)
}

func (s *EmailService) deliveryFailure(ctx context.Context, v *port.EmailChangeRequest, cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := s.store.DiscardVersion(cleanupCtx, v); err != nil {
		return fmt.Errorf("email change delivery cleanup: %w: %w", domain.ErrInternal, errors.Join(cause, err))
	}
	return fmt.Errorf("email change delivery: %w: %w", domain.ErrEmailFailed, cause)
}

func (s *EmailService) record(ctx context.Context, kind audit.EventType, actor api.EmailChangeActor) error {
	if s.config.Audit == nil {
		return nil
	}
	e := audit.NewEvent(kind, audit.WithActor(actor.UserID), audit.WithSession(actor.SessionID))
	e.Success = true
	return s.config.Audit.Record(ctx, e)
}
