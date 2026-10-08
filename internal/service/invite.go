package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// InviteService manages account invitations.
type InviteService struct {
	users        port.UserRepository
	sessions     port.SessionRepository
	invites      port.InviteRepository
	hasher       port.Hasher
	gen          port.TokenGenerator
	mailer       port.Mailer
	txManager    port.TxManager
	templates    port.TemplateProvider
	config       Config
	sessionSvc   *SessionService
	twoFactorSvc *TwoFactorService
	log          *slog.Logger
	audit        AuditPublisher
}

// NewInviteService returns an account invitation service.
func NewInviteService(
	users port.UserRepository,
	sessions port.SessionRepository,
	invites port.InviteRepository,
	hasher port.Hasher,
	gen port.TokenGenerator,
	mailer port.Mailer,
	txManager port.TxManager,
	config Config,
	sessionSvc *SessionService,
	twoFactorSvc *TwoFactorService,
) *InviteService {
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	return &InviteService{
		users:        users,
		sessions:     sessions,
		invites:      invites,
		hasher:       hasher,
		gen:          gen,
		mailer:       mailer,
		txManager:    txManager,
		templates:    resolveTemplates(config.TemplateProvider, config.URLValidator),
		config:       config,
		sessionSvc:   sessionSvc,
		twoFactorSvc: twoFactorSvc,
		log:          config.Logger,
		audit:        config.Audit,
	}
}

// GetInviteByToken returns a valid account invitation by token.
func (s *InviteService) GetInviteByToken(ctx context.Context, rawToken string) (*domain.Invite, error) {
	invite, err := s.invites.GetByCode(ctx, hashToken(rawToken))
	if err != nil {
		return nil, fmt.Errorf("get invite by token: lookup: %w", err)
	}
	if invite == nil {
		return nil, domain.ErrInviteNotFound
	}

	if invite.Status != domain.InvitePending {
		if invite.Status == domain.InviteAccepted {
			return nil, domain.ErrInviteAlreadyUsed
		}
		if invite.Status == domain.InviteRevoked {
			return nil, domain.ErrInviteRevoked
		}
		return nil, domain.ErrInviteNotFound
	}

	if time.Now().UTC().After(invite.ExpiresAt) {
		// Read-only classification: persisting an old snapshot here could
		// overwrite a concurrent revocation, acceptance, or code rotation.
		return nil, domain.ErrInviteExpired
	}

	return invite, nil
}

// CreateInvite creates an account invitation.
func (s *InviteService) CreateInvite(ctx context.Context, input api.CreateInviteInput) (*domain.Invite, error) {

	if err := s.requireOperation(ctx, input.AdminID, input.ActorSessionID, "goauth.app.invites.create"); err != nil {
		return nil, err
	}
	if !s.config.EnableInvite {
		return nil, domain.ErrMethodDisabled
	}
	input.Email = strings.TrimSpace(strings.ToLower(input.Email))
	if err := validateEmail(input.Email); err != nil {
		return nil, err
	}

	// Inviting someone who already has an account produces a link they can
	// never redeem, so reject it up front rather than emailing a dead end.
	existingUser, err := s.users.GetByEmail(ctx, input.Email)
	if err != nil {
		s.log.Error("failed to look up user by email", "err", err, "email", input.Email)
		return nil, domain.ErrInternal
	}
	if existingUser != nil {
		return nil, domain.ErrEmailAlreadyExists
	}

	// One live invite per address. Without this a re-pasted list in a bulk
	// send silently stacks duplicate rows for the same person.
	if prev, err := s.invites.GetByEmail(ctx, input.Email); err != nil {
		s.log.Error("failed to look up invite by email", "err", err, "email", input.Email)
		return nil, domain.ErrInternal
	} else if prev != nil && prev.Status == domain.InvitePending &&
		time.Now().UTC().Before(prev.ExpiresAt) {
		return nil, domain.ErrInviteAlreadyExists
	}

	if s.mailer == nil {
		return nil, domain.ErrEmailNotConfigured
	}

	raw, genErr := s.gen.Generate()
	if genErr != nil {
		s.log.Error("failed to generate invite code", "err", genErr, "email", input.Email)
		return nil, domain.ErrInternal
	}

	now := time.Now().UTC()
	invite := &domain.Invite{
		ID:        generateID(),
		Email:     input.Email,
		Code:      hashToken(raw),
		RawCode:   raw,
		Status:    domain.InvitePending,
		CreatedBy: input.AdminID,
		CreatedAt: now,
		ExpiresAt: now.Add(s.config.InviteTTL),
	}

	create := func(ctx context.Context) error {
		if err := s.invites.Create(ctx, invite); err != nil {
			return err
		}
		if s.config.AppPermissions != nil && s.audit != nil {
			return s.audit.Record(ctx, audit.NewInviteEvent(audit.EventAdminInviteCreated, input.AdminID, invite.ID, invite.Email))
		}
		return nil
	}
	if s.config.AppPermissions != nil {
		original := create
		create = func(ctx context.Context) error {
			return s.config.AppPermissions.withMutation(ctx, appActor(input.AdminID, input.ActorSessionID), "goauth.app.invites.create", original)
		}
	}
	if err := create(ctx); err != nil {
		var authErr *domain.AuthError
		if errors.As(err, &authErr) {
			return nil, err
		}
		s.log.Error("failed to create invite", "err", err, "email", input.Email)
		return nil, domain.ErrInternal
	}

	inviteURL := s.config.BaseURL + "/invite?token=" + raw
	result, tplErr := s.templates.Render(port.InviteData{
		AppName:   s.config.AppName,
		InviteURL: inviteURL,
		ExpiresIn: s.config.InviteTTL,
	})
	if tplErr != nil {
		s.log.Error("failed to render invite email template", "err", tplErr, "email", input.Email)
		return nil, domain.ErrInternal
	}
	if err := s.mailer.Send(ctx, invite.Email, result.Subject, result.HTML, result.Text); err != nil {
		s.log.Error("failed to send invite email", "err", err, "email", input.Email)
		return nil, domain.ErrInviteEmailFailed
	}

	invite.RawCode = ""

	if s.audit != nil && s.config.AppPermissions == nil {
		if err := s.audit.Record(ctx, audit.NewInviteEvent(audit.EventAdminInviteCreated, input.AdminID, invite.ID, invite.Email)); err != nil {
			return nil, err
		}
	}

	s.log.Info("invite created", "invite_id", invite.ID, "email", input.Email, "admin_id", input.AdminID)
	return invite, nil
}

// CompleteInviteRegistration registers a user from an invitation.
func (s *InviteService) CompleteInviteRegistration(ctx context.Context, input api.CompleteInviteInput) (*api.CompleteInviteResult, error) {
	if !s.config.EnableInvite {
		return nil, domain.ErrMethodDisabled
	}
	invite, err := s.invites.GetByCode(ctx, hashToken(input.Code))
	if err != nil {
		return nil, fmt.Errorf("complete invite registration: lookup: %w", err)
	}
	if invite == nil {
		return nil, domain.ErrInviteNotFound
	}

	if invite.Status != domain.InvitePending {
		return nil, domain.ErrInviteAlreadyUsed
	}

	if time.Now().UTC().After(invite.ExpiresAt) {
		return nil, domain.ErrInviteExpired
	}

	if strings.TrimSpace(input.Name) == "" {
		return nil, domain.ErrNameRequired
	}
	input.Name = strings.TrimSpace(input.Name)

	if input.Password != input.ConfirmPassword {
		return nil, domain.NewError("password_mismatch", "Passwords do not match")
	}

	if err := s.config.PasswordPolicy.Validate(input.Password); err != nil {
		return nil, err
	}

	hash, pepperVersion, err := hashPassword(s.hasher, input.Password)
	if err != nil {
		s.log.Error("failed to hash password", "err", err, "invite_id", invite.ID)
		return nil, domain.ErrInternal
	}

	now := time.Now().UTC()
	// Invite registration is an email/password registration, so it seeds and
	// gates exactly like Register. Skipping the seed would leave every invited
	// user with 2FA off in a default-on deployment.
	user := &domain.User{
		ID:                    generateID(),
		Email:                 invite.Email,
		PasswordHash:          &hash,
		PasswordPepperVersion: pepperVersion,
		Name:                  input.Name,
		Role:                  domain.RoleUser,
		IsVerified:            true,
		TwoFactorEnabled:      s.config.DefaultTwoFactorEnabled,
		CreatedAt:             now,
		UpdatedAt:             now,
	}

	createAccount := func(txCtx context.Context) error {
		if err := s.users.Create(txCtx, user); err != nil {
			if errors.Is(err, port.ErrDuplicateKey) {
				return domain.ErrEmailAlreadyExists
			}
			return err
		}
		return nil
	}
	// Enabled mode inserts before locking the invite or role, matching the user
	// order of administrative mutations. Any failed claim/assignment rolls back
	// the provisional account. Disabled mode retains the existing claim order.
	err = s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if s.config.AppPermissions != nil {
			if err := createAccount(txCtx); err != nil {
				return err
			}
		}
		claimed, err := s.invites.ClaimInvite(txCtx, invite.Code, time.Now().UTC())
		if err != nil {
			return err
		}
		if !claimed {
			// Lost the race: accepted, revoked, or expired between the
			// lookup above and this claim. A revoked invite redeems as
			// invite_already_used by convention, not invite_revoked.
			return domain.ErrInviteAlreadyUsed
		}
		if s.config.AppPermissions != nil {
			if err := s.config.AppPermissions.AssignBaseline(txCtx, user); err != nil {
				return err
			}
		} else if err := createAccount(txCtx); err != nil {
			return err
		}
		// Inside the transaction: the record commits with the account it
		// describes. The claim-and-create pair is already atomic; the audit
		// record joins it rather than trailing it.
		if s.audit != nil {
			if err := s.audit.Record(txCtx, audit.NewUserRegisteredEvent(user.ID, nil, "")); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		if s.config.AppPermissions != nil && errors.Is(err, domain.ErrEmailAlreadyExists) {
			// Another redemption may win the email insert before this transaction
			// reaches its claim. After rollback, preserve invite_already_used for
			// a consumed/rotated invitation, and email_already_exists otherwise.
			current, lookupErr := s.invites.GetByID(ctx, invite.ID)
			if lookupErr != nil {
				return nil, fmt.Errorf("complete invite registration: recheck after duplicate: %w", lookupErr)
			}
			if current == nil {
				return nil, domain.ErrInviteAlreadyUsed
			}
			consumedOrRotated := current.Status != domain.InvitePending || current.Code != invite.Code
			if consumedOrRotated || !current.ExpiresAt.After(time.Now().UTC()) {
				return nil, domain.ErrInviteAlreadyUsed
			}
		}
		var authErr *domain.AuthError
		if errors.As(err, &authErr) {
			return nil, err
		}
		s.log.Error("failed to create user from invite", "err", err, "email", invite.Email)
		return nil, domain.ErrInternal
	}

	// Same rationale as Register: gate on the global flag only, not the
	// effective check — a code mailed to the address that just accepted the
	// invite proves nothing here. The invite is already claimed above, so a
	// gated response does not strand it.
	if s.config.RequireEmail2FA && s.twoFactorSvc != nil {
		challenge, aerr := s.twoFactorSvc.challengeWithPassword(ctx, user)
		if aerr != nil {
			return nil, aerr
		}
		s.log.Info("invite registered, two-factor required", "user_id", user.ID, "invite_id", invite.ID)
		return api.NewCompleteInviteResult(api.CompleteInviteResult{
			User:               user,
			RequiresTwoFactor:  true,
			CodeSent:           challenge.Sent,
			TwoFactorChallenge: challenge.ID,
			TwoFactorExpiresAt: challenge.ExpiresAt,
		}, challenge.BindingToken), nil
	}

	var sessResult *api.SessionResult
	err = s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if _, err := lockPasswordIdentity(txCtx, s.users, user); err != nil {
			return err
		}
		var err error
		sessResult, err = s.sessionSvc.Create(txCtx, api.CreateSessionInput{
			UserID:    user.ID,
			IP:        input.IP,
			UserAgent: input.UserAgent,
		})
		return err
	})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) || errors.Is(err, domain.ErrUserBanned) {
			return nil, err
		}
		s.log.Error("failed to create session", "err", err, "user_id", user.ID)
		return nil, domain.ErrInternal
	}

	s.log.Info("invite registered", "user_id", user.ID, "email", user.Email, "invite_id", invite.ID)

	return &api.CompleteInviteResult{
		User:         user,
		Session:      sessResult.Session,
		SessionToken: sessResult.SessionToken,
		RefreshToken: sessResult.RefreshToken,
	}, nil
}

func inviteFilterFromInput(input api.ListInvitesInput) port.InviteFilter {
	var search *string
	if input.Search != "" {
		search = &input.Search
	}
	var status *string
	if input.Status != "" {
		status = &input.Status
	}
	return port.InviteFilter{
		Offset:         input.Offset,
		Limit:          input.Limit,
		Search:         search,
		Status:         status,
		OrderBy:        input.OrderBy,
		OrderDirection: input.OrderDirection,
	}
}

// ListInvites returns account invitations.
func (s *InviteService) ListInvites(ctx context.Context, input api.ListInvitesInput) ([]domain.Invite, error) {
	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.invites.read"); err != nil {
		return nil, err
	}
	invites, err := s.invites.List(ctx, inviteFilterFromInput(input))
	if err != nil {
		s.log.Error("failed to list invites", "err", err)
		return nil, domain.ErrInternal
	}
	return invites, nil
}

// CountInvites returns how many invites match the input's filters (pagination
// ignored).
func (s *InviteService) CountInvites(ctx context.Context, input api.ListInvitesInput) (int, error) {
	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.invites.read"); err != nil {
		return 0, err
	}
	n, err := s.invites.Count(ctx, inviteFilterFromInput(input))
	if err != nil {
		s.log.Error("failed to count invites", "err", err)
		return 0, domain.ErrInternal
	}
	return n, nil
}

// HardDeleteInvite permanently deletes an account invitation.
func (s *InviteService) HardDeleteInvite(ctx context.Context, input api.HardDeleteInviteInput) error {
	if s.config.AppPermissions != nil && ctx.Value(appManagementContextKey{}) == nil {
		return runAppMutationVoid(ctx, s.config.AppPermissions, appActor(input.ActorID, input.ActorSessionID), "goauth.app.invites.delete", func(txCtx context.Context) error { return s.HardDeleteInvite(txCtx, input) })
	}

	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.invites.delete"); err != nil {
		return err
	}
	// Read before deleting: the audit event names the recipient, and after the
	// delete there is no row left to read it from.
	invite, err := s.invites.GetByID(ctx, input.InviteID)
	if err != nil {
		return fmt.Errorf("hard delete invite: lookup: %w", err)
	}
	if invite == nil {
		return domain.ErrInviteNotFound
	}
	if err := s.invites.Delete(ctx, input.InviteID); err != nil {
		s.log.Error("failed to delete invite", "err", err, "invite_id", input.InviteID)
		return domain.ErrInternal
	}

	if s.audit != nil {
		if err := s.audit.Record(ctx, audit.NewInviteEvent(audit.EventAdminInviteDeleted, input.ActorID, invite.ID, invite.Email)); err != nil {
			return err
		}
	}

	s.log.Info("invite deleted", "invite_id", input.InviteID)
	return nil
}

// RevokeInvite revokes an account invitation.
func (s *InviteService) RevokeInvite(ctx context.Context, input api.RevokeInviteInput) error {
	if s.config.AppPermissions != nil && ctx.Value(appManagementContextKey{}) == nil {
		return runAppMutationVoid(ctx, s.config.AppPermissions, appActor(input.ActorID, input.ActorSessionID), "goauth.app.invites.revoke", func(txCtx context.Context) error { return s.RevokeInvite(txCtx, input) })
	}

	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.invites.revoke"); err != nil {
		return err
	}
	invite, err := s.invites.GetByID(ctx, input.InviteID)
	if err != nil {
		return fmt.Errorf("revoke invite: lookup: %w", err)
	}
	if invite == nil {
		return domain.ErrInviteNotFound
	}

	if invite.Status == domain.InviteRevoked {
		return nil
	}
	if err := s.txManager.WithTx(ctx, func(txCtx context.Context) error {
		changed, err := s.invites.Revoke(txCtx, input.InviteID)
		if err != nil {
			return err
		}
		if !changed {
			return domain.ErrInviteAlreadyUsed
		}
		if s.audit != nil {
			return s.audit.Record(txCtx, audit.NewInviteEvent(audit.EventAdminInviteRevoked, input.ActorID, invite.ID, invite.Email))
		}
		return nil
	}); err != nil {
		if _, ok := errors.AsType[*domain.AuthError](err); ok {
			return err
		}
		s.log.Error("failed to revoke invite", "err", err, "invite_id", input.InviteID)
		return domain.ErrInternal
	}

	s.log.Info("invite revoked", "invite_id", input.InviteID)
	return nil
}

// ResendInviteEmail sends an account invitation again.
func (s *InviteService) ResendInviteEmail(ctx context.Context, input api.ResendInviteEmailInput) error {

	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.invites.resend"); err != nil {
		return err
	}
	invite, err := s.invites.GetByID(ctx, input.InviteID)
	if err != nil {
		return fmt.Errorf("resend invite email: lookup: %w", err)
	}
	if invite == nil {
		return domain.ErrInviteNotFound
	}
	snapshot := *invite
	invite = &snapshot
	if invite.Status != domain.InvitePending && invite.Status != domain.InviteExpired {
		return domain.ErrInviteAlreadyUsed
	}

	if s.mailer == nil {
		return domain.ErrEmailNotConfigured
	}

	raw, err := s.gen.Generate()
	if err != nil {
		s.log.Error("failed to generate invite code", "err", err, "invite_id", input.InviteID)
		return domain.ErrInternal
	}

	var changed bool
	rotate := func(ctx context.Context) error {
		var err error
		changed, err = s.invites.RotateCode(ctx, invite.ID, invite.Code, hashToken(raw), time.Now().UTC().Add(s.config.InviteTTL))
		if err != nil {
			return err
		}
		if !changed {
			return domain.ErrInviteAlreadyUsed
		}
		if s.config.AppPermissions != nil && s.audit != nil {
			return s.audit.Record(ctx, audit.NewInviteEvent(audit.EventAdminInviteResent, input.ActorID, invite.ID, invite.Email))
		}
		return nil
	}
	if s.config.AppPermissions != nil {
		original := rotate
		rotate = func(ctx context.Context) error {
			return s.config.AppPermissions.withMutation(ctx, appActor(input.ActorID, input.ActorSessionID), "goauth.app.invites.resend", original)
		}
	}
	err = rotate(ctx)
	if err != nil {
		var authErr *domain.AuthError
		if errors.As(err, &authErr) {
			return err
		}
		s.log.Error("failed to update invite", "err", err, "invite_id", input.InviteID)
		return domain.ErrInternal
	}
	if !changed {
		return domain.ErrInviteAlreadyUsed
	}

	url := s.config.BaseURL + "/invite?token=" + raw
	result, tplErr := s.templates.Render(port.InviteData{
		AppName:   s.config.AppName,
		InviteURL: url,
		ExpiresIn: s.config.InviteTTL,
	})
	if tplErr != nil {
		s.log.Error("failed to render invite email template", "err", tplErr, "invite_id", input.InviteID)
		return domain.ErrInternal
	}
	if err := s.mailer.Send(ctx, invite.Email, result.Subject, result.HTML, result.Text); err != nil {
		s.log.Error("failed to send invite email", "err", err, "invite_id", input.InviteID)
		return domain.ErrInviteEmailFailed
	}

	if s.audit != nil && s.config.AppPermissions == nil {
		if err := s.audit.Record(ctx, audit.NewInviteEvent(audit.EventAdminInviteResent, input.ActorID, invite.ID, invite.Email)); err != nil {
			return err
		}
	}

	s.log.Info("invite resent", "invite_id", input.InviteID, "email", invite.Email)
	return nil
}

// ─── Bulk invite actions ───────────────────────────────────────────────
//
// Same partial-failure contract as the bulk user actions in admin.go: the
// request is not transactional, so the caller must read both lists.
//
// The caps differ by cost. Revoke and delete are pure DB writes and take the
// same 100 as the user actions. Send and resend each make an SMTP round-trip,
// so they cap lower and fan out across a small pool — 25 sequential sends at
// ~1s each would blow any proxy timeout, while 25 across 8 workers lands in a
// few seconds. Past 25, the caller chunks.
const (
	maxBulkInviteIDs    = 100
	maxBulkInviteEmails = 25
	bulkEmailWorkers    = 8
	// Per-send ceiling so one hung SMTP connection can't stall the batch.
	bulkEmailSendTimeout = 10 * time.Second
)

func inviteFailure(id, email string, err error) api.BulkInviteFailure {
	f := api.BulkInviteFailure{InviteID: id, Email: email, Code: "internal_error", Message: "Something went wrong"}
	var ae *domain.AuthError
	if errors.As(err, &ae) {
		f.Code, f.Message = ae.Code, ae.Message
	}
	return f
}

func validateBulkIDs(ids []string) error {
	if len(ids) == 0 {
		return domain.ErrInviteIDsRequired
	}
	if len(ids) > maxBulkInviteIDs {
		return domain.NewError("invalid_input", fmt.Sprintf("at most %d inviteIds per bulk request", maxBulkInviteIDs))
	}
	return nil
}

// BulkRevokeInvites revokes each invite, reporting per-invite outcome.
func (s *InviteService) BulkRevokeInvites(ctx context.Context, input api.BulkInviteIDsInput) (*api.BulkInviteResult, error) {
	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.invites.revoke"); err != nil {
		return nil, err
	}
	if err := validateBulkIDs(input.InviteIDs); err != nil {
		return nil, err
	}
	result := &api.BulkInviteResult{Succeeded: []string{}, Failed: []api.BulkInviteFailure{}}
	for _, id := range input.InviteIDs {
		if err := s.RevokeInvite(ctx, api.RevokeInviteInput{
			InviteID:       id,
			ActorID:        input.ActorID,
			ActorSessionID: input.ActorSessionID,
		}); err != nil {
			result.Failed = append(result.Failed, inviteFailure(id, "", err))
			continue
		}
		result.Succeeded = append(result.Succeeded, id)
	}
	return result, nil
}

// BulkDeleteInvites deletes each invite outright. It does not revoke first:
// the row is gone either way, and the audit trail lives in the audit log, not
// in a status on a deleted row.
func (s *InviteService) BulkDeleteInvites(ctx context.Context, input api.BulkInviteIDsInput) (*api.BulkInviteResult, error) {
	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.invites.delete"); err != nil {
		return nil, err
	}
	if err := validateBulkIDs(input.InviteIDs); err != nil {
		return nil, err
	}
	result := &api.BulkInviteResult{Succeeded: []string{}, Failed: []api.BulkInviteFailure{}}
	for _, id := range input.InviteIDs {
		if err := s.HardDeleteInvite(ctx, api.HardDeleteInviteInput{
			InviteID:       id,
			ActorID:        input.ActorID,
			ActorSessionID: input.ActorSessionID,
		}); err != nil {
			result.Failed = append(result.Failed, inviteFailure(id, "", err))
			continue
		}
		result.Succeeded = append(result.Succeeded, id)
	}
	return result, nil
}

// runBulkEmail fans `items` across a small worker pool, collecting each
// outcome. Order of the result slices follows completion, not input.
func runBulkEmail(ctx context.Context, items []string, work func(context.Context, string) error) *api.BulkInviteResult {
	type outcome struct {
		item string
		err  error
	}
	results := make(chan outcome, len(items))
	sem := make(chan struct{}, bulkEmailWorkers)
	var wg sync.WaitGroup

	for _, item := range items {
		wg.Add(1)
		go func(item string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			sendCtx, cancel := context.WithTimeout(ctx, bulkEmailSendTimeout)
			defer cancel()
			results <- outcome{item: item, err: work(sendCtx, item)}
		}(item)
	}
	wg.Wait()
	close(results)

	out := &api.BulkInviteResult{Succeeded: []string{}, Failed: []api.BulkInviteFailure{}}
	for r := range results {
		if r.err != nil {
			out.Failed = append(out.Failed, inviteFailure("", r.item, r.err))
			continue
		}
		out.Succeeded = append(out.Succeeded, r.item)
	}
	return out
}

// BulkSendInvites creates and emails one invite per address. Addresses that
// already have an account, or already have a live invite, come back in Failed
// with the same codes a single CreateInvite would have returned.
func (s *InviteService) BulkSendInvites(ctx context.Context, input api.BulkInviteEmailsInput) (*api.BulkInviteResult, error) {
	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.invites.create"); err != nil {
		return nil, err
	}
	if len(input.Emails) == 0 {
		return nil, domain.NewError("invalid_input", "emails must not be empty")
	}
	if len(input.Emails) > maxBulkInviteEmails {
		return nil, domain.NewError("invalid_input", fmt.Sprintf("at most %d emails per bulk request", maxBulkInviteEmails))
	}
	return runBulkEmail(ctx, input.Emails, func(c context.Context, email string) error {
		_, err := s.CreateInvite(c, api.CreateInviteInput{Email: email, AdminID: input.ActorID, ActorSessionID: input.ActorSessionID})
		return err
	}), nil
}

// BulkResendInvites rotates the code and re-sends each invite's email. Keyed
// by invite ID, but capped and fanned out like a send because it is one SMTP
// round-trip per item.
func (s *InviteService) BulkResendInvites(ctx context.Context, input api.BulkInviteIDsInput) (*api.BulkInviteResult, error) {
	if err := s.requireOperation(ctx, input.ActorID, input.ActorSessionID, "goauth.app.invites.resend"); err != nil {
		return nil, err
	}
	if len(input.InviteIDs) == 0 {
		return nil, domain.ErrInviteIDsRequired
	}
	if len(input.InviteIDs) > maxBulkInviteEmails {
		return nil, domain.NewError("invalid_input", fmt.Sprintf("at most %d inviteIds per bulk resend", maxBulkInviteEmails))
	}
	out := runBulkEmail(ctx, input.InviteIDs, func(c context.Context, id string) error {
		return s.ResendInviteEmail(c, api.ResendInviteEmailInput{
			InviteID:       id,
			ActorID:        input.ActorID,
			ActorSessionID: input.ActorSessionID,
		})
	})
	// keyed by ID here, not email
	for i := range out.Failed {
		out.Failed[i].InviteID, out.Failed[i].Email = out.Failed[i].Email, ""
	}
	return out, nil
}
