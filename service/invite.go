package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

type InviteService struct {
	users        port.UserRepository
	sessions     port.SessionRepository
	invites      port.InviteRepository
	hasher       port.Hasher
	gen          port.TokenGenerator
	mailer       port.Mailer
	templates    port.TemplateProvider
	config       Config
	sessionSvc   *SessionService
	twoFactorSvc *TwoFactorService
	log          *slog.Logger
	audit        AuditPublisher
}

func NewInviteService(
	users port.UserRepository,
	sessions port.SessionRepository,
	invites port.InviteRepository,
	hasher port.Hasher,
	gen port.TokenGenerator,
	mailer port.Mailer,
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
		templates:    resolveTemplates(config.TemplateProvider, config.URLValidator),
		config:       config,
		sessionSvc:   sessionSvc,
		twoFactorSvc: twoFactorSvc,
		log:          config.Logger,
		audit:        config.Audit,
	}
}

func (s *InviteService) GetInviteByToken(ctx context.Context, rawToken string) (*domain.Invite, error) {
	invite, err := s.invites.GetByCode(ctx, hashToken(rawToken))
	if err != nil || invite == nil {
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
		invite.Status = domain.InviteExpired
		s.invites.Update(ctx, invite)
		return nil, domain.ErrInviteExpired
	}

	return invite, nil
}

func (s *InviteService) CreateInvite(ctx context.Context, input CreateInviteInput) (*domain.Invite, error) {
	if err := requireAdminRole(ctx, s.users, input.AdminID); err != nil {
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
		return nil, domain.NewError("email_not_configured", "Email sender is not configured")
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

	if err := s.invites.Create(ctx, invite); err != nil {
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
		return nil, domain.NewError("email_failed", "Failed to send invite email")
	}

	invite.RawCode = ""

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewInviteEvent(
			audit.EventAdminInviteCreated, input.AdminID, invite.ID, invite.Email))
	}

	s.log.Info("invite created", "invite_id", invite.ID, "email", input.Email, "admin_id", input.AdminID)
	return invite, nil
}

func (s *InviteService) CompleteInviteRegistration(ctx context.Context, input CompleteInviteInput) (*CompleteInviteResult, error) {
	if !s.config.EnableInvite {
		return nil, domain.ErrMethodDisabled
	}
	invite, err := s.invites.GetByCode(ctx, hashToken(input.Code))
	if err != nil || invite == nil {
		return nil, domain.ErrInviteNotFound
	}

	if invite.Status != domain.InvitePending {
		return nil, domain.ErrInviteAlreadyUsed
	}

	if time.Now().UTC().After(invite.ExpiresAt) {
		return nil, domain.ErrInviteExpired
	}

	if strings.TrimSpace(input.Name) == "" {
		return nil, domain.NewError("name_required", "Name is required")
	}
	input.Name = strings.TrimSpace(input.Name)

	if input.Password != input.ConfirmPassword {
		return nil, domain.NewError("password_mismatch", "Passwords do not match")
	}

	if err := s.config.PasswordPolicy.Validate(input.Password); err != nil {
		return nil, err
	}

	hash, err := s.hasher.Hash(input.Password)
	if err != nil {
		s.log.Error("failed to hash password", "err", err, "invite_id", invite.ID)
		return nil, domain.ErrInternal
	}

	now := time.Now().UTC()
	// Invite registration is an email/password registration, so it seeds and
	// gates exactly like Register. Skipping the seed would leave every invited
	// user with 2FA off in a default-on deployment.
	user := &domain.User{
		ID:               generateID(),
		Email:            invite.Email,
		PasswordHash:     &hash,
		Name:             input.Name,
		Role:             domain.RoleUser,
		IsVerified:       true,
		TwoFactorEnabled: s.config.DefaultTwoFactorEnabled,
		CreatedAt:        now,
		UpdatedAt:        now,
	}

	if err := s.users.Create(ctx, user); err != nil {
		s.log.Error("failed to create user from invite", "err", err, "email", invite.Email)
		return nil, domain.ErrInternal
	}

	invite.Status = domain.InviteAccepted
	now2 := time.Now().UTC()
	invite.AcceptedAt = &now2
	s.invites.Update(ctx, invite)

	// Same rationale as Register: gate on the global flag only, not the
	// effective check — a code mailed to the address that just accepted the
	// invite proves nothing here. The invite is already claimed above, so a
	// gated response does not strand it.
	if s.config.RequireEmail2FA && s.twoFactorSvc != nil {
		challenge, aerr := s.twoFactorSvc.Challenge(ctx, user.ID)
		if aerr != nil {
			return nil, aerr
		}
		s.log.Info("invite registered, two-factor required", "user_id", user.ID, "invite_id", invite.ID)
		if s.audit != nil {
			s.audit.Publish(ctx, audit.NewUserRegisteredEvent(user.ID, nil, ""))
		}
		return &CompleteInviteResult{
			User:               user,
			RequiresTwoFactor:  true,
			CodeSent:           challenge.Sent,
			TwoFactorChallenge: challenge.ID,
			TwoFactorExpiresAt: challenge.ExpiresAt,
			bindingToken:       challenge.BindingToken,
		}, nil
	}

	sessResult, err := s.sessionSvc.Create(ctx, user.ID, input.IP, input.UserAgent)
	if err != nil {
		s.log.Error("failed to create session", "err", err, "user_id", user.ID)
		return nil, domain.ErrInternal
	}

	s.log.Info("invite registered", "user_id", user.ID, "email", user.Email, "invite_id", invite.ID)

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewUserRegisteredEvent(user.ID, nil, ""))
	}

	return &CompleteInviteResult{
		User:         user,
		Session:      sessResult.Session,
		SessionToken: sessResult.SessionToken,
		RefreshToken: sessResult.RefreshToken,
	}, nil
}

func inviteFilterFromInput(input ListInvitesInput) port.InviteFilter {
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

func (s *InviteService) ListInvites(ctx context.Context, input ListInvitesInput) ([]domain.Invite, error) {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
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
func (s *InviteService) CountInvites(ctx context.Context, input ListInvitesInput) (int, error) {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return 0, err
	}
	n, err := s.invites.Count(ctx, inviteFilterFromInput(input))
	if err != nil {
		s.log.Error("failed to count invites", "err", err)
		return 0, domain.ErrInternal
	}
	return n, nil
}

func (s *InviteService) HardDeleteInvite(ctx context.Context, inviteID, actorID string) error {
	if err := requireAdminRole(ctx, s.users, actorID); err != nil {
		return err
	}
	// Read before deleting: the audit event names the recipient, and after the
	// delete there is no row left to read it from.
	invite, err := s.invites.GetByID(ctx, inviteID)
	if err != nil || invite == nil {
		return domain.ErrInviteNotFound
	}
	if err := s.invites.Delete(ctx, inviteID); err != nil {
		s.log.Error("failed to delete invite", "err", err, "invite_id", inviteID)
		return domain.ErrInternal
	}

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewInviteEvent(
			audit.EventAdminInviteDeleted, actorID, invite.ID, invite.Email))
	}

	s.log.Info("invite deleted", "invite_id", inviteID)
	return nil
}

func (s *InviteService) RevokeInvite(ctx context.Context, inviteID, actorID string) error {
	if err := requireAdminRole(ctx, s.users, actorID); err != nil {
		return err
	}
	invite, err := s.invites.GetByID(ctx, inviteID)
	if err != nil || invite == nil {
		return domain.ErrInviteNotFound
	}

	invite.Status = domain.InviteRevoked
	if err := s.invites.Update(ctx, invite); err != nil {
		s.log.Error("failed to revoke invite", "err", err, "invite_id", inviteID)
		return domain.ErrInternal
	}
	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewInviteEvent(
			audit.EventAdminInviteRevoked, actorID, invite.ID, invite.Email))
	}

	s.log.Info("invite revoked", "invite_id", inviteID)
	return nil
}

func (s *InviteService) ResendInviteEmail(ctx context.Context, inviteID, actorID string) error {
	if err := requireAdminRole(ctx, s.users, actorID); err != nil {
		return err
	}
	invite, err := s.invites.GetByID(ctx, inviteID)
	if err != nil || invite == nil {
		return domain.ErrInviteNotFound
	}

	if s.mailer == nil {
		return domain.NewError("email_not_configured", "Email sender is not configured")
	}

	raw, err := s.gen.Generate()
	if err != nil {
		s.log.Error("failed to generate invite code", "err", err, "invite_id", inviteID)
		return domain.ErrInternal
	}

	invite.Code = hashToken(raw)
	invite.ExpiresAt = time.Now().UTC().Add(s.config.InviteTTL)

	if err := s.invites.Update(ctx, invite); err != nil {
		s.log.Error("failed to update invite", "err", err, "invite_id", inviteID)
		return domain.ErrInternal
	}

	url := s.config.BaseURL + "/invite?token=" + raw
	result, tplErr := s.templates.Render(port.InviteData{
		AppName:   s.config.AppName,
		InviteURL: url,
		ExpiresIn: s.config.InviteTTL,
	})
	if tplErr != nil {
		s.log.Error("failed to render invite email template", "err", tplErr, "invite_id", inviteID)
		return domain.ErrInternal
	}
	if err := s.mailer.Send(ctx, invite.Email, result.Subject, result.HTML, result.Text); err != nil {
		s.log.Error("failed to send invite email", "err", err, "invite_id", inviteID)
		return domain.NewError("email_failed", "Failed to send invite email")
	}

	if s.audit != nil {
		s.audit.Publish(ctx, audit.NewInviteEvent(
			audit.EventAdminInviteResent, actorID, invite.ID, invite.Email))
	}

	s.log.Info("invite resent", "invite_id", inviteID, "email", invite.Email)
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

// BulkInviteIDsInput is the input for the ID-keyed bulk actions.
type BulkInviteIDsInput struct {
	InviteIDs []string
	ActorID   string
}

// BulkInviteEmailsInput is the input for bulk send, which is keyed by address
// rather than by ID — the invites don't exist yet.
type BulkInviteEmailsInput struct {
	Emails  []string
	ActorID string
}

// BulkInviteFailure names the invite (by ID, or by email for a send) that
// didn't succeed, with the same stable code a single call would have returned.
type BulkInviteFailure struct {
	InviteID string `json:"inviteId,omitempty"`
	Email    string `json:"email,omitempty"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

// BulkInviteResult reports per-item outcome, not overall success.
type BulkInviteResult struct {
	Succeeded []string            `json:"succeeded"`
	Failed    []BulkInviteFailure `json:"failed"`
}

func inviteFailure(id, email string, err error) BulkInviteFailure {
	f := BulkInviteFailure{InviteID: id, Email: email, Code: "internal_error", Message: "Something went wrong"}
	var ae *domain.AuthError
	if errors.As(err, &ae) {
		f.Code, f.Message = ae.Code, ae.Message
	}
	return f
}

func validateBulkIDs(ids []string) error {
	if len(ids) == 0 {
		return domain.NewError("invalid_input", "inviteIds must not be empty")
	}
	if len(ids) > maxBulkInviteIDs {
		return domain.NewError("invalid_input", fmt.Sprintf("at most %d inviteIds per bulk request", maxBulkInviteIDs))
	}
	return nil
}

// BulkRevokeInvites revokes each invite, reporting per-invite outcome.
func (s *InviteService) BulkRevokeInvites(ctx context.Context, input BulkInviteIDsInput) (*BulkInviteResult, error) {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return nil, err
	}
	if err := validateBulkIDs(input.InviteIDs); err != nil {
		return nil, err
	}
	result := &BulkInviteResult{Succeeded: []string{}, Failed: []BulkInviteFailure{}}
	for _, id := range input.InviteIDs {
		if err := s.RevokeInvite(ctx, id, input.ActorID); err != nil {
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
func (s *InviteService) BulkDeleteInvites(ctx context.Context, input BulkInviteIDsInput) (*BulkInviteResult, error) {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return nil, err
	}
	if err := validateBulkIDs(input.InviteIDs); err != nil {
		return nil, err
	}
	result := &BulkInviteResult{Succeeded: []string{}, Failed: []BulkInviteFailure{}}
	for _, id := range input.InviteIDs {
		if err := s.HardDeleteInvite(ctx, id, input.ActorID); err != nil {
			result.Failed = append(result.Failed, inviteFailure(id, "", err))
			continue
		}
		result.Succeeded = append(result.Succeeded, id)
	}
	return result, nil
}

// runBulkEmail fans `items` across a small worker pool, collecting each
// outcome. Order of the result slices follows completion, not input.
func runBulkEmail(ctx context.Context, items []string, work func(context.Context, string) error) *BulkInviteResult {
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

	out := &BulkInviteResult{Succeeded: []string{}, Failed: []BulkInviteFailure{}}
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
func (s *InviteService) BulkSendInvites(ctx context.Context, input BulkInviteEmailsInput) (*BulkInviteResult, error) {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return nil, err
	}
	if len(input.Emails) == 0 {
		return nil, domain.NewError("invalid_input", "emails must not be empty")
	}
	if len(input.Emails) > maxBulkInviteEmails {
		return nil, domain.NewError("invalid_input", fmt.Sprintf("at most %d emails per bulk request", maxBulkInviteEmails))
	}
	return runBulkEmail(ctx, input.Emails, func(c context.Context, email string) error {
		_, err := s.CreateInvite(c, CreateInviteInput{Email: email, AdminID: input.ActorID})
		return err
	}), nil
}

// BulkResendInvites rotates the code and re-sends each invite's email. Keyed
// by invite ID, but capped and fanned out like a send because it is one SMTP
// round-trip per item.
func (s *InviteService) BulkResendInvites(ctx context.Context, input BulkInviteIDsInput) (*BulkInviteResult, error) {
	if err := requireAdminRole(ctx, s.users, input.ActorID); err != nil {
		return nil, err
	}
	if len(input.InviteIDs) == 0 {
		return nil, domain.NewError("invalid_input", "inviteIds must not be empty")
	}
	if len(input.InviteIDs) > maxBulkInviteEmails {
		return nil, domain.NewError("invalid_input", fmt.Sprintf("at most %d inviteIds per bulk resend", maxBulkInviteEmails))
	}
	out := runBulkEmail(ctx, input.InviteIDs, func(c context.Context, id string) error {
		return s.ResendInviteEmail(c, id, input.ActorID)
	})
	// keyed by ID here, not email
	for i := range out.Failed {
		out.Failed[i].InviteID, out.Failed[i].Email = out.Failed[i].Email, ""
	}
	return out, nil
}
