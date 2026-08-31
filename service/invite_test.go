package service

import (
	"context"
	"testing"
	"time"

	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
)

func TestInviteRegister(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	invites := testutil.NewMockInviteRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewInviteService(users, sessions, invites, hasher, gen, nil, defaultTestConfig(), sessSvc, nil)

	raw, _ := gen.Generate()
	now := time.Now().UTC()
	invite := &domain.Invite{
		ID:        raw,
		Email:     "invited@example.com",
		Code:      hashToken(raw),
		CreatedBy: "admin-id",
		Status:    domain.InvitePending,
		ExpiresAt: now.Add(defaultTestConfig().InviteTTL),
		CreatedAt: now,
	}
	invites.Create(context.Background(), invite)

	result, err := svc.CompleteInviteRegistration(context.Background(), CompleteInviteInput{
		Code:            raw,
		Name:            "Invited User",
		Password:        "Passw0rd!",
		ConfirmPassword: "Passw0rd!",
	})
	if err != nil {
		t.Fatalf("CompleteInviteRegistration failed: %v", err)
	}
	if result.User == nil {
		t.Fatal("Expected user, got nil")
	}
	if result.User.Email != "invited@example.com" {
		t.Fatalf("Expected email invited@example.com, got %s", result.User.Email)
	}
	if !result.User.IsVerified {
		t.Fatal("Expected user to be auto-verified")
	}
	if result.SessionToken == "" {
		t.Fatal("Expected session token, got empty")
	}
}

func TestInviteRegisterExpired(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	invites := testutil.NewMockInviteRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	cfg := defaultTestConfig()
	cfg.InviteTTL = -1 * time.Hour

	svc := NewInviteService(users, sessions, invites, hasher, gen, nil, cfg, sessSvc, nil)

	raw, _ := gen.Generate()
	now := time.Now().UTC()
	invite := &domain.Invite{
		ID:        raw,
		Email:     "invited@example.com",
		Code:      hashToken(raw),
		CreatedBy: "admin-id",
		Status:    domain.InvitePending,
		ExpiresAt: now.Add(cfg.InviteTTL),
		CreatedAt: now,
	}
	invites.Create(context.Background(), invite)

	_, err := svc.CompleteInviteRegistration(context.Background(), CompleteInviteInput{
		Code:            raw,
		Name:            "Invited User",
		Password:        "Passw0rd!",
		ConfirmPassword: "Passw0rd!",
	})
	if err == nil {
		t.Fatal("Expected error for expired invite, got nil")
	}
	if authErrCode(err) != "invite_expired" {
		t.Fatalf("Expected invite_expired, got %s", authErrCode(err))
	}
}

func TestInviteRegisterPasswordMismatch(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	invites := testutil.NewMockInviteRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewInviteService(users, sessions, invites, hasher, gen, nil, defaultTestConfig(), sessSvc, nil)

	raw, _ := gen.Generate()
	invite := &domain.Invite{
		ID:        raw,
		Email:     "invited@example.com",
		Code:      hashToken(raw),
		CreatedBy: "admin-id",
		Status:    domain.InvitePending,
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
		CreatedAt: time.Now().UTC(),
	}
	invites.Create(context.Background(), invite)

	_, err := svc.CompleteInviteRegistration(context.Background(), CompleteInviteInput{
		Code:            raw,
		Name:            "Invited User",
		Password:        "Passw0rd!",
		ConfirmPassword: "different",
	})
	if err == nil {
		t.Fatal("Expected error for password mismatch, got nil")
	}
	if authErrCode(err) != "password_mismatch" {
		t.Fatalf("Expected password_mismatch, got %s", authErrCode(err))
	}
}

func TestCreateInvite_NoMailer_ReturnsEmailNotConfigured(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	invites := testutil.NewMockInviteRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewInviteService(users, sessions, invites, hasher, gen, nil, defaultTestConfig(), sessSvc, nil)
	adminID := seedInviteAdmin(users)

	_, err := svc.CreateInvite(context.Background(), CreateInviteInput{
		Email:   "invited@example.com",
		AdminID: adminID,
	})
	if err == nil {
		t.Fatal("expected an error with no mailer configured, got nil")
	}
	if authErrCode(err) != "email_not_configured" {
		t.Fatalf("Code = %q, want email_not_configured", authErrCode(err))
	}
	if got, _ := invites.GetByEmail(context.Background(), "invited@example.com"); got != nil {
		t.Fatal("no invite row should be left behind when the mailer is nil")
	}
}

func TestResendInviteEmail_NoMailer_ReturnsEmailNotConfigured(t *testing.T) {
	users := testutil.NewMockUserRepo()
	sessions := testutil.NewMockSessionRepo()
	invites := testutil.NewMockInviteRepo()
	hasher := &testutil.MockHasher{}
	gen := &testutil.MockTokenGen{Length: 32}
	sessSvc := newTestSessionService(sessions, gen)

	svc := NewInviteService(users, sessions, invites, hasher, gen, nil, defaultTestConfig(), sessSvc, nil)
	adminID := seedInviteAdmin(users)

	raw, _ := gen.Generate()
	now := time.Now().UTC()
	invite := &domain.Invite{
		ID:        raw,
		Email:     "invited@example.com",
		Code:      hashToken(raw),
		CreatedBy: "admin-id",
		Status:    domain.InvitePending,
		ExpiresAt: now.Add(defaultTestConfig().InviteTTL),
		CreatedAt: now,
	}
	invites.Create(context.Background(), invite)

	err := svc.ResendInviteEmail(context.Background(), invite.ID, adminID)
	if err == nil {
		t.Fatal("expected an error with no mailer configured, got nil")
	}
	if authErrCode(err) != "email_not_configured" {
		t.Fatalf("Code = %q, want email_not_configured", authErrCode(err))
	}
}

// seedInviteAdmin adds the admin every app-wide invite call now requires and
// returns its ID.
func seedInviteAdmin(users *testutil.MockUserRepo) string {
	admin := &domain.User{ID: "invite-admin", Email: "invite-admin@example.com", Role: domain.RoleAdmin}
	users.Create(context.Background(), admin)
	return admin.ID
}

func newInviteTestService(users *testutil.MockUserRepo) (*InviteService, *testutil.MockInviteRepo, string) {
	sessions := testutil.NewMockSessionRepo()
	invites := testutil.NewMockInviteRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	svc := NewInviteService(users, sessions, invites, &testutil.MockHasher{}, gen, nil,
		defaultTestConfig(), newTestSessionService(sessions, gen), nil)
	return svc, invites, seedInviteAdmin(users)
}

// App-wide invites are admin-only at the service layer, not just behind the
// admin middleware — Auth.Services.Invite is a documented direct-call path.
func TestInvite_NonAdminActorIsForbidden(t *testing.T) {
	users := testutil.NewMockUserRepo()
	svc, invites, _ := newInviteTestService(users)
	users.Create(context.Background(), &domain.User{
		ID: "plain-user", Email: "plain@example.com", Role: domain.RoleUser,
	})

	inv := &domain.Invite{
		ID: "inv-1", Email: "x@example.com", Status: domain.InvitePending,
		ExpiresAt: time.Now().UTC().Add(time.Hour), CreatedAt: time.Now().UTC(),
	}
	invites.Create(context.Background(), inv)

	ctx := context.Background()
	calls := map[string]error{
		"create": func() error {
			_, e := svc.CreateInvite(ctx, CreateInviteInput{Email: "a@b.co", AdminID: "plain-user"})
			return e
		}(),
		"list":    func() error { _, e := svc.ListInvites(ctx, ListInvitesInput{ActorID: "plain-user"}); return e }(),
		"count":   func() error { _, e := svc.CountInvites(ctx, ListInvitesInput{ActorID: "plain-user"}); return e }(),
		"revoke":  svc.RevokeInvite(ctx, inv.ID, "plain-user"),
		"resend":  svc.ResendInviteEmail(ctx, inv.ID, "plain-user"),
		"delete":  svc.HardDeleteInvite(ctx, inv.ID, "plain-user"),
		"noactor": func() error { _, e := svc.ListInvites(ctx, ListInvitesInput{}); return e }(),
	}
	for name, err := range calls {
		if authErrCode(err) != "forbidden" {
			t.Errorf("%s: code = %q, want forbidden", name, authErrCode(err))
		}
	}
}

func TestCreateInvite_EmailAlreadyRegistered(t *testing.T) {
	users := testutil.NewMockUserRepo()
	svc, _, adminID := newInviteTestService(users)
	users.Create(context.Background(), &domain.User{
		ID: "existing", Email: "taken@example.com", Role: domain.RoleUser,
	})

	_, err := svc.CreateInvite(context.Background(), CreateInviteInput{
		Email: "taken@example.com", AdminID: adminID,
	})
	if authErrCode(err) != "email_already_exists" {
		t.Fatalf("code = %q, want email_already_exists", authErrCode(err))
	}
}

func TestCreateInvite_DuplicatePendingInviteRejected(t *testing.T) {
	users := testutil.NewMockUserRepo()
	svc, invites, adminID := newInviteTestService(users)
	now := time.Now().UTC()
	invites.Create(context.Background(), &domain.Invite{
		ID: "inv-live", Email: "dup@example.com", Status: domain.InvitePending,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	})

	_, err := svc.CreateInvite(context.Background(), CreateInviteInput{
		Email: "dup@example.com", AdminID: adminID,
	})
	if authErrCode(err) != "invite_already_exists" {
		t.Fatalf("code = %q, want invite_already_exists", authErrCode(err))
	}
}

// An invite that lapsed shouldn't block re-inviting the same person: it gets
// past the duplicate guard and fails later, on the nil mailer.
func TestCreateInvite_ExpiredInviteDoesNotBlockReinvite(t *testing.T) {
	users := testutil.NewMockUserRepo()
	svc, invites, adminID := newInviteTestService(users)
	now := time.Now().UTC()
	invites.Create(context.Background(), &domain.Invite{
		ID: "inv-old", Email: "again@example.com", Status: domain.InvitePending,
		ExpiresAt: now.Add(-time.Hour), CreatedAt: now.Add(-2 * time.Hour),
	})

	_, err := svc.CreateInvite(context.Background(), CreateInviteInput{
		Email: "again@example.com", AdminID: adminID,
	})
	if authErrCode(err) == "invite_already_exists" {
		t.Fatal("an expired invite must not block a re-invite")
	}
	if authErrCode(err) != "email_not_configured" {
		t.Fatalf("code = %q, want email_not_configured", authErrCode(err))
	}
}

// ─── bulk invite actions ───────────────────────────────────────────────

func newBulkInviteService(users *testutil.MockUserRepo, mailer port.Mailer) (*InviteService, *testutil.MockInviteRepo, string) {
	sessions := testutil.NewMockSessionRepo()
	invites := testutil.NewMockInviteRepo()
	gen := &testutil.MockTokenGen{Length: 32}
	svc := NewInviteService(users, sessions, invites, &testutil.MockHasher{}, gen, mailer,
		defaultTestConfig(), newTestSessionService(sessions, gen), nil)
	return svc, invites, seedInviteAdmin(users)
}

func seedPendingInvite(t *testing.T, invites *testutil.MockInviteRepo, id, email string) {
	t.Helper()
	now := time.Now().UTC()
	invites.Create(context.Background(), &domain.Invite{
		ID: id, Email: email, Status: domain.InvitePending,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	})
}

func TestBulkRevokeInvites_PartialFailure(t *testing.T) {
	users := testutil.NewMockUserRepo()
	svc, invites, adminID := newBulkInviteService(users, &testutil.MockMailer{})
	seedPendingInvite(t, invites, "inv-a", "a@example.com")

	res, err := svc.BulkRevokeInvites(context.Background(), BulkInviteIDsInput{
		InviteIDs: []string{"inv-a", "missing"}, ActorID: adminID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Succeeded) != 1 || res.Succeeded[0] != "inv-a" {
		t.Errorf("Succeeded = %v, want [inv-a]", res.Succeeded)
	}
	if len(res.Failed) != 1 || res.Failed[0].InviteID != "missing" {
		t.Fatalf("Failed = %+v, want one entry for \"missing\"", res.Failed)
	}
	if res.Failed[0].Code != "invite_not_found" {
		t.Errorf("failure code = %q, want invite_not_found", res.Failed[0].Code)
	}
}

func TestBulkDeleteInvites_RemovesRows(t *testing.T) {
	users := testutil.NewMockUserRepo()
	svc, invites, adminID := newBulkInviteService(users, &testutil.MockMailer{})
	seedPendingInvite(t, invites, "inv-a", "a@example.com")
	seedPendingInvite(t, invites, "inv-b", "b@example.com")

	res, err := svc.BulkDeleteInvites(context.Background(), BulkInviteIDsInput{
		InviteIDs: []string{"inv-a", "inv-b"}, ActorID: adminID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Succeeded) != 2 {
		t.Fatalf("Succeeded = %v, want 2", res.Succeeded)
	}
	if got, _ := invites.GetByID(context.Background(), "inv-a"); got != nil {
		t.Error("inv-a should be gone")
	}
}

func TestBulkSendInvites_SendsEachAndReportsRejections(t *testing.T) {
	users := testutil.NewMockUserRepo()
	mailer := &testutil.MockMailer{}
	svc, invites, adminID := newBulkInviteService(users, mailer)

	// one address already has an account, one already has a live invite
	users.Create(context.Background(), &domain.User{
		ID: "u1", Email: "taken@example.com", Role: domain.RoleUser,
	})
	seedPendingInvite(t, invites, "inv-live", "pending@example.com")

	res, err := svc.BulkSendInvites(context.Background(), BulkInviteEmailsInput{
		Emails:  []string{"new1@example.com", "new2@example.com", "taken@example.com", "pending@example.com"},
		ActorID: adminID,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Succeeded) != 2 {
		t.Errorf("Succeeded = %v, want 2", res.Succeeded)
	}
	if len(res.Failed) != 2 {
		t.Fatalf("Failed = %+v, want 2", res.Failed)
	}
	codes := map[string]bool{}
	for _, f := range res.Failed {
		codes[f.Code] = true
		if f.Email == "" {
			t.Error("a bulk-send failure must name the email it came from")
		}
	}
	if !codes["email_already_exists"] || !codes["invite_already_exists"] {
		t.Errorf("codes = %v, want both email_already_exists and invite_already_exists", codes)
	}
	if mailer.SentCount() != 2 {
		t.Errorf("SentCount = %d, want 2 (rejected addresses must not be emailed)", mailer.SentCount())
	}
}

func TestBulkInvites_CapsRejectOversizedRequests(t *testing.T) {
	users := testutil.NewMockUserRepo()
	svc, _, adminID := newBulkInviteService(users, &testutil.MockMailer{})

	tooManyIDs := make([]string, maxBulkInviteIDs+1)
	for i := range tooManyIDs {
		tooManyIDs[i] = "id"
	}
	if _, err := svc.BulkRevokeInvites(context.Background(), BulkInviteIDsInput{
		InviteIDs: tooManyIDs, ActorID: adminID,
	}); authErrCode(err) != "invalid_input" {
		t.Errorf("revoke cap: code = %q, want invalid_input", authErrCode(err))
	}

	// send caps lower than revoke — it pays an SMTP round-trip per address
	tooManyEmails := make([]string, maxBulkInviteEmails+1)
	for i := range tooManyEmails {
		tooManyEmails[i] = "a@example.com"
	}
	if _, err := svc.BulkSendInvites(context.Background(), BulkInviteEmailsInput{
		Emails: tooManyEmails, ActorID: adminID,
	}); authErrCode(err) != "invalid_input" {
		t.Errorf("send cap: code = %q, want invalid_input", authErrCode(err))
	}

	if _, err := svc.BulkRevokeInvites(context.Background(), BulkInviteIDsInput{
		InviteIDs: nil, ActorID: adminID,
	}); authErrCode(err) != "invalid_input" {
		t.Errorf("empty: code = %q, want invalid_input", authErrCode(err))
	}
}

func TestBulkInvites_NonAdminForbidden(t *testing.T) {
	users := testutil.NewMockUserRepo()
	svc, _, _ := newBulkInviteService(users, &testutil.MockMailer{})
	users.Create(context.Background(), &domain.User{
		ID: "plain", Email: "plain2@example.com", Role: domain.RoleUser,
	})
	ctx := context.Background()

	checks := map[string]error{
		"send": func() error {
			_, e := svc.BulkSendInvites(ctx, BulkInviteEmailsInput{Emails: []string{"a@b.co"}, ActorID: "plain"})
			return e
		}(),
		"resend": func() error {
			_, e := svc.BulkResendInvites(ctx, BulkInviteIDsInput{InviteIDs: []string{"x"}, ActorID: "plain"})
			return e
		}(),
		"revoke": func() error {
			_, e := svc.BulkRevokeInvites(ctx, BulkInviteIDsInput{InviteIDs: []string{"x"}, ActorID: "plain"})
			return e
		}(),
		"delete": func() error {
			_, e := svc.BulkDeleteInvites(ctx, BulkInviteIDsInput{InviteIDs: []string{"x"}, ActorID: "plain"})
			return e
		}(),
	}
	for name, err := range checks {
		if authErrCode(err) != "forbidden" {
			t.Errorf("%s: code = %q, want forbidden", name, authErrCode(err))
		}
	}
}
