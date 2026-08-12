package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
)

// ─── fakes ──────────────────────────────────────────────────

type fakeUserRepo struct {
	byEmail map[string]*domain.User
	created []*domain.User
	admins  int

	listErr   error
	createErr error
}

func newFakeUserRepo() *fakeUserRepo {
	return &fakeUserRepo{byEmail: map[string]*domain.User{}}
}

func (f *fakeUserRepo) Create(ctx context.Context, user *domain.User) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.byEmail[user.Email] = user
	f.created = append(f.created, user)
	if user.Role == domain.RoleAdmin {
		f.admins++
	}
	return nil
}

func (f *fakeUserRepo) GetByID(ctx context.Context, id string) (*domain.User, error) {
	return nil, nil
}

func (f *fakeUserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	return f.byEmail[email], nil
}

func (f *fakeUserRepo) Update(ctx context.Context, user *domain.User) error { return nil }
func (f *fakeUserRepo) Delete(ctx context.Context, id string) error        { return nil }

func (f *fakeUserRepo) List(ctx context.Context, filter port.UserFilter) ([]domain.User, int, error) {
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	if filter.Role != nil && *filter.Role == domain.RoleAdmin {
		return nil, f.admins, nil
	}
	return nil, len(f.byEmail), nil
}

func (f *fakeUserRepo) SetPasswordAndVerify(ctx context.Context, userID, passwordHash, tokenID string) error {
	return nil
}
func (f *fakeUserRepo) SetBanStatus(ctx context.Context, userID string, isBanned bool, bannedAt *time.Time, updatedAt time.Time) error {
	return nil
}
func (f *fakeUserRepo) UpdateLastLoginAt(ctx context.Context, userID string, t time.Time) error {
	return nil
}
func (f *fakeUserRepo) SetTwoFactorEnabled(ctx context.Context, userID string, enabled bool, updatedAt time.Time) error {
	return nil
}

type fakeMailer struct {
	sendErr     error
	sent        []string
	lastSubject string
	lastHTML    string
	lastBody    string
}

func (f *fakeMailer) Send(ctx context.Context, to, subject, html, text string) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, to)
	f.lastSubject = subject
	f.lastHTML = html
	f.lastBody = text
	return nil
}

func testDeps(repo *fakeUserRepo, mailer port.Mailer) seedAdminDeps {
	return seedAdminDeps{
		repo:   repo,
		mailer: mailer,
		hash:   func(s string) (string, error) { return "hashed:" + s, nil },
		now:    func() time.Time { return time.Unix(0, 0).UTC() },
		genID:  func() string { return "fixed-id" },
	}
}

// ─── mode detection: email ──────────────────────────────────

func TestResolveAdminEmail_EnvVarWins(t *testing.T) {
	email, err := resolveAdminEmail("env@example.com", false, true, func(string) (string, error) {
		t.Fatal("should not prompt when env var is set")
		return "", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if email != "env@example.com" {
		t.Fatalf("expected env@example.com, got %s", email)
	}
}

func TestResolveAdminEmail_NonInteractiveNoEnv_Errors(t *testing.T) {
	_, err := resolveAdminEmail("", true, true, func(string) (string, error) {
		t.Fatal("should not prompt in non-interactive mode")
		return "", nil
	})
	if err == nil {
		t.Fatal("expected error when ADMIN_EMAIL unset and --non-interactive passed")
	}
}

func TestResolveAdminEmail_NoTTYNoEnv_Errors(t *testing.T) {
	_, err := resolveAdminEmail("", false, false, func(string) (string, error) {
		t.Fatal("should not prompt when stdin is not a TTY")
		return "", nil
	})
	if err == nil {
		t.Fatal("expected error when ADMIN_EMAIL unset and stdin is not a TTY")
	}
}

func TestResolveAdminEmail_TTYPrompts(t *testing.T) {
	email, err := resolveAdminEmail("", false, true, func(label string) (string, error) {
		return "typed@example.com", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if email != "typed@example.com" {
		t.Fatalf("expected typed@example.com, got %s", email)
	}
}

// ─── mode detection + validation: password ──────────────────

var defaultPolicy = domain.PasswordPolicy{MinLength: 8, RequireDigit: true}

func TestResolveAdminPassword_EnvVarValid(t *testing.T) {
	pw, generated, err := resolveAdminPassword("Sup3rSecret", false, true, defaultPolicy, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if generated {
		t.Fatal("expected generated=false for env-supplied password")
	}
	if pw != "Sup3rSecret" {
		t.Fatalf("expected password to be passed through, got %s", pw)
	}
}

func TestResolveAdminPassword_EnvVarWeak_Rejected(t *testing.T) {
	_, _, err := resolveAdminPassword("short", false, true, defaultPolicy, nil)
	if err == nil {
		t.Fatal("expected error for weak ADMIN_PASSWORD")
	}
}

func TestResolveAdminPassword_NonInteractive_AutoGenerates(t *testing.T) {
	pw, generated, err := resolveAdminPassword("", true, true, defaultPolicy, func(string) (string, error) {
		t.Fatal("should not prompt in non-interactive mode")
		return "", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !generated {
		t.Fatal("expected generated=true")
	}
	if authErr := defaultPolicy.Validate(pw); authErr != nil {
		t.Fatalf("generated password fails policy: %v", authErr)
	}
}

func TestResolveAdminPassword_TTYEmptyInput_AutoGenerates(t *testing.T) {
	pw, generated, err := resolveAdminPassword("", false, true, defaultPolicy, func(string) (string, error) {
		return "", nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !generated {
		t.Fatal("expected generated=true when prompt returns empty input")
	}
	if pw == "" {
		t.Fatal("expected a non-empty generated password")
	}
}

func TestResolveAdminPassword_TTYTypedWeak_Rejected(t *testing.T) {
	_, _, err := resolveAdminPassword("", false, true, defaultPolicy, func(string) (string, error) {
		return "weak", nil
	})
	if err == nil {
		t.Fatal("expected error for weak typed password")
	}
}

func TestGeneratePassword_SatisfiesStrictPolicy(t *testing.T) {
	strict := domain.PasswordPolicy{MinLength: 12, RequireUppercase: true, RequireDigit: true, RequireSpecial: true}
	for i := 0; i < 50; i++ {
		pw, err := generatePassword()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if authErr := strict.Validate(pw); authErr != nil {
			t.Fatalf("generated password %q fails strict policy: %v", pw, authErr)
		}
	}
}

// ─── mailer resolution ───────────────────────────────────────

func TestResolveMailer_DevNoSMTP_UsesLogMailer(t *testing.T) {
	m, err := resolveMailer(goauth.EnvironmentDev, smtpConfig{}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := m.(*goauth.LogMailer); !ok {
		t.Fatalf("expected *goauth.LogMailer, got %T", m)
	}
}

func TestResolveMailer_StagingNoSMTPNoSkip_Errors(t *testing.T) {
	_, err := resolveMailer(goauth.EnvironmentStaging, smtpConfig{}, false)
	if err == nil {
		t.Fatal("expected error when staging has no SMTP config and check isn't skipped")
	}
}

func TestResolveMailer_StagingNoSMTPWithSkip_ReturnsNilMailer(t *testing.T) {
	m, err := resolveMailer(goauth.EnvironmentStaging, smtpConfig{}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m != nil {
		t.Fatalf("expected nil mailer when skip-mailer-check has no SMTP config, got %T", m)
	}
}

func TestResolveMailer_WithSMTPFields_BuildsSMTPMailer(t *testing.T) {
	m, err := resolveMailer(goauth.EnvironmentProd, smtpConfig{Host: "smtp.example.com", From: "auth@example.com", Port: 587}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := m.(*goauth.SMTPMailer); !ok {
		t.Fatalf("expected *goauth.SMTPMailer, got %T", m)
	}
}

// ─── account-created email delivery ─────────────────────────

// The HTML and text bodies used to be the same plain string passed twice, so
// every client rendered the text version. Pin that they arrive distinct.
func TestSeedAdmin_SendsDistinctHTMLAndTextBodies(t *testing.T) {
	repo := newFakeUserRepo()
	mailer := &fakeMailer{}
	_, err := seedAdmin(context.Background(), seedAdminParams{email: "admin@example.com", password: "Sup3rSecret"}, testDeps(repo, mailer))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mailer.lastSubject != adminAccountCreatedSubject {
		t.Fatalf("expected subject %q, got %q", adminAccountCreatedSubject, mailer.lastSubject)
	}
	if mailer.lastHTML == mailer.lastBody {
		t.Fatal("expected distinct HTML and text bodies, got the same string for both")
	}
	if !strings.Contains(mailer.lastHTML, "<html") {
		t.Fatalf("expected the HTML argument to carry markup, got %q", mailer.lastHTML)
	}
	if strings.Contains(mailer.lastBody, "<") {
		t.Fatalf("expected the text argument to carry no markup, got %q", mailer.lastBody)
	}
}

// ─── core seeding logic: duplicate guards + mailer-abort-before-write ─────

func TestSeedAdmin_HappyPath(t *testing.T) {
	repo := newFakeUserRepo()
	mailer := &fakeMailer{}
	user, err := seedAdmin(context.Background(), seedAdminParams{email: "admin@example.com", password: "Sup3rSecret"}, testDeps(repo, mailer))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user.Role != domain.RoleAdmin {
		t.Fatalf("expected admin role, got %s", user.Role)
	}
	if !user.IsVerified {
		t.Fatal("expected seeded admin to be marked verified")
	}
	if len(mailer.sent) != 1 || mailer.sent[0] != "admin@example.com" {
		t.Fatalf("expected verification email sent to admin@example.com, got %v", mailer.sent)
	}
	if len(repo.created) != 1 {
		t.Fatalf("expected exactly one user created, got %d", len(repo.created))
	}
}

func TestSeedAdmin_DuplicateEmail_Rejected(t *testing.T) {
	repo := newFakeUserRepo()
	repo.byEmail["admin@example.com"] = &domain.User{Email: "admin@example.com"}
	mailer := &fakeMailer{}

	_, err := seedAdmin(context.Background(), seedAdminParams{email: "admin@example.com", password: "Sup3rSecret"}, testDeps(repo, mailer))
	if err == nil {
		t.Fatal("expected error for duplicate email")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("expected 'already exists' error, got: %v", err)
	}
	if len(repo.created) != 0 {
		t.Fatal("expected nothing written to the database")
	}
	if len(mailer.sent) != 0 {
		t.Fatal("expected no mailer send when email already exists")
	}
}

func TestSeedAdmin_DuplicateAdmin_RejectedWithoutForce(t *testing.T) {
	repo := newFakeUserRepo()
	repo.admins = 1
	mailer := &fakeMailer{}

	_, err := seedAdmin(context.Background(), seedAdminParams{email: "second@example.com", password: "Sup3rSecret"}, testDeps(repo, mailer))
	if err == nil {
		t.Fatal("expected error when an admin already exists and --force is not passed")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Fatalf("expected error to mention --force, got: %v", err)
	}
	if len(repo.created) != 0 {
		t.Fatal("expected nothing written to the database")
	}
}

func TestSeedAdmin_DuplicateAdmin_AllowedWithForce(t *testing.T) {
	repo := newFakeUserRepo()
	repo.admins = 1
	mailer := &fakeMailer{}

	_, err := seedAdmin(context.Background(), seedAdminParams{email: "second@example.com", password: "Sup3rSecret", force: true}, testDeps(repo, mailer))
	if err != nil {
		t.Fatalf("unexpected error with --force: %v", err)
	}
	if len(repo.created) != 1 {
		t.Fatal("expected the second admin to be created")
	}
}

func TestSeedAdmin_MailerFailure_AbortsBeforeDBWrite(t *testing.T) {
	repo := newFakeUserRepo()
	mailer := &fakeMailer{sendErr: errors.New("smtp: connection refused")}

	_, err := seedAdmin(context.Background(), seedAdminParams{email: "admin@example.com", password: "Sup3rSecret"}, testDeps(repo, mailer))
	if err == nil {
		t.Fatal("expected error when mailer send fails")
	}
	if len(repo.created) != 0 {
		t.Fatal("expected nothing written to the database after a failed mailer send")
	}
	if got, err := repo.GetByEmail(context.Background(), "admin@example.com"); err != nil || got != nil {
		t.Fatalf("expected GetByEmail to still return nothing, got user=%v err=%v", got, err)
	}
}

func TestSeedAdmin_SkipMailerCheck_SkipsSendAndStillCreates(t *testing.T) {
	repo := newFakeUserRepo()

	_, err := seedAdmin(context.Background(), seedAdminParams{email: "admin@example.com", password: "Sup3rSecret", skipMailerCheck: true}, testDeps(repo, nil))
	if err != nil {
		t.Fatalf("unexpected error with skipMailerCheck and nil mailer: %v", err)
	}
	if len(repo.created) != 1 {
		t.Fatal("expected the admin to be created even with no mailer, since the check was skipped")
	}
}
