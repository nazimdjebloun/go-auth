package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/schema"
	"github.com/nazimdjebloun/go-auth/middleware"
	"github.com/nazimdjebloun/go-auth/port"
	_ "modernc.org/sqlite"
)

func migrateDB(t *testing.T, db *sql.DB, driver string) {
	t.Helper()
	schemaSQL, err := goauth.GetSchema(driver)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range schema.SplitSQL(schemaSQL) {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("migration failed: %v\nStatement: %s", err, stmt)
		}
	}
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// testMailer captures email bodies so tests can extract raw tokens sent by the
// forgot-password and invite flows.
type testMailer struct {
	mu     sync.Mutex
	bodies []string
}

func (m *testMailer) Send(_ context.Context, _, _, _, text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bodies = append(m.bodies, text)
	return nil
}

func (m *testMailer) lastBody() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.bodies) == 0 {
		return ""
	}
	return m.bodies[len(m.bodies)-1]
}

func (m *testMailer) waitForResetToken(t *testing.T) string {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if raw := extractTokenFromEmail(m.lastBody()); raw != "" {
			return raw
		}
		select {
		case <-ticker.C:
		case <-timer.C:
			t.Fatal("queued recovery did not deliver a reset email")
			return ""
		}
	}
}

// ---------------------------------------------------------------------------
// SQLite helpers
// ---------------------------------------------------------------------------

func newSQLiteDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "goauth-*.db")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", f.Name()+"?_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)")
	if err != nil {
		checkTestErrors(t).noError(os.Remove(f.Name()))
		t.Fatal(err)
	}
	cleanup := func() {
		checkTestErrors(t).noError(db.Close())
		checkTestErrors(t).noError(os.Remove(f.Name()))
	}
	return db, cleanup
}

// newTestAuth builds a *goauth.Auth directly rather than returning an
// intermediate goauth.Config — the config type is unexported (NewConfig is
// the only supported way to build one), so external packages can't name it
// as a variable/return type.
func newTestAuth(db *sql.DB, mailer port.Mailer, auditOptions ...goauth.AuditConfig) (*goauth.Auth, error) {
	auditCfg := goauth.AuditConfig{Enabled: true}
	if len(auditOptions) > 0 {
		auditCfg = auditOptions[0]
	}
	cfg, err := goauth.NewConfig(
		goauth.WithBcryptCost(4),
		goauth.WithApp(goauth.AppConfig{
			Name:    "TestApp",
			BaseURL: "http://localhost:8080",
			Database: goauth.DatabaseConfig{
				DB:     db,
				Driver: goauth.DriverSQLite,
			},
		}),
		goauth.WithSession(goauth.SessionConfig{
			TTL:             1 * time.Hour,
			IdleTTL:         1 * time.Hour,
			RefreshTokenTTL: 1 * time.Hour,
			TokenTTL:        1 * time.Hour,
			// Off, so refresh-token reuse is detected immediately rather than
			// tolerated for the default 5s — see TestRefreshToken_E2E.
			GraceWindow: goauth.Duration(0),
		}),
		goauth.WithSecurity(goauth.SecurityConfig{
			AllowHTTPURLs:  goauth.AllowPlaintextEmailLinks(),
			AllowedOrigins: []string{"http://localhost:8080"},
		}),
		goauth.WithRegistration(goauth.RegistrationConfig{
			EnableEmailPassword: true,
			EnableOAuth:         true,
			EnableInvite:        true,
			AllowPublic:         true,
			InviteTTL:           1 * time.Hour,
			VerificationCodeTTL: 1 * time.Hour,
		}),
		goauth.WithCookie(goauth.CookieConfig{Name: "goauth_session"}),
		goauth.WithMailer(mailer),
		goauth.WithSecret("0123456789abcdef0123456789abcdef"),
		goauth.WithAudit(auditCfg),
	)
	if err != nil {
		return nil, err
	}
	return goauth.New(cfg)
}

func openAuth(t *testing.T, db *sql.DB, mailer port.Mailer) *goauth.Auth {
	t.Helper()
	migrateDB(t, db, "sqlite")
	a, err := newTestAuth(db, mailer)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// newTestAuth2FA is newTestAuth with a caller-supplied TwoFactorConfig and
// RegistrationConfig layered on top of the same sane defaults. 2FA tests each
// need a different combination of RequireEmail2FA / DefaultTwoFactorEnabled /
// DisableTwoFactorChallengeBinding / RequireEmailVerification, which
// newTestAuth's one fixed config doesn't cover.
func newTestAuth2FA(db *sql.DB, mailer port.Mailer, twoFactor goauth.TwoFactorConfig, reg goauth.RegistrationConfig) (*goauth.Auth, error) {
	sec := goauth.SecurityConfig{}
	if sec.AllowHTTPURLs == nil {
		sec.AllowHTTPURLs = goauth.AllowPlaintextEmailLinks()
	}
	if len(sec.AllowedOrigins) == 0 {
		sec.AllowedOrigins = []string{"http://localhost:8080"}
	}

	reg.EnableEmailPassword = true
	reg.EnableOAuth = true
	reg.EnableInvite = true
	reg.AllowPublic = true
	if reg.InviteTTL == 0 {
		reg.InviteTTL = 1 * time.Hour
	}
	if reg.VerificationCodeTTL == 0 {
		reg.VerificationCodeTTL = 1 * time.Hour
	}

	cfg, err := goauth.NewConfig(
		goauth.WithBcryptCost(4),
		goauth.WithApp(goauth.AppConfig{
			Name:    "TestApp",
			BaseURL: "http://localhost:8080",
			Database: goauth.DatabaseConfig{
				DB:     db,
				Driver: goauth.DriverSQLite,
			},
		}),
		goauth.WithSession(goauth.SessionConfig{
			TTL:             1 * time.Hour,
			IdleTTL:         1 * time.Hour,
			RefreshTokenTTL: 1 * time.Hour,
			TokenTTL:        1 * time.Hour,
			GraceWindow:     goauth.Duration(0),
		}),
		goauth.WithSecurity(sec),
		goauth.WithTwoFactor(twoFactor),
		goauth.WithRegistration(reg),
		goauth.WithCookie(goauth.CookieConfig{Name: "goauth_session"}),
		goauth.WithMailer(mailer),
		goauth.WithSecret("0123456789abcdef0123456789abcdef"),
		goauth.WithAudit(goauth.AuditConfig{Enabled: true}),
	)
	if err != nil {
		return nil, err
	}
	return goauth.New(cfg)
}

func openAuth2FA(t *testing.T, db *sql.DB, mailer port.Mailer, twoFactor goauth.TwoFactorConfig, reg goauth.RegistrationConfig) *goauth.Auth {
	t.Helper()
	migrateDB(t, db, "sqlite")
	a, err := newTestAuth2FA(db, mailer, twoFactor, reg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// wrongTwoFactorCode returns a 6-digit code guaranteed to differ from real,
// by rolling its first digit — cheaper than rejecting on collision.
func wrongTwoFactorCode(actualCode string) string {
	d := (actualCode[0] - '0' + 1) % 10
	return string(rune('0'+d)) + actualCode[1:]
}

// twoFactorEnabledInDB re-reads the persisted flag directly, rather than
// trusting an in-memory *domain.User, since the whole point of this check is
// to catch the column silently not being wired into the user queries.
func twoFactorEnabledInDB(t *testing.T, db *sql.DB, userID string) bool {
	t.Helper()
	var enabled bool
	if err := db.QueryRow("SELECT two_factor_enabled FROM users WHERE id = ?", userID).Scan(&enabled); err != nil {
		t.Fatal(err)
	}
	return enabled
}

// extractCodeAfter splits body at prefix and returns everything up to the next
// newline (or the rest of the string).
func extractCodeAfter(body, prefix string) string {
	i := strings.Index(body, prefix)
	if i < 0 {
		return ""
	}
	rest := body[i+len(prefix):]
	nl := strings.Index(rest, "\n")
	if nl < 0 {
		return strings.TrimSpace(rest)
	}
	return strings.TrimSpace(rest[:nl])
}

// extractTokenFromEmail parses the token query parameter from a URL in the email body.
func extractTokenFromEmail(body string) string {
	prefix := "token="
	i := strings.Index(body, prefix)
	if i < 0 {
		return ""
	}
	rest := body[i+len(prefix):]
	var sb strings.Builder
	for _, r := range rest {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		} else {
			break
		}
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestMigrations_CreateTables(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	migrateDB(t, db, "sqlite")

	for _, name := range []string{"users", "sessions", "verification_tokens", "invites", "organizations", "organization_members", "organization_invites"} {
		var n int
		if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Errorf("table %q not found", name)
		}
	}
}

func TestRegister_CreatesUserAndSession(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "alice@example.com",
		Password: validTestPassword(),
		Name:     "Alice",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if res.User == nil || res.User.Email != "alice@example.com" {
		t.Fatal("user not created correctly")
	}
	if res.Session == nil {
		t.Fatal("session not created")
	}
	if res.SessionToken == "" {
		t.Fatal("session token missing")
	}

	// Password is hashed, not plaintext
	var pwHash string
	if err := db.QueryRow("SELECT password_hash FROM users WHERE id = ?", res.User.ID).Scan(&pwHash); err != nil {
		t.Fatal(err)
	}
	if pwHash == "" || pwHash == validTestPassword() {
		t.Error("password not hashed")
	}

	// Session token_hash is SHA256 of raw token, not the raw value
	var tokHash string
	if err := db.QueryRow("SELECT token_hash FROM sessions WHERE id = ?", res.Session.ID).Scan(&tokHash); err != nil {
		t.Fatal(err)
	}
	if tokHash == res.SessionToken {
		t.Error("raw session token stored in DB")
	}
	if tokHash != sha256Hex(res.SessionToken) {
		t.Error("session token hash does not match SHA256(raw token)")
	}
}

func TestSession_ValidateAfterRegister(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "bob@example.com",
		Password: validTestPassword(),
		Name:     "Bob",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	user, session, aerr := a.Services().Auth.ValidateSession(ctx, res.SessionToken)
	if aerr != nil {
		t.Fatal(aerr)
	}
	if user.ID != res.User.ID {
		t.Error("ValidateSession returned wrong user")
	}
	if session.ID != res.Session.ID {
		t.Error("ValidateSession returned wrong session")
	}
}

func TestSession_RevokeInvalidates(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "carol@example.com",
		Password: validTestPassword(),
		Name:     "Carol",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	if aerr := a.Services().Auth.Logout(ctx, res.Session.ID); aerr != nil {
		t.Fatal(aerr)
	}

	_, _, aerr = a.Services().Auth.ValidateSession(ctx, res.SessionToken)
	if aerr == nil {
		t.Error("ValidateSession should fail after session revoked")
	}
}

func TestSession_RevokeByIDForUser_OwnershipAndMalformedID(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()

	ctx := context.Background()
	alice, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "alice@revoke.com",
		Password: validTestPassword(),
		Name:     "Alice",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	bob, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "bob@revoke.com",
		Password: validTestPassword(),
		Name:     "Bob",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	revoked, err := a.Services().Session.RevokeByIDForUser(ctx, "not-a-uuid", alice.User.ID)
	if err != nil {
		t.Fatalf("malformed id should not error: %v", err)
	}
	if revoked {
		t.Error("expected revoked=false for malformed id")
	}

	revoked, err = a.Services().Session.RevokeByIDForUser(ctx, alice.Session.ID, bob.User.ID)
	if err != nil {
		t.Fatalf("cross-user revoke should not error: %v", err)
	}
	if revoked {
		t.Error("expected revoked=false for another user's session")
	}

	_, _, aerr = a.Services().Auth.ValidateSession(ctx, alice.SessionToken)
	if aerr != nil {
		t.Error("alice session should still be valid")
	}

	revoked, err = a.Services().Session.RevokeByIDForUser(ctx, alice.Session.ID, alice.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Error("expected revoked=true when owner revokes")
	}
	_, _, aerr = a.Services().Auth.ValidateSession(ctx, alice.SessionToken)
	if aerr == nil {
		t.Error("alice session should be invalid after owner revoke")
	}
}

func TestSession_RevokeManyForUser_ScopingAndMalformedIDs(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()

	ctx := context.Background()
	alice, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "alice2@revoke.com",
		Password: validTestPassword(),
		Name:     "Alice",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	bob, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "bob2@revoke.com",
		Password: validTestPassword(),
		Name:     "Bob",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	n, err := a.Services().Session.RevokeManyForUser(ctx, []string{bob.Session.ID, "not-a-uuid"}, alice.User.ID)
	if err != nil {
		t.Fatalf("mixed revoke should not error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 revoked for bob's session + malformed id, got %d", n)
	}

	n, err = a.Services().Session.RevokeManyForUser(ctx, []string{alice.Session.ID, "not-a-uuid"}, alice.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 revoked, got %d", n)
	}

	_, _, aerr = a.Services().Auth.ValidateSession(ctx, alice.SessionToken)
	if aerr == nil {
		t.Error("alice session should be invalid after revoke")
	}
	_, _, aerr = a.Services().Auth.ValidateSession(ctx, bob.SessionToken)
	if aerr != nil {
		t.Error("bob session should still be valid")
	}
}

func TestPassword_ForgotAndReset(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()

	ctx := context.Background()

	// Register with an admin email so Login skips the email-verified check.
	var aerr error
	registered, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "admin@test.com",
		Password: validTestPassword(),
		Name:     "Admin",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	// Forgot password
	if aerr := a.Services().Password.ForgotPassword(ctx, api.ForgotPasswordInput{
		Email: "admin@test.com",
	}); aerr != nil {
		t.Fatal(aerr)
	}

	resetToken := mailer.waitForResetToken(t)
	if resetToken == "" {
		t.Fatal("could not extract reset token from email body")
	}

	// Verify raw token is NOT stored — only SHA256 hash
	var tokHash string
	if err := db.QueryRow("SELECT token_hash FROM verification_tokens WHERE type = ?", domain.TokenResetPass).Scan(&tokHash); err != nil {
		t.Fatal(err)
	}
	if tokHash == resetToken {
		t.Error("raw reset token stored in verification_tokens.token_hash")
	}
	if tokHash != sha256Hex(resetToken) {
		t.Error("reset token hash does not match SHA256(raw token)")
	}
	if _, err := db.Exec("INSERT INTO verification_tokens (id, user_id, email, token_hash, type, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
		"pending-reset-2fa", registered.User.ID, registered.User.Email, "pending-reset-2fa-hash", domain.TokenTwoFactor, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Reset password
	if aerr := a.Services().Password.ResetPassword(ctx, api.ResetPasswordInput{
		Code:        resetToken,
		NewPassword: "NewP@sswd2",
	}); aerr != nil {
		t.Fatal(aerr)
	}

	// Token should be marked used
	var usedCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM verification_tokens WHERE type = ? AND used_at IS NOT NULL", domain.TokenResetPass).Scan(&usedCount); err != nil {
		t.Fatal(err)
	}
	if usedCount != 1 {
		t.Error("reset token not marked as used")
	}
	var pending2FA int
	if err := db.QueryRow("SELECT COUNT(*) FROM verification_tokens WHERE id = ?", "pending-reset-2fa").Scan(&pending2FA); err != nil {
		t.Fatal(err)
	}
	if pending2FA != 0 {
		t.Fatal("password reset left a pending 2FA challenge")
	}

	// Login with new password succeeds
	if _, aerr = a.Services().Auth.Login(ctx, api.LoginInput{
		Email:    "admin@test.com",
		Password: "NewP@sswd2",
	}); aerr != nil {
		t.Fatalf("login with new password failed: %v", aerr)
	}

	// Login with old password fails
	if _, aerr = a.Services().Auth.Login(ctx, api.LoginInput{
		Email:    "admin@test.com",
		Password: validTestPassword(),
	}); aerr == nil {
		t.Error("expected error when logging in with old password")
	}
}

func TestInvite_CreateAndCompleteRegistration(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()

	ctx := context.Background()

	// Register an admin
	admin, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "admin@test.com",
		Password: validTestPassword(),
		Name:     "Admin",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	// App-wide invites are admin-only at the service layer, so promote first —
	// Register hands out the default "user" role.
	if _, err := db.Exec("UPDATE users SET role = 'admin' WHERE id = ?", admin.User.ID); err != nil {
		t.Fatal(err)
	}

	// Create invite
	invite, aerr := a.Services().Invite.CreateInvite(ctx, api.CreateInviteInput{
		Email:   "invitee@example.com",
		AdminID: admin.User.ID,
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if invite == nil {
		t.Fatal("invite not created")
	}

	// RawCode must not be exposed in the response
	if invite.RawCode != "" {
		t.Error("invite.RawCode must be empty in response")
	}

	// DB stores hashed code, not raw
	var codeHash string
	if err := db.QueryRow("SELECT code FROM invites WHERE id = ?", invite.ID).Scan(&codeHash); err != nil {
		t.Fatal(err)
	}
	if codeHash == "" {
		t.Error("invite code hash should be stored")
	}

	// For registration completion, insert a known code hash directly
	// (CreateInvite no longer returns the raw code for security).
	knownRaw := "test-invite-code-12345"
	knownHash := sha256Hex(knownRaw)
	_, err := db.Exec("UPDATE invites SET code = ? WHERE id = ?", knownHash, invite.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Complete registration
	regResult, aerr := a.CompleteInviteRegistration(ctx, api.CompleteInviteInput{
		Code:            knownRaw,
		Name:            "Invitee",
		Password:        "Inv@lidPwd1",
		ConfirmPassword: "Inv@lidPwd1",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if regResult.User == nil {
		t.Fatal("invitee user not created")
	}
	if regResult.User.Email != "invitee@example.com" {
		t.Errorf("invitee email = %q, want invitee@example.com", regResult.User.Email)
	}
	if !regResult.User.IsVerified {
		t.Error("invite-registered user should be auto-verified")
	}
	if regResult.Session == nil {
		t.Fatal("session not created for invitee")
	}
	if regResult.SessionToken == "" {
		t.Fatal("session token missing")
	}

	// Invite marked accepted
	var status string
	if err := db.QueryRow("SELECT status FROM invites WHERE id = ?", invite.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "accepted" {
		t.Errorf("invite status = %q, want accepted", status)
	}
}

// ---------------------------------------------------------------------------
// CheckSession / GetSession
// ---------------------------------------------------------------------------

func TestCheckSession_ValidToken(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "check@test.com",
		Password: validTestPassword(),
		Name:     "Check",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	if !a.CheckSession(ctx, res.SessionToken) {
		t.Error("CheckSession returned false for a valid token")
	}
}

func TestCheckSession_InvalidToken(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()

	if a.CheckSession(context.Background(), "this-token-does-not-exist") {
		t.Error("CheckSession returned true for an invalid token")
	}
}

func TestCheckSession_EmptyToken(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()

	if a.CheckSession(context.Background(), "") {
		t.Error("CheckSession returned true for an empty token")
	}
}

func TestCheckSession_ExpiredSession(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	migrateDB(t, db, "sqlite")
	cfg, err := goauth.NewConfig(
		goauth.WithBcryptCost(4),
		goauth.WithApp(goauth.AppConfig{
			Name:    "TestApp",
			BaseURL: "http://localhost:8080",
			Database: goauth.DatabaseConfig{
				DB:     db,
				Driver: goauth.DriverSQLite,
			},
		}),
		goauth.WithSession(goauth.SessionConfig{
			TTL:             1 * time.Millisecond,
			IdleTTL:         1 * time.Millisecond,
			RefreshTokenTTL: 1 * time.Millisecond,
			TokenTTL:        1 * time.Millisecond,
		}),
		goauth.WithSecurity(goauth.SecurityConfig{
			AllowHTTPURLs:  goauth.AllowPlaintextEmailLinks(),
			AllowedOrigins: []string{"http://localhost:8080"},
		}),
		goauth.WithCookie(goauth.CookieConfig{Name: "goauth_session"}),
		goauth.WithMailer(&testMailer{}),
		goauth.WithSecret("0123456789abcdef0123456789abcdef"),
	)
	if err != nil {
		t.Fatal(err)
	}
	a, err := goauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "expire@test.com",
		Password: validTestPassword(),
		Name:     "Expire",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	// Wait for session to expire
	time.Sleep(50 * time.Millisecond)

	if a.CheckSession(ctx, res.SessionToken) {
		t.Error("CheckSession returned true for an expired token")
	}
}

func TestCheckSession_BannedUser(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "banned@test.com",
		Password: validTestPassword(),
		Name:     "Banned",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	// Promote a second user to admin so BanUser's actor authorization check
	// has someone to authorize.
	admin, aerr := a.Register(ctx, api.RegisterInput{
		Email: "banner-admin@test.com", Password: validTestPassword(), Name: "Admin",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if _, err := db.Exec("UPDATE users SET role = 'admin' WHERE id = ?", admin.User.ID); err != nil {
		t.Fatal(err)
	}

	// Ban the user via admin service
	if aerr := a.Services().Admin.BanUser(ctx, api.BanUserInput{UserID: res.User.ID, ActorID: admin.User.ID}); aerr != nil {
		t.Fatal(aerr)
	}

	if a.CheckSession(ctx, res.SessionToken) {
		t.Error("CheckSession returned true for a banned user's session")
	}
}

func TestCheckSession_AfterLogout(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "logout@test.com",
		Password: validTestPassword(),
		Name:     "Logout",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	// Logout
	if aerr = a.Services().Auth.Logout(ctx, res.Session.ID); aerr != nil {
		t.Fatal(aerr)
	}

	if a.CheckSession(ctx, res.SessionToken) {
		t.Error("CheckSession returned true after logout (session revoked)")
	}
}

func TestGetSession_ValidToken(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "getsession@test.com",
		Password: validTestPassword(),
		Name:     "GetSession",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	user, session, err := a.GetSession(ctx, res.SessionToken)
	if err != nil {
		t.Fatalf("GetSession returned error: %v", err)
	}
	if user == nil {
		t.Fatal("GetSession returned nil user")
	}
	if user.ID != res.User.ID {
		t.Errorf("user.ID = %q, want %q", user.ID, res.User.ID)
	}
	if user.Email != "getsession@test.com" {
		t.Errorf("user.Email = %q, want getsession@test.com", user.Email)
	}
	if session == nil {
		t.Fatal("GetSession returned nil session")
	}
	if session.ID != res.Session.ID {
		t.Errorf("session.ID = %q, want %q", session.ID, res.Session.ID)
	}
	if session.IsRevoked {
		t.Error("session should not be revoked")
	}
}

func TestGetSession_InvalidToken(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()

	user, session, err := a.GetSession(context.Background(), "invalid-token")
	if err == nil {
		t.Fatal("expected error for invalid token, got nil")
	}
	if user != nil {
		t.Error("expected nil user for invalid token")
	}
	if session != nil {
		t.Error("expected nil session for invalid token")
	}
}

func TestGetSession_ExpiredToken(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	migrateDB(t, db, "sqlite")
	cfg, err := goauth.NewConfig(
		goauth.WithBcryptCost(4),
		goauth.WithApp(goauth.AppConfig{
			Name:    "TestApp",
			BaseURL: "http://localhost:8080",
			Database: goauth.DatabaseConfig{
				DB:     db,
				Driver: goauth.DriverSQLite,
			},
		}),
		goauth.WithSession(goauth.SessionConfig{
			TTL:             1 * time.Millisecond,
			IdleTTL:         1 * time.Millisecond,
			RefreshTokenTTL: 1 * time.Millisecond,
			TokenTTL:        1 * time.Millisecond,
		}),
		goauth.WithSecurity(goauth.SecurityConfig{
			AllowHTTPURLs:  goauth.AllowPlaintextEmailLinks(),
			AllowedOrigins: []string{"http://localhost:8080"},
		}),
		goauth.WithCookie(goauth.CookieConfig{Name: "goauth_session"}),
		goauth.WithMailer(&testMailer{}),
		goauth.WithSecret("0123456789abcdef0123456789abcdef"),
	)
	if err != nil {
		t.Fatal(err)
	}
	a, err := goauth.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "expire-get@test.com",
		Password: validTestPassword(),
		Name:     "ExpireGet",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	time.Sleep(50 * time.Millisecond)

	user, session, err := a.GetSession(ctx, res.SessionToken)
	if err == nil {
		t.Fatal("expected error for expired session, got nil")
	}
	if user != nil {
		t.Error("expected nil user for expired session")
	}
	if session != nil {
		t.Error("expected nil session for expired session")
	}
}

func TestGetSession_BannedUser(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "banned-get@test.com",
		Password: validTestPassword(),
		Name:     "BannedGet",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	// Promote a second user to admin so BanUser's actor authorization check
	// has someone to authorize.
	admin, aerr2 := a.Register(ctx, api.RegisterInput{
		Email: "banner-admin-get@test.com", Password: validTestPassword(), Name: "Admin",
	})
	if aerr2 != nil {
		t.Fatal(aerr2)
	}
	if _, err := db.Exec("UPDATE users SET role = 'admin' WHERE id = ?", admin.User.ID); err != nil {
		t.Fatal(err)
	}

	// Ban the user
	if aerr = a.Services().Admin.BanUser(ctx, api.BanUserInput{UserID: res.User.ID, ActorID: admin.User.ID}); aerr != nil {
		t.Fatal(aerr)
	}

	user, session, err := a.GetSession(ctx, res.SessionToken)
	if err == nil {
		t.Fatal("expected error for banned user's session, got nil")
	}
	if user != nil {
		t.Error("expected nil user for banned user")
	}
	if session != nil {
		t.Error("expected nil session for banned user")
		_ = session
	}
}

func TestGetSession_ReturnsFullUserWithRole(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "role-check@test.com",
		Password: validTestPassword(),
		Name:     "RoleCheck",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	user, session, err := a.GetSession(ctx, res.SessionToken)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if user.Role != "user" {
		t.Errorf("user.Role = %q, want user", user.Role)
	}
	if user.ID == "" {
		t.Error("user.ID is empty")
	}
	if user.Email != "role-check@test.com" {
		t.Errorf("user.Email = %q, want role-check@test.com", user.Email)
	}
	if user.Name != "RoleCheck" {
		t.Errorf("user.Name = %q, want RoleCheck", user.Name)
	}
	if session.UserID != user.ID {
		t.Errorf("session.UserID = %q, want %q", session.UserID, user.ID)
	}
}

func TestGetSession_AfterLogoutReturnsError(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "revoked-get@test.com",
		Password: validTestPassword(),
		Name:     "RevokedGet",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	// Logout (revokes session)
	if aerr = a.Services().Auth.Logout(ctx, res.Session.ID); aerr != nil {
		t.Fatal(aerr)
	}

	user, session, err := a.GetSession(ctx, res.SessionToken)
	if err == nil {
		t.Fatal("expected error for revoked session, got nil")
	}
	if user != nil {
		t.Error("expected nil user for revoked session, got non-nil")
	}
	if session != nil {
		t.Error("expected nil session for revoked session, got non-nil")
	}
}

func TestRefreshToken_E2E(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()

	ctx := context.Background()

	res, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "grace@example.com",
		Password: validTestPassword(),
		Name:     "Grace",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if res.RefreshToken == "" {
		t.Fatal("expected refresh token after register")
	}

	// First refresh: should succeed and return new tokens
	refreshResult, err := a.Services().Session.RefreshSession(ctx, res.RefreshToken)
	if err != nil {
		t.Fatalf("first refresh failed: %v", err)
	}
	session2 := refreshResult.Session
	rawToken2 := refreshResult.SessionToken
	refresh2 := refreshResult.RefreshToken
	if session2 == nil {
		t.Fatal("expected session after refresh")
	}
	if rawToken2 == "" {
		t.Fatal("expected new session token after refresh")
	}
	if refresh2 == "" {
		t.Fatal("expected new refresh token after refresh")
	}
	if refresh2 == res.RefreshToken {
		t.Error("refresh token should be rotated")
	}
	if rawToken2 == res.SessionToken {
		t.Error("session token should be rotated")
	}

	// New session token should validate BEFORE reuse test (which revokes the session)
	user, session, aerr := a.Services().Auth.ValidateSession(ctx, rawToken2)
	if aerr != nil {
		t.Fatalf("new session token should validate: %v", aerr)
	}
	if user == nil || user.ID != session2.UserID {
		t.Error("ValidateSession returned wrong user")
	}
	if session == nil || session.ID != session2.ID {
		t.Error("ValidateSession returned wrong session")
	}

	// Refresh token hash should be SHA256 of raw refresh token (not stored in plaintext)
	var storedHash string
	if err := db.QueryRow("SELECT refresh_token_hash FROM sessions WHERE id = ?", session2.ID).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if storedHash == refresh2 {
		t.Error("raw refresh token stored in database")
	}
	if storedHash != sha256Hex(refresh2) {
		t.Error("refresh_token_hash does not match SHA256(raw refresh token)")
	}

	// Old refresh token should be dead (reuse detection)
	_, err = a.Services().Session.RefreshSession(ctx, res.RefreshToken)
	if err == nil {
		t.Fatal("expected error when reusing old refresh token")
	}
	ae, ok := err.(*domain.AuthError)
	if !ok {
		t.Fatalf("expected *domain.AuthError, got %T", err)
	}
	if ae.Code != domain.ErrSessionRevoked.Code {
		t.Errorf("expected ErrSessionRevoked, got %v", ae.Code)
	}

	// After reuse detection, the session should be revoked
	_, _, aerr = a.Services().Auth.ValidateSession(ctx, rawToken2)
	if aerr == nil {
		t.Fatal("expected session to be revoked after reuse detection")
	}

	// New refresh token (refresh2) should also be dead (session revoked)
	_, err = a.Services().Session.RefreshSession(ctx, refresh2)
	if err == nil {
		t.Fatal("expected error when using new refresh token after session revocation")
	}
}

// TestAuditLogList_HandlesNullJSONColumns is a regression test for a bug where
// the SQLite driver returned SQL NULL for parsed_ua / metadata and scanning
// them into json.RawMessage failed, making every admin audit-log listing 500.
func TestAuditLogList_HandlesNullJSONColumns(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()

	ctx := context.Background()
	res, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "audit@example.com",
		Password: validTestPassword(),
		Name:     "Audit",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if res.User == nil {
		t.Fatal("user not created")
	}

	// Both a user-agent-carrying event (login) and one with neither parsed_ua
	// nor metadata (admin-created user) exercise the NULL scan path.
	if _, aerr := a.Login(ctx, api.LoginInput{
		Email:     "audit@example.com",
		Password:  validTestPassword(),
		UserAgent: "TestAgent/1.0",
	}); aerr != nil {
		t.Fatal(aerr)
	}

	var events []api.AuditLogEntry
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for {
		events, err = a.Services().AuditLog.List(ctx, port.AuditLogFilter{Limit: 50})
		if err != nil {
			t.Fatalf("audit log list must not fail on NULL json columns: %v", err)
		}
		if len(events) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(events) == 0 {
		t.Fatal("expected audit events to be recorded")
	}
	// GetByID must also survive NULL columns.
	for _, e := range events {
		got, err := a.Services().AuditLog.GetByID(ctx, e.ID)
		if err != nil {
			t.Fatalf("audit log get by id %s failed: %v", e.ID, err)
		}
		if got == nil {
			t.Fatalf("audit log %s not found", e.ID)
		}
	}

	// Regression: the search filter referenced the same placeholder twice but
	// bound a single argument, which failed on ?-placeholder drivers.
	search := "TestAgent"
	searched, err := a.Services().AuditLog.List(ctx, port.AuditLogFilter{Limit: 50, Search: &search})
	if err != nil {
		t.Fatalf("search filter must not fail: %v", err)
	}
	if len(searched) == 0 {
		deadline = time.Now().Add(5 * time.Second)
		for len(searched) == 0 && !time.Now().After(deadline) {
			time.Sleep(50 * time.Millisecond)
			searched, err = a.Services().AuditLog.List(ctx, port.AuditLogFilter{Limit: 50, Search: &search})
			if err != nil {
				t.Fatalf("search filter must not fail: %v", err)
			}
		}
	}
	if len(searched) == 0 {
		t.Fatal("expected audit events matching search to be returned")
	}

	// Regression: event-type filter must bind correctly.
	loginType := "login.success"
	typed, err := a.Services().AuditLog.List(ctx, port.AuditLogFilter{Limit: 50, Types: []string{loginType}})
	if err != nil {
		t.Fatalf("event-type filter must not fail: %v", err)
	}
	if len(typed) == 0 {
		deadline = time.Now().Add(5 * time.Second)
		for len(typed) == 0 && !time.Now().After(deadline) {
			time.Sleep(50 * time.Millisecond)
			typed, err = a.Services().AuditLog.List(ctx, port.AuditLogFilter{Limit: 50, Types: []string{loginType}})
			if err != nil {
				t.Fatalf("event-type filter must not fail: %v", err)
			}
		}
	}
	if len(typed) == 0 {
		rows, _ := db.Query("SELECT event_type, user_agent FROM audit_log")
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var et, ua string
			_ = rows.Scan(&et, &ua)
			t.Logf("stored event: type=%s ua=%q", et, ua)
		}
		t.Fatal("expected login.success audit events to be returned")
	}
}

func TestPublicServicesAndHandlerLookup(t *testing.T) {
	db, cleanup := newSQLiteDB(t)
	defer cleanup()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()

	services := a.Services()
	if services.Auth == nil {
		t.Fatal("auth service was not configured")
	}
	services.Auth = nil
	if a.Services().Auth == nil {
		t.Fatal("reassigning a returned service field changed Auth wiring")
	}
	if h, ok := a.Handler("POST /auth/login"); !ok || h == nil {
		t.Fatal("enabled login handler is unavailable")
	}
	if h, ok := a.Handler("GET /not-a-route"); ok || h != nil {
		t.Fatal("unknown route returned a handler")
	}
}

// TestMount_BakesInCORS verifies Mount wires the CORS middleware into every
// mounted handler so consumers don't need to wrap the mux with a.CORS
// themselves.
func TestMount_BakesInCORS(t *testing.T) {
	db, cleanup := newSQLiteDB(t)
	defer cleanup()
	a := openAuth(t, db, &testMailer{})

	mux := http.NewServeMux()
	a.Mount(mux)

	// A real request from an allowed origin must carry CORS response headers.
	req := httptest.NewRequest("GET", "/auth/me", nil)
	req.Header.Set("Origin", "http://localhost:8080")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:8080" {
		t.Errorf("expected Access-Control-Allow-Origin http://localhost:8080, got %q", got)
	}
	varySet := false
	for _, v := range rec.Header().Values("Vary") {
		if v == "Origin" {
			varySet = true
		}
	}
	if !varySet {
		t.Errorf("expected Vary: Origin on origin-echoed response, got %v", rec.Header().Values("Vary"))
	}

	// Preflight OPTIONS must short-circuit at the CORS layer with 204, before
	// any rate-limit accounting or handler runs.
	pre := httptest.NewRequest("OPTIONS", "/auth/login", nil)
	pre.Header.Set("Origin", "http://localhost:8080")
	pre.Header.Set("Access-Control-Request-Method", "POST")
	preRec := httptest.NewRecorder()
	mux.ServeHTTP(preRec, pre)

	if preRec.Code != http.StatusNoContent {
		t.Errorf("expected 204 preflight, got %d", preRec.Code)
	}
	if got := preRec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:8080" {
		t.Errorf("expected preflight Access-Control-Allow-Origin, got %q", got)
	}

	// Preflight to a path go-auth does not own must still 404 and must NOT be
	// answered by the CORS layer — OPTIONS is registered 1:1 with real routes,
	// never a catch-all. (The same would hold for a consumer's own routes on a
	// shared mux.)
	unknown := httptest.NewRequest("OPTIONS", "/auth/does-not-exist", nil)
	unknown.Header.Set("Origin", "http://localhost:8080")
	unknown.Header.Set("Access-Control-Request-Method", "POST")
	unknownRec := httptest.NewRecorder()
	mux.ServeHTTP(unknownRec, unknown)

	if unknownRec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for OPTIONS on unregistered path, got %d", unknownRec.Code)
	}
	if got := unknownRec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected no CORS header for unregistered path, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Two-factor authentication
// ---------------------------------------------------------------------------

func TestTwoFactor_VerifyThenEnable_LaterLoginRequiresTwoFactor(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth2FA(t, db, mailer, goauth.TwoFactorConfig{}, goauth.RegistrationConfig{
		RequireEmailVerification: true,
	})
	defer a.Close()
	ctx := context.Background()

	reg, aerr := a.Services().Auth.Register(ctx, api.RegisterInput{
		Email:    "dana@example.com",
		Password: validTestPassword(),
		Name:     "Dana",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if !reg.RequiresVerification {
		t.Fatal("expected registration to require email verification")
	}

	code := extractCodeAfter(mailer.lastBody(), "Your code: ")
	if code == "" {
		t.Fatal("could not extract verification code")
	}
	user, aerr := a.Services().Verify.VerifyEmail(ctx, code)
	if aerr != nil {
		t.Fatal(aerr)
	}

	if aerr := a.Services().TwoFactor.Enable(ctx, user.ID, validTestPassword(), true, ""); aerr != nil {
		t.Fatal(aerr)
	}

	login, aerr := a.Services().Auth.Login(ctx, api.LoginInput{
		Email:    "dana@example.com",
		Password: validTestPassword(),
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if !login.RequiresTwoFactor {
		t.Fatal("expected login to require two-factor after Enable")
	}
	if login.Session != nil {
		t.Error("gated login must not issue a session")
	}

	twoFACode := extractCodeAfter(mailer.lastBody(), "Your code: ")
	if twoFACode == "" {
		t.Fatal("could not extract 2fa code")
	}
	verifyResult, aerr := a.Services().TwoFactor.Verify(ctx, login.TwoFactorChallenge, login.BindingToken(), twoFACode, "127.0.0.1", "test-agent")
	if aerr != nil {
		t.Fatal(aerr)
	}
	if verifyResult.User.ID != user.ID {
		t.Error("verify returned wrong user")
	}
	if verifyResult.Session == nil {
		t.Fatal("expected a session after successful 2fa verify")
	}
}

func TestTwoFactor_RegisterWithRequireEmail2FA_ChallengeThenVerify(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth2FA(t, db, mailer, goauth.TwoFactorConfig{RequireEmail2FA: true}, goauth.RegistrationConfig{})
	defer a.Close()
	ctx := context.Background()

	reg, aerr := a.Services().Auth.Register(ctx, api.RegisterInput{
		Email:    "erin@example.com",
		Password: validTestPassword(),
		Name:     "Erin",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if !reg.RequiresTwoFactor {
		t.Fatal("expected registration to require two-factor under RequireEmail2FA")
	}
	if reg.Session != nil {
		t.Error("gated registration must not issue a session")
	}

	code := extractCodeAfter(mailer.lastBody(), "Your code: ")
	if code == "" {
		t.Fatal("could not extract 2fa code")
	}
	verifyResult, aerr := a.Services().TwoFactor.Verify(ctx, reg.TwoFactorChallenge, reg.BindingToken(), code, "127.0.0.1", "test-agent")
	if aerr != nil {
		t.Fatal(aerr)
	}
	if verifyResult.User.Email != "erin@example.com" {
		t.Errorf("verify returned wrong user: %s", verifyResult.User.Email)
	}
	if verifyResult.Session == nil {
		t.Fatal("expected a session after successful 2fa verify")
	}
}

func TestTwoFactor_EnableDisable_PersistsToDB(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()
	ctx := context.Background()

	reg, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "frank@example.com",
		Password: validTestPassword(),
		Name:     "Frank",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	if twoFactorEnabledInDB(t, db, reg.User.ID) {
		t.Fatal("2fa should start disabled")
	}

	if aerr := a.Services().TwoFactor.Enable(ctx, reg.User.ID, validTestPassword(), true, ""); aerr != nil {
		t.Fatal(aerr)
	}
	if !twoFactorEnabledInDB(t, db, reg.User.ID) {
		t.Error("Enable did not persist two_factor_enabled=true")
	}

	if aerr := a.Services().TwoFactor.Disable(ctx, reg.User.ID, validTestPassword()); aerr != nil {
		t.Fatal(aerr)
	}
	if twoFactorEnabledInDB(t, db, reg.User.ID) {
		t.Error("Disable did not persist two_factor_enabled=false")
	}
}

func TestTwoFactor_AttemptCap_ResendFails_FreshLoginIssuesNewCode(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()
	ctx := context.Background()

	reg, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "grace@example.com",
		Password: validTestPassword(),
		Name:     "Grace",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if aerr := a.Services().TwoFactor.Enable(ctx, reg.User.ID, validTestPassword(), true, ""); aerr != nil {
		t.Fatal(aerr)
	}

	login, aerr := a.Services().Auth.Login(ctx, api.LoginInput{Email: "grace@example.com", Password: validTestPassword()})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if !login.RequiresTwoFactor {
		t.Fatal("expected login to require two-factor")
	}
	realCode := extractCodeAfter(mailer.lastBody(), "Your code: ")
	wrong := wrongTwoFactorCode(realCode)

	for i := 0; i < 5; i++ {
		if _, aerr := a.Services().TwoFactor.Verify(ctx, login.TwoFactorChallenge, login.BindingToken(), wrong, "127.0.0.1", "test-agent"); aerr == nil {
			t.Fatalf("wrong guess %d unexpectedly succeeded", i+1)
		}
	}

	// The cap is real: even the correct code is now rejected.
	if _, aerr := a.Services().TwoFactor.Verify(ctx, login.TwoFactorChallenge, login.BindingToken(), realCode, "127.0.0.1", "test-agent"); aerr == nil {
		t.Fatal("expected correct code to be rejected once the lineage is capped")
	}

	// Resend on a capped lineage does not hand out a fresh guess budget.
	if _, aerr := a.Services().TwoFactor.Resend(ctx, login.TwoFactorChallenge, login.BindingToken()); aerr == nil {
		t.Fatal("expected Resend to fail on a capped lineage")
	}

	// A fresh Login still works — Challenge replaces the dead lineage rather
	// than refusing (see TwoFactorService.Challenge).
	login2, aerr := a.Services().Auth.Login(ctx, api.LoginInput{Email: "grace@example.com", Password: validTestPassword()})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if !login2.RequiresTwoFactor {
		t.Fatal("expected second login to require two-factor")
	}
	if login2.TwoFactorChallenge == login.TwoFactorChallenge {
		t.Fatal("expected a new challenge lineage, got the same capped one")
	}
	newCode := extractCodeAfter(mailer.lastBody(), "Your code: ")
	if newCode == "" {
		t.Fatal("could not extract new 2fa code")
	}
	if _, aerr := a.Services().TwoFactor.Verify(ctx, login2.TwoFactorChallenge, login2.BindingToken(), newCode, "127.0.0.1", "test-agent"); aerr != nil {
		t.Fatalf("verify on fresh lineage should succeed: %v", aerr)
	}
}

// TestTwoFactor_NoAccountLevelRefusal_AcrossManyLineages pins the current,
// deliberate design: Challenge never refuses on a capped lineage, it replaces
// it. An attacker or a very unlucky user can rack up failures across many
// lineages and every Login still returns a fresh challenge rather than an
// account-level lockout. The per-lineage cap bounds one browser's guesses;
// it is explicitly not an account-wide brute-force control (see
// docs/security.mdx and the comment on TwoFactorService.Challenge).
func TestTwoFactor_NoAccountLevelRefusal_AcrossManyLineages(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()
	ctx := context.Background()

	reg, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "henry@example.com",
		Password: validTestPassword(),
		Name:     "Henry",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if aerr := a.Services().TwoFactor.Enable(ctx, reg.User.ID, validTestPassword(), true, ""); aerr != nil {
		t.Fatal(aerr)
	}

	const lineages = 8 // 8 * 5 = 40 recorded failures
	var lastChallenge string
	for i := 0; i < lineages; i++ {
		login, aerr := a.Services().Auth.Login(ctx, api.LoginInput{Email: "henry@example.com", Password: validTestPassword()})
		if aerr != nil {
			t.Fatalf("login %d: expected a fresh challenge, not an account-level refusal: %v", i, aerr)
		}
		if !login.RequiresTwoFactor {
			t.Fatalf("login %d: expected two-factor to still be required", i)
		}
		if login.TwoFactorChallenge == lastChallenge {
			t.Fatalf("login %d: expected a fresh lineage, reused the capped one", i)
		}
		lastChallenge = login.TwoFactorChallenge

		realCode := extractCodeAfter(mailer.lastBody(), "Your code: ")
		wrong := wrongTwoFactorCode(realCode)
		for j := 0; j < 5; j++ {
			if _, aerr := a.Services().TwoFactor.Verify(ctx, login.TwoFactorChallenge, login.BindingToken(), wrong, "127.0.0.1", "test-agent"); aerr == nil {
				t.Fatalf("login %d guess %d: wrong code unexpectedly succeeded", i, j)
			}
		}
	}
}

func TestTwoFactor_ResendCeiling(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()
	ctx := context.Background()

	reg, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "ivy@example.com",
		Password: validTestPassword(),
		Name:     "Ivy",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if aerr := a.Services().TwoFactor.Enable(ctx, reg.User.ID, validTestPassword(), true, ""); aerr != nil {
		t.Fatal(aerr)
	}
	login, aerr := a.Services().Auth.Login(ctx, api.LoginInput{Email: "ivy@example.com", Password: validTestPassword()})
	if aerr != nil {
		t.Fatal(aerr)
	}

	for i := 0; i < 3; i++ {
		if _, aerr := a.Services().TwoFactor.Resend(ctx, login.TwoFactorChallenge, login.BindingToken()); aerr != nil {
			t.Fatalf("resend %d should succeed: %v", i+1, aerr)
		}
	}
	if _, aerr := a.Services().TwoFactor.Resend(ctx, login.TwoFactorChallenge, login.BindingToken()); aerr == nil {
		t.Fatal("expected the 4th resend to fail")
	}
}

func TestTwoFactor_ConcurrentGuesses_NeverExceedCap(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()
	ctx := context.Background()

	reg, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "jack@example.com",
		Password: validTestPassword(),
		Name:     "Jack",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if aerr := a.Services().TwoFactor.Enable(ctx, reg.User.ID, validTestPassword(), true, ""); aerr != nil {
		t.Fatal(aerr)
	}
	login, aerr := a.Services().Auth.Login(ctx, api.LoginInput{Email: "jack@example.com", Password: validTestPassword()})
	if aerr != nil {
		t.Fatal(aerr)
	}
	realCode := extractCodeAfter(mailer.lastBody(), "Your code: ")
	wrong := wrongTwoFactorCode(realCode)

	var wg sync.WaitGroup
	var succeeded int32
	n := 20
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, aerr := a.Services().TwoFactor.Verify(ctx, login.TwoFactorChallenge, login.BindingToken(), wrong, "127.0.0.1", "test-agent")
			if aerr == nil {
				atomic.AddInt32(&succeeded, 1)
			}
		}()
	}
	wg.Wait()

	if succeeded != 0 {
		t.Errorf("expected every wrong guess to fail, got %d successes", succeeded)
	}

	var attempts int
	if err := db.QueryRow("SELECT attempts FROM verification_tokens WHERE id = ?", login.TwoFactorChallenge).Scan(&attempts); err != nil {
		t.Fatal(err)
	}
	if attempts != 5 {
		t.Errorf("expected exactly 5 recorded attempts after a %d-request concurrent burst, got %d", n, attempts)
	}
}

// TestRegister_ConcurrentSameEmail_OneWinsOneGetsEmailAlreadyExists exercises
// the race that motivated sqlstore's unique-constraint translation
// (port.ErrDuplicateKey -> domain.ErrEmailAlreadyExists): two requests for
// the same email both pass the GetByEmail existence check before either
// Create lands. Before that translation existed, the loser of the race got
// a generic 500 internal_error instead of the correct 409
// email_already_exists — this asserts the fix against the real SQLite
// repository, not a mock.
func TestRegister_ConcurrentSameEmail_OneWinsOneGetsEmailAlreadyExists(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()
	ctx := context.Background()

	var wg sync.WaitGroup
	var succeeded, duplicates, other int32
	n := 10
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := a.Register(ctx, api.RegisterInput{
				Email:    "race@example.com",
				Password: validTestPassword(),
				Name:     "Race Condition",
			})
			switch {
			case err == nil:
				atomic.AddInt32(&succeeded, 1)
			case errors.Is(err, domain.ErrEmailAlreadyExists):
				atomic.AddInt32(&duplicates, 1)
			default:
				t.Errorf("unexpected error: %v", err)
				atomic.AddInt32(&other, 1)
			}
		}()
	}
	wg.Wait()

	if succeeded != 1 {
		t.Errorf("expected exactly 1 successful registration out of %d concurrent attempts, got %d", n, succeeded)
	}
	if duplicates != int32(n)-1 {
		t.Errorf("expected %d losers to get email_already_exists, got %d (other=%d)", n-1, duplicates, other)
	}
	if other != 0 {
		t.Errorf("expected zero unexpected errors, got %d", other)
	}
}

func TestTwoFactor_ChallengeBinding_RequiredByDefault(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()
	ctx := context.Background()

	regA, aerr := a.Register(ctx, api.RegisterInput{Email: "kate@example.com", Password: validTestPassword(), Name: "Kate"})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if aerr := a.Services().TwoFactor.Enable(ctx, regA.User.ID, validTestPassword(), true, ""); aerr != nil {
		t.Fatal(aerr)
	}
	regB, aerr := a.Register(ctx, api.RegisterInput{Email: "leo@example.com", Password: validTestPassword(), Name: "Leo"})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if aerr := a.Services().TwoFactor.Enable(ctx, regB.User.ID, validTestPassword(), true, ""); aerr != nil {
		t.Fatal(aerr)
	}

	loginA, aerr := a.Services().Auth.Login(ctx, api.LoginInput{Email: "kate@example.com", Password: validTestPassword()})
	if aerr != nil {
		t.Fatal(aerr)
	}
	codeA := extractCodeAfter(mailer.lastBody(), "Your code: ")

	loginB, aerr := a.Services().Auth.Login(ctx, api.LoginInput{Email: "leo@example.com", Password: validTestPassword()})
	if aerr != nil {
		t.Fatal(aerr)
	}

	if loginA.BindingToken() == "" {
		t.Fatal("expected a non-empty binding token when binding is enabled")
	}

	// Missing binding cookie.
	if _, aerr := a.Services().TwoFactor.Verify(ctx, loginA.TwoFactorChallenge, "", codeA, "127.0.0.1", "test-agent"); aerr == nil {
		t.Fatal("expected verify to fail with a missing binding token")
	}
	// Binding token from a different challenge.
	if _, aerr := a.Services().TwoFactor.Verify(ctx, loginA.TwoFactorChallenge, loginB.BindingToken(), codeA, "127.0.0.1", "test-agent"); aerr == nil {
		t.Fatal("expected verify to fail with a mismatched binding token")
	}
	// The correct binding token still works.
	if _, aerr := a.Services().TwoFactor.Verify(ctx, loginA.TwoFactorChallenge, loginA.BindingToken(), codeA, "127.0.0.1", "test-agent"); aerr != nil {
		t.Fatalf("expected verify to succeed with the matching binding token: %v", aerr)
	}
}

func TestTwoFactor_ChallengeBinding_DisabledSkipsCheck(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth2FA(t, db, mailer, goauth.TwoFactorConfig{DisableChallengeBinding: true}, goauth.RegistrationConfig{})
	defer a.Close()
	ctx := context.Background()

	reg, aerr := a.Services().Auth.Register(ctx, api.RegisterInput{Email: "mona@example.com", Password: validTestPassword(), Name: "Mona"})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if aerr := a.Services().TwoFactor.Enable(ctx, reg.User.ID, validTestPassword(), true, ""); aerr != nil {
		t.Fatal(aerr)
	}
	login, aerr := a.Services().Auth.Login(ctx, api.LoginInput{Email: "mona@example.com", Password: validTestPassword()})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if login.BindingToken() != "" {
		t.Error("expected an empty binding token when binding is disabled")
	}
	code := extractCodeAfter(mailer.lastBody(), "Your code: ")
	if _, aerr := a.Services().TwoFactor.Verify(ctx, login.TwoFactorChallenge, "", code, "127.0.0.1", "test-agent"); aerr != nil {
		t.Fatalf("expected verify to succeed with no binding token when binding is disabled: %v", aerr)
	}
}

func TestTwoFactor_DefaultTwoFactorEnabled_GatedUntilDisabled(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth2FA(t, db, mailer, goauth.TwoFactorConfig{DefaultEnabled: true}, goauth.RegistrationConfig{})
	defer a.Close()
	ctx := context.Background()

	reg, aerr := a.Services().Auth.Register(ctx, api.RegisterInput{Email: "nina@example.com", Password: validTestPassword(), Name: "Nina"})
	if aerr != nil {
		t.Fatal(aerr)
	}
	// Register itself does not gate — only RequireEmail2FA gates registration
	// (see the "deliberate exception" note on AuthService.Register).
	if reg.RequiresTwoFactor {
		t.Fatal("registration should not gate on DefaultTwoFactorEnabled alone")
	}
	if reg.Session == nil {
		t.Fatal("expected registration to issue a session directly")
	}
	if !twoFactorEnabledInDB(t, db, reg.User.ID) {
		t.Fatal("expected the new user to be seeded with two_factor_enabled=true")
	}

	login, aerr := a.Services().Auth.Login(ctx, api.LoginInput{Email: "nina@example.com", Password: validTestPassword()})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if !login.RequiresTwoFactor {
		t.Fatal("expected the next login to require two-factor")
	}
	code := extractCodeAfter(mailer.lastBody(), "Your code: ")
	verifyResult, aerr := a.Services().TwoFactor.Verify(ctx, login.TwoFactorChallenge, login.BindingToken(), code, "127.0.0.1", "test-agent")
	if aerr != nil {
		t.Fatal(aerr)
	}
	user := verifyResult.User

	if aerr := a.Services().TwoFactor.Disable(ctx, user.ID, validTestPassword()); aerr != nil {
		t.Fatal(aerr)
	}

	login2, aerr := a.Services().Auth.Login(ctx, api.LoginInput{Email: "nina@example.com", Password: validTestPassword()})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if login2.RequiresTwoFactor {
		t.Fatal("expected login to no longer require two-factor after Disable")
	}
	if login2.Session == nil {
		t.Fatal("expected an ungated login to issue a session")
	}
}

func TestTwoFactor_RequireEmail2FA_GatesAdminLoginAndInvite(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth2FA(t, db, mailer, goauth.TwoFactorConfig{RequireEmail2FA: true}, goauth.RegistrationConfig{})
	defer a.Close()
	ctx := context.Background()

	// Register (also gated under RequireEmail2FA), verify, then promote to
	// admin directly so AdminLogin can be exercised in isolation.
	reg, aerr := a.Services().Auth.Register(ctx, api.RegisterInput{Email: "oscar@example.com", Password: validTestPassword(), Name: "Oscar"})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if !reg.RequiresTwoFactor {
		t.Fatal("expected registration to require two-factor under RequireEmail2FA")
	}
	code := extractCodeAfter(mailer.lastBody(), "Your code: ")
	verifyResult, aerr := a.Services().TwoFactor.Verify(ctx, reg.TwoFactorChallenge, reg.BindingToken(), code, "127.0.0.1", "test-agent")
	if aerr != nil {
		t.Fatal(aerr)
	}
	user := verifyResult.User
	if _, err := db.Exec("UPDATE users SET role = 'admin' WHERE id = ?", user.ID); err != nil {
		t.Fatal(err)
	}

	adminLogin, aerr := a.Services().Auth.AdminLogin(ctx, api.LoginInput{Email: "oscar@example.com", Password: validTestPassword()})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if !adminLogin.RequiresTwoFactor {
		t.Fatal("expected admin login to require two-factor — admins are not exempt")
	}
	if adminLogin.Session != nil {
		t.Error("gated admin login must not issue a session")
	}
	adminCode := extractCodeAfter(mailer.lastBody(), "Your code: ")
	if _, aerr := a.Services().TwoFactor.Verify(ctx, adminLogin.TwoFactorChallenge, adminLogin.BindingToken(), adminCode, "127.0.0.1", "test-agent"); aerr != nil {
		t.Fatalf("admin verify should succeed: %v", aerr)
	}

	// Invite registration is gated the same way as Register.
	invite, aerr := a.Services().Invite.CreateInvite(ctx, api.CreateInviteInput{Email: "pat@example.com", AdminID: user.ID})
	if aerr != nil {
		t.Fatal(aerr)
	}
	knownRaw := "test-invite-code-2fa"
	knownHash := sha256Hex(knownRaw)
	if _, err := db.Exec("UPDATE invites SET code = ? WHERE id = ?", knownHash, invite.ID); err != nil {
		t.Fatal(err)
	}

	inviteResult, aerr := a.Services().Invite.CompleteInviteRegistration(ctx, api.CompleteInviteInput{
		Code:            knownRaw,
		Name:            "Pat",
		Password:        "Inv@lidPwd1",
		ConfirmPassword: "Inv@lidPwd1",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if !inviteResult.RequiresTwoFactor {
		t.Fatal("expected invite registration to require two-factor under RequireEmail2FA")
	}
	if inviteResult.Session != nil {
		t.Error("gated invite registration must not issue a session")
	}
	inviteCode := extractCodeAfter(mailer.lastBody(), "Your code: ")
	if _, aerr := a.Services().TwoFactor.Verify(ctx, inviteResult.TwoFactorChallenge, inviteResult.BindingToken(), inviteCode, "127.0.0.1", "test-agent"); aerr != nil {
		t.Fatalf("invite verify should succeed: %v", aerr)
	}
}

func TestTwoFactor_Enable_RevokesOtherSessionsByDefault(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()
	ctx := context.Background()

	reg, aerr := a.Register(ctx, api.RegisterInput{Email: "quinn@example.com", Password: validTestPassword(), Name: "Quinn"})
	if aerr != nil {
		t.Fatal(aerr)
	}
	// A second session from another device.
	if _, aerr := a.Services().Auth.Login(ctx, api.LoginInput{Email: "quinn@example.com", Password: validTestPassword(), IP: "10.0.0.2", UserAgent: "second-device"}); aerr != nil {
		t.Fatal(aerr)
	}

	sessions, err := a.Services().Session.ListAll(ctx, reg.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions before Enable, got %d", len(sessions))
	}

	if aerr := a.Services().TwoFactor.Enable(ctx, reg.User.ID, validTestPassword(), false, reg.Session.ID); aerr != nil {
		t.Fatal(aerr)
	}

	sessions, err = a.Services().Session.ListAll(ctx, reg.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected only the caller's session to survive Enable, got %d", len(sessions))
	}
	if sessions[0].ID != reg.Session.ID {
		t.Error("the surviving session should be the caller's own")
	}
}

func TestTwoFactor_Enable_KeepOtherSessionsLeavesBoth(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	mailer := &testMailer{}
	a := openAuth(t, db, mailer)
	defer a.Close()
	ctx := context.Background()

	reg, aerr := a.Register(ctx, api.RegisterInput{Email: "ray@example.com", Password: validTestPassword(), Name: "Ray"})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if _, aerr := a.Services().Auth.Login(ctx, api.LoginInput{Email: "ray@example.com", Password: validTestPassword(), IP: "10.0.0.3", UserAgent: "second-device"}); aerr != nil {
		t.Fatal(aerr)
	}

	if aerr := a.Services().TwoFactor.Enable(ctx, reg.User.ID, validTestPassword(), true, reg.Session.ID); aerr != nil {
		t.Fatal(aerr)
	}

	sessions, err := a.Services().Session.ListAll(ctx, reg.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected both sessions to survive with keepOtherSessions=true, got %d", len(sessions))
	}
}

// --- CSRF cross-site config mismatch warnings ---
//
// SameSite=None and ExposeCSRFTokenInBody are the same decision from two sides.
// Setting one without the other leaves a browser deployment that half-works,
// which reads as a library bug rather than a config mismatch, so New warns.
// It warns rather than rejects: a native client keeps its own cookie jar and
// is not subject to SameSite, so either alone is legitimate there.
func newAuthWithCSRFTopology(t *testing.T, db *sql.DB, sameSite http.SameSite, exposeInBody bool) *bytes.Buffer {
	t.Helper()
	migrateDB(t, db, "sqlite")

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg, err := goauth.NewConfig(
		goauth.WithBcryptCost(4),
		goauth.WithApp(goauth.AppConfig{
			Name:     "TestApp",
			BaseURL:  "https://api.example.com",
			Database: goauth.DatabaseConfig{DB: db, Driver: goauth.DriverSQLite},
		}),
		goauth.WithSecurity(goauth.SecurityConfig{
			AllowedOrigins: []string{"https://panel.example.com"},
			CSRFToken:      &middleware.CSRFTokenConfig{ExposeCSRFTokenInBody: exposeInBody},
		}),
		goauth.WithCookie(goauth.CookieConfig{Name: "goauth_session", SameSite: sameSite}),
		goauth.WithSecret("0123456789abcdef0123456789abcdef"),
		goauth.WithMailer(&testMailer{}),
		goauth.WithLogger(logger),
	)
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	a, err := goauth.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(a.Close)
	return &buf
}

func TestCSRFTopology_WarnsOnNoneWithoutBodyToken(t *testing.T) {
	db, cleanup := newSQLiteDB(t)
	defer cleanup()

	logs := newAuthWithCSRFTopology(t, db, http.SameSiteNoneMode, false).String()
	if !strings.Contains(logs, "cannot read the CSRF token") {
		t.Errorf("expected a warning about the unreadable token, got:\n%s", logs)
	}
}

func TestCSRFTopology_WarnsOnBodyTokenWithoutNone(t *testing.T) {
	db, cleanup := newSQLiteDB(t)
	defer cleanup()

	logs := newAuthWithCSRFTopology(t, db, http.SameSiteLaxMode, true).String()
	if !strings.Contains(logs, "arrives unauthenticated") {
		t.Errorf("expected a warning about the missing session cookie, got:\n%s", logs)
	}
}

func TestCSRFTopology_SilentWhenBothSet(t *testing.T) {
	db, cleanup := newSQLiteDB(t)
	defer cleanup()

	logs := newAuthWithCSRFTopology(t, db, http.SameSiteNoneMode, true).String()
	if strings.Contains(logs, "ExposeCSRFTokenInBody") {
		t.Errorf("a correctly configured cross-site deployment must not warn, got:\n%s", logs)
	}
}

func TestCSRFTopology_SilentOnPlainSameOriginDefaults(t *testing.T) {
	db, cleanup := newSQLiteDB(t)
	defer cleanup()

	logs := newAuthWithCSRFTopology(t, db, http.SameSiteLaxMode, false).String()
	if strings.Contains(logs, "ExposeCSRFTokenInBody") {
		t.Errorf("the default same-origin setup must not warn, got:\n%s", logs)
	}
}
