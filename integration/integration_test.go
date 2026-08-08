package integration_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/service"
	_ "modernc.org/sqlite"
)

func migrateDB(t *testing.T, db *sql.DB, driver string) {
	t.Helper()
	schema, err := goauth.GetSchema(driver)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range goauth.SplitSQL(schema) {
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

// ---------------------------------------------------------------------------
// SQLite helpers
// ---------------------------------------------------------------------------

func newSQLiteDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	f, err := os.CreateTemp("", "goauth-*.db")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", f.Name()+"?_pragma=busy_timeout(10000)")
	if err != nil {
		os.Remove(f.Name())
		t.Fatal(err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		db.Close()
		os.Remove(f.Name())
		t.Fatal(err)
	}
	cleanup := func() { db.Close(); os.Remove(f.Name()) }
	return db, cleanup
}

// newTestAuth builds a *goauth.Auth directly rather than returning an
// intermediate goauth.Config — the config type is unexported (NewConfig is
// the only supported way to build one), so external packages can't name it
// as a variable/return type.
func newTestAuth(db *sql.DB, mailer port.Mailer) (*goauth.Auth, error) {
	cfg, err := goauth.NewConfig(
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
		}),
		goauth.WithSecurity(goauth.SecurityConfig{
			AllowedOrigins: []string{"http://localhost:8080"},
			TokenTTL:       1 * time.Hour,
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
		goauth.WithEmail(goauth.EmailConfig{AllowHTTPURLs: true}),
		goauth.WithAudit(goauth.AuditConfig{Enabled: true}),
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
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "alice@example.com",
		Password: "V@lidPswd1",
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
	if pwHash == "" || pwHash == "V@lidPswd1" {
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
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "bob@example.com",
		Password: "V@lidPswd1",
		Name:     "Bob",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	user, session, aerr := a.Services.Auth.ValidateSession(ctx, res.SessionToken)
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
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "carol@example.com",
		Password: "V@lidPswd1",
		Name:     "Carol",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	if aerr := a.Services.Auth.Logout(ctx, res.Session.ID); aerr != nil {
		t.Fatal(aerr)
	}

	_, _, aerr = a.Services.Auth.ValidateSession(ctx, res.SessionToken)
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
	alice, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "alice@revoke.com",
		Password: "V@lidPswd1",
		Name:     "Alice",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	bob, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "bob@revoke.com",
		Password: "V@lidPswd1",
		Name:     "Bob",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	revoked, err := a.Services.Session.RevokeByIDForUser(ctx, "not-a-uuid", alice.User.ID)
	if err != nil {
		t.Fatalf("malformed id should not error: %v", err)
	}
	if revoked {
		t.Error("expected revoked=false for malformed id")
	}

	revoked, err = a.Services.Session.RevokeByIDForUser(ctx, alice.Session.ID, bob.User.ID)
	if err != nil {
		t.Fatalf("cross-user revoke should not error: %v", err)
	}
	if revoked {
		t.Error("expected revoked=false for another user's session")
	}

	_, _, aerr = a.Services.Auth.ValidateSession(ctx, alice.SessionToken)
	if aerr != nil {
		t.Error("alice session should still be valid")
	}

	revoked, err = a.Services.Session.RevokeByIDForUser(ctx, alice.Session.ID, alice.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Error("expected revoked=true when owner revokes")
	}
	_, _, aerr = a.Services.Auth.ValidateSession(ctx, alice.SessionToken)
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
	alice, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "alice2@revoke.com",
		Password: "V@lidPswd1",
		Name:     "Alice",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	bob, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "bob2@revoke.com",
		Password: "V@lidPswd1",
		Name:     "Bob",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	n, err := a.Services.Session.RevokeManyForUser(ctx, []string{bob.Session.ID, "not-a-uuid"}, alice.User.ID)
	if err != nil {
		t.Fatalf("mixed revoke should not error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 revoked for bob's session + malformed id, got %d", n)
	}

	n, err = a.Services.Session.RevokeManyForUser(ctx, []string{alice.Session.ID, "not-a-uuid"}, alice.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 revoked, got %d", n)
	}

	_, _, aerr = a.Services.Auth.ValidateSession(ctx, alice.SessionToken)
	if aerr == nil {
		t.Error("alice session should be invalid after revoke")
	}
	_, _, aerr = a.Services.Auth.ValidateSession(ctx, bob.SessionToken)
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
	var aerr *domain.AuthError
	if _, aerr = a.Register(ctx, goauth.RegisterInput{
		Email:    "admin@test.com",
		Password: "V@lidPswd1",
		Name:     "Admin",
	}); aerr != nil {
		t.Fatal(aerr)
	}

	// Forgot password
	if aerr := a.Services.Password.ForgotPassword(ctx, service.ForgotPasswordInput{
		Email: "admin@test.com",
	}); aerr != nil {
		t.Fatal(aerr)
	}

	body := mailer.lastBody()
	resetToken := extractTokenFromEmail(body)
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

	// Reset password
	if aerr := a.Services.Password.ResetPassword(ctx, service.ResetPasswordInput{
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

	// Login with new password succeeds
	if _, aerr = a.Services.Auth.Login(ctx, service.LoginInput{
		Email:    "admin@test.com",
		Password: "NewP@sswd2",
	}); aerr != nil {
		t.Fatalf("login with new password failed: %v", aerr)
	}

	// Login with old password fails
	if _, aerr = a.Services.Auth.Login(ctx, service.LoginInput{
		Email:    "admin@test.com",
		Password: "V@lidPswd1",
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
	admin, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "admin@test.com",
		Password: "V@lidPswd1",
		Name:     "Admin",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	// Create invite
	invite, aerr := a.Services.Invite.CreateInvite(ctx, service.CreateInviteInput{
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
	regResult, aerr := a.CompleteInviteRegistration(ctx, goauth.CompleteInviteInput{
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
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "check@test.com",
		Password: "V@lidPswd1",
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
		}),
		goauth.WithSecurity(goauth.SecurityConfig{
			TokenTTL:       1 * time.Millisecond,
			AllowedOrigins: []string{"http://localhost:8080"},
		}),
		goauth.WithCookie(goauth.CookieConfig{Name: "goauth_session"}),
		goauth.WithMailer(&testMailer{}),
		goauth.WithSecret("0123456789abcdef0123456789abcdef"),
		goauth.WithEmail(goauth.EmailConfig{AllowHTTPURLs: true}),
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
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "expire@test.com",
		Password: "V@lidPswd1",
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
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "banned@test.com",
		Password: "V@lidPswd1",
		Name:     "Banned",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	// Ban the user via admin service
	if aerr := a.Services.Admin.BanUser(ctx, res.User.ID); aerr != nil {
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
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "logout@test.com",
		Password: "V@lidPswd1",
		Name:     "Logout",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	// Logout
	if aerr = a.Services.Auth.Logout(ctx, res.Session.ID); aerr != nil {
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
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "getsession@test.com",
		Password: "V@lidPswd1",
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
		}),
		goauth.WithSecurity(goauth.SecurityConfig{
			TokenTTL:       1 * time.Millisecond,
			AllowedOrigins: []string{"http://localhost:8080"},
		}),
		goauth.WithCookie(goauth.CookieConfig{Name: "goauth_session"}),
		goauth.WithMailer(&testMailer{}),
		goauth.WithSecret("0123456789abcdef0123456789abcdef"),
		goauth.WithEmail(goauth.EmailConfig{AllowHTTPURLs: true}),
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
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "expire-get@test.com",
		Password: "V@lidPswd1",
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
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "banned-get@test.com",
		Password: "V@lidPswd1",
		Name:     "BannedGet",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	// Ban the user
	if aerr = a.Services.Admin.BanUser(ctx, res.User.ID); aerr != nil {
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
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "role-check@test.com",
		Password: "V@lidPswd1",
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
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "revoked-get@test.com",
		Password: "V@lidPswd1",
		Name:     "RevokedGet",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	// Logout (revokes session)
	if aerr = a.Services.Auth.Logout(ctx, res.Session.ID); aerr != nil {
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

	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "grace@example.com",
		Password: "V@lidPswd1",
		Name:     "Grace",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if res.RefreshToken == "" {
		t.Fatal("expected refresh token after register")
	}

	// First refresh: should succeed and return new tokens
	session2, rawToken2, refresh2, err := a.Services.Session.RefreshSession(ctx, res.RefreshToken)
	if err != nil {
		t.Fatalf("first refresh failed: %v", err)
	}
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
	user, session, aerr := a.Services.Auth.ValidateSession(ctx, rawToken2)
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
	_, _, _, err = a.Services.Session.RefreshSession(ctx, res.RefreshToken)
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
	_, _, aerr = a.Services.Auth.ValidateSession(ctx, rawToken2)
	if aerr == nil {
		t.Fatal("expected session to be revoked after reuse detection")
	}

	// New refresh token (refresh2) should also be dead (session revoked)
	_, _, _, err = a.Services.Session.RefreshSession(ctx, refresh2)
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
	res, aerr := a.Register(ctx, goauth.RegisterInput{
		Email:    "audit@example.com",
		Password: "V@lidPswd1",
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
	if _, aerr := a.Login(ctx, goauth.LoginInput{
		Email:     "audit@example.com",
		Password:  "V@lidPswd1",
		UserAgent: "TestAgent/1.0",
	}); aerr != nil {
		t.Fatal(aerr)
	}

	var events []port.AuditLogEntry
	var total int
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for {
		events, total, err = a.Services.AuditLog.List(ctx, port.AuditLogFilter{Limit: 50})
		if err != nil {
			t.Fatalf("audit log list must not fail on NULL json columns: %v", err)
		}
		if total > 0 {
			break
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if total == 0 || len(events) == 0 {
		t.Fatal("expected audit events to be recorded")
	}
	// GetByID must also survive NULL columns.
	for _, e := range events {
		got, err := a.Services.AuditLog.GetByID(ctx, e.ID)
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
	searched, _, err := a.Services.AuditLog.List(ctx, port.AuditLogFilter{Limit: 50, Search: &search})
	if err != nil {
		t.Fatalf("search filter must not fail: %v", err)
	}
	if len(searched) == 0 {
		deadline = time.Now().Add(5 * time.Second)
		for len(searched) == 0 && !time.Now().After(deadline) {
			time.Sleep(50 * time.Millisecond)
			searched, _, err = a.Services.AuditLog.List(ctx, port.AuditLogFilter{Limit: 50, Search: &search})
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
	typed, _, err := a.Services.AuditLog.List(ctx, port.AuditLogFilter{Limit: 50, Type: &loginType})
	if err != nil {
		t.Fatalf("event-type filter must not fail: %v", err)
	}
	if len(typed) == 0 {
		deadline = time.Now().Add(5 * time.Second)
		for len(typed) == 0 && !time.Now().After(deadline) {
			time.Sleep(50 * time.Millisecond)
			typed, _, err = a.Services.AuditLog.List(ctx, port.AuditLogFilter{Limit: 50, Type: &loginType})
			if err != nil {
				t.Fatalf("event-type filter must not fail: %v", err)
			}
		}
	}
	if len(typed) == 0 {
		rows, _ := db.Query("SELECT event_type, user_agent FROM audit_log")
		defer rows.Close()
		for rows.Next() {
			var et, ua string
			_ = rows.Scan(&et, &ua)
			t.Logf("stored event: type=%s ua=%q", et, ua)
		}
		t.Fatal("expected login.success audit events to be returned")
	}
}

// TestMount_BakesInCORS verifies Mount wires the CORS middleware into every
// mounted handler so consumers don't need to wrap the mux with
// Auth.Middleware.CORS themselves.
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
