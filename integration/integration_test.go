package integration_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/service"
	_ "modernc.org/sqlite"
)

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

func (m *testMailer) Send(_ context.Context, _, _, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bodies = append(m.bodies, body)
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
	db, err := sql.Open("sqlite", f.Name())
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

func testConfig(db *sql.DB, mailer goauth.Mailer) goauth.Config {
	return goauth.Config{
		AppName: "TestApp",
		Database: goauth.DatabaseConfig{
			DB:     db,
			Driver: "sqlite3",
		},
		AdminEmails:        []string{"admin@test.com"},
		BcryptCost:         4,
		TokenLength:        32,
		SessionTTL:         1 * time.Hour,
		TokenTTL:           1 * time.Hour,
		InviteTTL:          1 * time.Hour,
		VerificationCodeTTL: 1 * time.Hour,
		Mailer:             mailer,
	}
}

func openAuth(t *testing.T, db *sql.DB, mailer goauth.Mailer) *goauth.Auth {
	t.Helper()
	a, err := goauth.New(testConfig(db, mailer))
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestMigrations_CreateTables(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, nil)
	a.Close()

	for _, name := range []string{"users", "sessions", "verification_tokens", "invites"} {
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
	resetToken := extractCodeAfter(body, "Your password reset code: ")
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
		Email:       "admin@test.com",
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
	if invite.RawCode == "" {
		t.Error("invite.RawCode should be populated on creation")
	}

	// DB stores hashed code, not raw
	var codeHash string
	if err := db.QueryRow("SELECT code FROM invites WHERE id = ?", invite.ID).Scan(&codeHash); err != nil {
		t.Fatal(err)
	}
	if codeHash == invite.RawCode {
		t.Error("raw invite code stored in invites.code")
	}
	if codeHash != sha256Hex(invite.RawCode) {
		t.Error("invite code hash does not match SHA256(raw code)")
	}

	// Complete registration
	regResult, aerr := a.CompleteInviteRegistration(ctx, goauth.CompleteInviteInput{
		Code:            invite.RawCode,
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
	cfg := testConfig(db, &testMailer{})
	cfg.SessionTTL = 1 * time.Millisecond // expire immediately
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
	cfg := testConfig(db, &testMailer{})
	cfg.SessionTTL = 1 * time.Millisecond
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
