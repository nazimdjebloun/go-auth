package integration_test

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/port"
)

// mysqlTestDSN returns the DSN for a live MySQL server, or "" when unset so
// the caller skips. Every MySQL behavioral test is env-gated the same way the
// Postgres ones are: absent DSN means skip, never fail.
func mysqlTestDSN() string {
	return os.Getenv("GOAUTH_MYSQL_TEST_DSN")
}

// newMySQLTestAuth mirrors newPostgresTestAuth: same short-lived bcrypt cost,
// session TTLs, and origins so behavior — not configuration — is what the two
// drivers are compared on.
func newMySQLTestAuth(db *sql.DB, mailer port.Mailer) (*goauth.Auth, error) {
	cfg, err := goauth.NewConfig(
		goauth.WithBcryptCost(4),
		goauth.WithApp(goauth.AppConfig{
			Name:    "TestAppMySQL",
			BaseURL: "http://localhost:8080",
			Database: goauth.DatabaseConfig{
				DB:     db,
				Driver: goauth.DriverMySQL,
			},
		}),
		goauth.WithSession(goauth.SessionConfig{
			TTL:             1 * time.Hour,
			IdleTTL:         1 * time.Hour,
			RefreshTokenTTL: 1 * time.Hour,
			TokenTTL:        1 * time.Hour,
			// Off, so a reused refresh token is detected immediately rather
			// than tolerated through the default grace window — the reuse
			// path is exactly what the rotation test below must observe.
			GraceWindow: goauth.Duration(0),
		}),
		goauth.WithSecurity(goauth.SecurityConfig{
			AllowHTTPURLs:  goauth.AllowPlaintextEmailLinks(),
			AllowedOrigins: []string{"http://localhost:8080"},
		}),
		goauth.WithCookie(goauth.CookieConfig{Name: "goauth_session"}),
		goauth.WithMailer(mailer),
		goauth.WithSecret("0123456789abcdef0123456789abcdef"),
	)
	if err != nil {
		return nil, err
	}
	return goauth.New(cfg)
}

// mysqlTestDB creates a dedicated goauth_test database (isolated from the
// database named in the DSN), applies the MySQL schema through the same
// SplitSQL pipeline the CLI uses, and returns a connection plus a cleanup
// that drops the database entirely.
func mysqlTestDB(t *testing.T, dsn string) (*sql.DB, func()) {
	t.Helper()

	cfg, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("mysql.ParseDSN: %v", err)
	}

	// Connect without a default database to create the test database.
	cfg.DBName = ""
	adminDB, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatalf("open admin db: %v", err)
	}
	if _, err := adminDB.Exec("CREATE DATABASE IF NOT EXISTS `goauth_test`"); err != nil {
		checkTestErrors(t).noError(adminDB.Close())
		t.Fatalf("CREATE DATABASE: %v", err)
	}
	checkTestErrors(t).noError(adminDB.Close())

	cfg.DBName = "goauth_test"
	testDB, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}

	cleanup := func() {
		checkTestErrors(t).noError(testDB.Close())
		cfg.DBName = ""
		if cleanupDB, err := sql.Open("mysql", cfg.FormatDSN()); err == nil {
			_, _ = cleanupDB.Exec("DROP DATABASE IF EXISTS `goauth_test`")
			checkTestErrors(t).noError(cleanupDB.Close())
		}
	}
	return testDB, cleanup
}

// TestMySQL_RegisterAndValidateSession covers the core write/read paths on
// real MySQL: registration issues a session whose token is stored hash-only,
// validation resolves user and session, logout revokes, and the revoked
// token no longer validates.
func TestMySQL_RegisterAndValidateSession(t *testing.T) {
	dsn := mysqlTestDSN()
	if dsn == "" {
		t.Skip("GOAUTH_MYSQL_TEST_DSN not set")
	}

	db, cleanup := mysqlTestDB(t, dsn)
	defer cleanup()

	mailer := &testMailer{}
	migrateDB(t, db, "mysql")
	a, err := newMySQLTestAuth(db, mailer)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	ctx := context.Background()

	res, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "alice@mysql.test",
		Password: validTestPassword(),
		Name:     "Alice",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}
	if res.SessionToken == "" {
		t.Fatal("session token missing after register")
	}

	user, session, aerr := a.Services().Auth.ValidateSession(ctx, res.SessionToken)
	if aerr != nil {
		t.Fatal("ValidateSession:", aerr)
	}
	if user.ID != res.User.ID || session.ID != res.Session.ID {
		t.Error("user or session ID mismatch")
	}

	// The stored hash must be SHA-256 of the raw token, never the raw token.
	var tokHash string
	if err := db.QueryRow("SELECT token_hash FROM sessions WHERE id = ?", session.ID).Scan(&tokHash); err != nil {
		t.Fatal(err)
	}
	if tokHash != sha256Hex(res.SessionToken) {
		t.Error("session token hash mismatch")
	}

	if aerr := a.Services().Auth.Logout(ctx, session.ID); aerr != nil {
		t.Fatal(aerr)
	}
	if _, _, aerr = a.Services().Auth.ValidateSession(ctx, res.SessionToken); aerr == nil {
		t.Error("expected error after session revoked")
	}
}

// TestMySQL_RefreshRotation covers the driver-specific regression fixed in
// 42101de: on MySQL, rotation must preserve previous_refresh_token_hash from
// the pre-rotation refresh hash, dead outside the grace window (disabled
// here), while the rotated pair keeps working.
func TestMySQL_RefreshRotation(t *testing.T) {
	dsn := mysqlTestDSN()
	if dsn == "" {
		t.Skip("GOAUTH_MYSQL_TEST_DSN not set")
	}

	db, cleanup := mysqlTestDB(t, dsn)
	defer cleanup()

	mailer := &testMailer{}
	migrateDB(t, db, "mysql")
	a, err := newMySQLTestAuth(db, mailer)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	ctx := context.Background()

	res, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "bob@mysql.test",
		Password: validTestPassword(),
		Name:     "Bob",
	})
	if aerr != nil {
		t.Fatal(aerr)
	}

	rotated, aerr := a.Services().Session.RefreshSession(ctx, res.RefreshToken)
	if aerr != nil {
		t.Fatal("first refresh:", aerr)
	}

	var prevHash, curHash string
	if err := db.QueryRow("SELECT prev_refresh_token_hash, refresh_token_hash FROM sessions WHERE id = ?", rotated.Session.ID).Scan(&prevHash, &curHash); err != nil {
		t.Fatal(err)
	}
	if prevHash != sha256Hex(res.RefreshToken) {
		t.Error("prev_refresh_token_hash not preserved across MySQL rotation")
	}
	if curHash != sha256Hex(rotated.RefreshToken) {
		t.Error("refresh_token_hash not updated to the new token")
	}

	// Old token must be dead outside any grace window (grace is disabled).
	if _, aerr := a.Services().Session.RefreshSession(ctx, res.RefreshToken); aerr == nil {
		t.Error("expected reused pre-rotation refresh token to be rejected")
	}

	if _, _, aerr := a.Services().Auth.ValidateSession(ctx, rotated.SessionToken); aerr != nil {
		t.Fatal("ValidateSession after rotation:", aerr)
	}
	if _, aerr := a.Services().Session.RefreshSession(ctx, rotated.RefreshToken); aerr != nil {
		t.Fatal("second refresh with rotated token:", aerr)
	}
}

// TestMySQL_PasswordReset mirrors the Postgres reset test: forgot-password
// sends a real token-bearing mail, the code resets the password, and login
// with the new password succeeds.
func TestMySQL_PasswordReset(t *testing.T) {
	dsn := mysqlTestDSN()
	if dsn == "" {
		t.Skip("GOAUTH_MYSQL_TEST_DSN not set")
	}

	db, cleanup := mysqlTestDB(t, dsn)
	defer cleanup()

	mailer := &testMailer{}
	migrateDB(t, db, "mysql")
	a, err := newMySQLTestAuth(db, mailer)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	ctx := context.Background()

	if _, aerr := a.Register(ctx, api.RegisterInput{
		Email:    "admin@mysql.test",
		Password: validTestPassword(),
		Name:     "Admin",
	}); aerr != nil {
		t.Fatal(aerr)
	}

	if aerr := a.Services().Password.ForgotPassword(ctx, api.ForgotPasswordInput{
		Email: "admin@mysql.test",
	}); aerr != nil {
		t.Fatal(aerr)
	}

	resetToken := mailer.waitForResetToken(t)
	if resetToken == "" {
		t.Fatal("could not extract reset token from email")
	}

	if aerr := a.Services().Password.ResetPassword(ctx, api.ResetPasswordInput{
		Code:        resetToken,
		NewPassword: "NewP@sswd2",
	}); aerr != nil {
		t.Fatal(aerr)
	}

	if _, aerr := a.Services().Auth.Login(ctx, api.LoginInput{
		Email:    "admin@mysql.test",
		Password: "NewP@sswd2",
	}); aerr != nil {
		t.Fatal("login with reset password failed:", aerr)
	}
}
