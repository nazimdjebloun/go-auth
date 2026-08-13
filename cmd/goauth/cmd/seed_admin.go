package cmd

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/hasher"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var seedAdminCmd = &cobra.Command{
	Use:   "seed-admin",
	Short: "Bootstrap the first admin account",
	Long: `Creates an admin user directly in the database — the only way to get a
first admin today short of a manual UPDATE statement.

Admin login always requires a working 2FA mailer, so this command sends a
real verification email before writing anything to the database (unless
--skip-mailer-check is passed). In --env dev with no SMTP flags given, a
log-only mailer is used instead of real SMTP.

Email is read from ADMIN_EMAIL, prompted for interactively, or the command
fails loud in non-interactive mode. Password works the same way via
ADMIN_PASSWORD, falling back to a strong auto-generated password printed
once.`,
	Args: cobra.NoArgs,
	Run:  runSeedAdminCmd,
}

func init() {
	seedAdminCmd.Flags().String("driver", "", "Database driver (postgres, sqlite, mysql)")
	seedAdminCmd.Flags().String("dsn", "", "Database DSN")
	seedAdminCmd.Flags().String("env", "", "Target environment: dev, staging, or prod")
	seedAdminCmd.Flags().Bool("non-interactive", false, "Disable TTY prompts; missing ADMIN_EMAIL is a hard error")
	seedAdminCmd.Flags().Bool("skip-mailer-check", false, "Skip sending a real verification email before creating the admin")
	seedAdminCmd.Flags().Bool("force", false, "Allow creating an admin even if one already exists")
	seedAdminCmd.Flags().String("smtp-host", "", "SMTP host (or SMTP_HOST)")
	seedAdminCmd.Flags().Int("smtp-port", 587, "SMTP port (or SMTP_PORT)")
	seedAdminCmd.Flags().String("smtp-from", "", "SMTP From address (or SMTP_FROM)")
	seedAdminCmd.Flags().String("smtp-user", "", "SMTP username (or SMTP_USER)")
	seedAdminCmd.Flags().String("smtp-pass", "", "SMTP password (or SMTP_PASS)")
	seedAdminCmd.Flags().String("smtp-tls", "starttls", "SMTP TLS mode: none, starttls, or implicit (or SMTP_TLS)")
	seedAdminCmd.MarkFlagRequired("driver")
	seedAdminCmd.MarkFlagRequired("dsn")
	seedAdminCmd.MarkFlagRequired("env")
	rootCmd.AddCommand(seedAdminCmd)
}

func runSeedAdminCmd(cmd *cobra.Command, args []string) {
	driver, _ := cmd.Flags().GetString("driver")
	dsn, _ := cmd.Flags().GetString("dsn")
	envFlag, _ := cmd.Flags().GetString("env")
	nonInteractive, _ := cmd.Flags().GetBool("non-interactive")
	skipMailerCheck, _ := cmd.Flags().GetBool("skip-mailer-check")
	force, _ := cmd.Flags().GetBool("force")

	env, err := parseEnvironment(envFlag)
	if err != nil {
		abort(err)
	}

	smtp := resolveSMTPConfig(cmd)

	isTTY := term.IsTerminal(int(os.Stdin.Fd()))

	email, err := resolveAdminEmail(os.Getenv("ADMIN_EMAIL"), nonInteractive, isTTY, promptLine)
	if err != nil {
		abort(err)
	}

	policy := domain.PasswordPolicy{MinLength: 8, RequireDigit: true}
	password, generated, err := resolveAdminPassword(os.Getenv("ADMIN_PASSWORD"), nonInteractive, isTTY, policy, promptHidden)
	if err != nil {
		abort(err)
	}

	mailer, err := resolveMailer(env, smtp, skipMailerCheck)
	if err != nil {
		abort(err)
	}
	if skipMailerCheck {
		fmt.Fprintln(os.Stderr, "WARNING: mailer check skipped — this admin may not be able to complete login if 2FA email delivery isn't actually working.")
	}

	sqlDriver := sqlDriverName(driver)
	db, err := sql.Open(sqlDriver, dsn)
	if err != nil {
		abort(fmt.Errorf("seed-admin: failed to connect: %w", err))
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		abort(fmt.Errorf("seed-admin: ping failed: %w", err))
	}

	repo := sqlstore.NewUserRepository(sqlstore.NewDB(db, sqlDriver))
	h := hasher.New(12)

	deps := seedAdminDeps{
		repo:   repo,
		mailer: mailer,
		hash:   h.Hash,
		now:    func() time.Time { return time.Now().UTC() },
		genID:  func() string { return uuid.New().String() },
	}
	params := seedAdminParams{
		email:           email,
		password:        password,
		force:           force,
		skipMailerCheck: skipMailerCheck,
	}

	if _, err := seedAdmin(context.Background(), params, deps); err != nil {
		abort(err)
	}

	fmt.Printf("goauth: admin account created: %s\n", email)
	if generated {
		fmt.Println("ONE-TIME — this will not be shown again")
		fmt.Println("Password:", password)
	}
}

func abort(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func parseEnvironment(v string) (goauth.Environment, error) {
	switch v {
	case "dev":
		return goauth.EnvironmentDev, nil
	case "staging":
		return goauth.EnvironmentStaging, nil
	case "prod":
		return goauth.EnvironmentProd, nil
	default:
		return "", fmt.Errorf("seed-admin: --env must be one of dev, staging, or prod, got %q", v)
	}
}

// ─── Email/password resolution ─────────────────────────────

// resolveAdminEmail follows: env var wins; otherwise a TTY prompt unless
// non-interactive mode or no TTY is available, in which case it fails loud
// rather than hanging on stdin that will never come.
func resolveAdminEmail(envEmail string, nonInteractive, isTTY bool, prompt func(label string) (string, error)) (string, error) {
	if envEmail != "" {
		return envEmail, nil
	}
	if nonInteractive || !isTTY {
		return "", errors.New("seed-admin: ADMIN_EMAIL is required in non-interactive mode")
	}
	email, err := prompt("Admin email: ")
	if err != nil {
		return "", fmt.Errorf("seed-admin: reading admin email: %w", err)
	}
	email = strings.TrimSpace(email)
	if email == "" {
		return "", errors.New("seed-admin: ADMIN_EMAIL is required in non-interactive mode")
	}
	return email, nil
}

// resolveAdminPassword follows the same shape as resolveAdminEmail,
// independently: env var wins (validated against policy); otherwise a hidden
// prompt when interactive, falling back to auto-generation on empty input;
// auto-generate outright when non-interactive or no TTY.
func resolveAdminPassword(envPassword string, nonInteractive, isTTY bool, policy domain.PasswordPolicy, promptHiddenFn func(label string) (string, error)) (password string, generated bool, err error) {
	if envPassword != "" {
		if err := policy.Validate(envPassword); err != nil {
			var authErr *domain.AuthError
			errors.As(err, &authErr)
			return "", false, fmt.Errorf("seed-admin: ADMIN_PASSWORD does not meet the password policy: %s", authErr.Message)
		}
		return envPassword, false, nil
	}
	if nonInteractive || !isTTY {
		pw, genErr := generatePassword()
		return pw, true, genErr
	}
	typed, promptErr := promptHiddenFn("Admin password (leave empty to auto-generate): ")
	if promptErr != nil {
		return "", false, fmt.Errorf("seed-admin: reading admin password: %w", promptErr)
	}
	typed = strings.TrimSpace(typed)
	if typed == "" {
		pw, genErr := generatePassword()
		return pw, true, genErr
	}
	if err := policy.Validate(typed); err != nil {
		var authErr *domain.AuthError
		errors.As(err, &authErr)
		return "", false, fmt.Errorf("seed-admin: password does not meet the password policy: %s", authErr.Message)
	}
	return typed, false, nil
}

const passwordGenLength = 24

// generatePassword produces a strong random password that satisfies any
// reasonable PasswordPolicy: it guarantees at least one lowercase, uppercase,
// digit, and special character rather than leaving that to chance.
func generatePassword() (string, error) {
	classes := []string{
		"abcdefghijklmnopqrstuvwxyz",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"0123456789",
		"!@#$%^&*-_=+",
	}
	all := strings.Join(classes, "")

	pw := make([]byte, 0, passwordGenLength)
	for _, class := range classes {
		ch, err := randChar(class)
		if err != nil {
			return "", err
		}
		pw = append(pw, ch)
	}
	for len(pw) < passwordGenLength {
		ch, err := randChar(all)
		if err != nil {
			return "", err
		}
		pw = append(pw, ch)
	}

	for i := len(pw) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return "", err
		}
		j := jBig.Int64()
		pw[i], pw[j] = pw[j], pw[i]
	}
	return string(pw), nil
}

func randChar(charset string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
	if err != nil {
		return 0, err
	}
	return charset[n.Int64()], nil
}

func promptLine(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	var line string
	if _, err := fmt.Scanln(&line); err != nil {
		return "", err
	}
	return line, nil
}

func promptHidden(label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ─── Mailer resolution ──────────────────────────────────────

type smtpConfig struct {
	Host string
	Port int
	From string
	User string
	Pass string
	TLS  goauth.TLSMode
}

func resolveSMTPConfig(cmd *cobra.Command) smtpConfig {
	port, _ := strconv.Atoi(flagOrEnv(cmd, "smtp-port", "SMTP_PORT"))
	return smtpConfig{
		Host: flagOrEnv(cmd, "smtp-host", "SMTP_HOST"),
		Port: port,
		From: flagOrEnv(cmd, "smtp-from", "SMTP_FROM"),
		User: flagOrEnv(cmd, "smtp-user", "SMTP_USER"),
		Pass: flagOrEnv(cmd, "smtp-pass", "SMTP_PASS"),
		TLS:  parseTLSMode(flagOrEnv(cmd, "smtp-tls", "SMTP_TLS")),
	}
}

func parseTLSMode(v string) goauth.TLSMode {
	switch v {
	case "implicit":
		return goauth.TLSImplicit
	case "none":
		return goauth.TLSNone
	default:
		return goauth.TLSStart
	}
}

// flagOrEnv resolves a string setting: an explicitly-passed flag wins, then
// the environment variable, then the flag's default value.
func flagOrEnv(cmd *cobra.Command, flagName, envName string) string {
	if cmd.Flags().Changed(flagName) {
		v, _ := cmd.Flags().GetString(flagName)
		return v
	}
	if v := os.Getenv(envName); v != "" {
		return v
	}
	v, _ := cmd.Flags().GetString(flagName)
	return v
}

// resolveMailer decides which port.Mailer to build:
//   - --env dev with no SMTP fields given → a log-only mailer
//   - SMTP fields given → a real SMTP mailer
//   - no SMTP fields and not dev: a hard error, unless skipCheck is set, in
//     which case there is nothing to verify and (nil, nil) is returned.
func resolveMailer(env goauth.Environment, smtp smtpConfig, skipCheck bool) (port.Mailer, error) {
	hasSMTP := smtp.Host != "" || smtp.From != ""

	if env == goauth.EnvironmentDev && !hasSMTP {
		return goauth.NewLogMailer(nil), nil
	}

	if !hasSMTP {
		if skipCheck {
			return nil, nil
		}
		return nil, fmt.Errorf("seed-admin: --env %s requires SMTP configuration (or --skip-mailer-check)", env)
	}

	return goauth.NewSMTPMailer(goauth.EmailConfig{
		Host:    smtp.Host,
		Port:    smtp.Port,
		From:    smtp.From,
		User:    smtp.User,
		Pass:    smtp.Pass,
		TLSMode: smtp.TLS,
	})
}

// ─── Core seeding logic ─────────────────────────────────────

type seedAdminDeps struct {
	repo   port.UserRepository
	mailer port.Mailer // nil only when skipMailerCheck left no mailer to build
	hash   func(string) (string, error)
	now    func() time.Time
	genID  func() string
}

type seedAdminParams struct {
	email           string
	password        string
	force           bool
	skipMailerCheck bool
}

// seedAdmin performs the duplicate checks, mailer verification, and user
// creation, in that order — mailer verification always runs (when not
// skipped) before any database write, so a failed send never leaves a
// half-seeded, unreachable admin behind.
func seedAdmin(ctx context.Context, p seedAdminParams, d seedAdminDeps) (*domain.User, error) {
	existing, err := d.repo.GetByEmail(ctx, p.email)
	if err != nil {
		return nil, fmt.Errorf("seed-admin: checking existing user: %w", err)
	}
	if existing != nil {
		return nil, fmt.Errorf("seed-admin: a user with email %q already exists", p.email)
	}

	if !p.force {
		adminRole := domain.RoleAdmin
		_, total, err := d.repo.List(ctx, port.UserFilter{Role: &adminRole, Limit: 1})
		if err != nil {
			return nil, fmt.Errorf("seed-admin: checking for existing admin: %w", err)
		}
		if total > 0 {
			return nil, errors.New("seed-admin: an admin account already exists; pass --force to create another")
		}
	}

	if !p.skipMailerCheck {
		if d.mailer == nil {
			return nil, errors.New("seed-admin: no mailer configured")
		}
		subject, html, text := adminAccountCreatedEmail()
		if err := d.mailer.Send(ctx, p.email, subject, html, text); err != nil {
			return nil, fmt.Errorf("seed-admin: mailer verification failed, nothing was written to the database: %w", err)
		}
	}

	hash, err := d.hash(p.password)
	if err != nil {
		return nil, fmt.Errorf("seed-admin: hashing password: %w", err)
	}

	now := d.now()
	user := &domain.User{
		ID:           d.genID(),
		Email:        p.email,
		PasswordHash: &hash,
		Role:         domain.RoleAdmin,
		IsVerified:   true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := d.repo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("seed-admin: creating user: %w", err)
	}
	return user, nil
}
