package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/token"
)

type signupUsersWithoutGlobalGuard struct{ port.UserRepository }

func (signupUsersWithoutGlobalGuard) WithAdminGuard(context.Context, func(context.Context) error) error {
	return errors.New("ordinary signup must not lock all users")
}

type signupStateWithoutExclusiveLock struct{ port.AppAuthorizationState }

func (signupStateWithoutExclusiveLock) LockAppState(context.Context) error {
	return errors.New("ordinary signup must not exclusively lock app state")
}

func appSignupAction(t *testing.T, f appFixture, mode, email string) func(context.Context) error {
	t.Helper()
	users := signupUsersWithoutGlobalGuard{UserRepository: f.users}
	tokens := sqlstore.NewTokenRepository(f.db)
	sessions := sqlstore.NewSessionRepository(f.db)
	cfg := defaultTestConfig()
	cfg.AppPermissions, cfg.DisableAdminTwoFactor = f.s, true
	switch mode {
	case "password":
		svc := NewAuthService(
			f.db, users, sessions, tokens, &testutil.MockHasher{}, token.New(),
			nil, cfg, f.s.sessionSvc, nil, nil,
		)
		return func(ctx context.Context) error {
			_, err := svc.Register(ctx, api.RegisterInput{
				Email: email, Name: "Signup", Password: "Passw0rd!",
			})
			return err
		}
	case "invite":
		invites := sqlstore.NewInviteRepository(f.db)
		raw := uuid.NewString()
		now := time.Now().UTC()
		if err := invites.Create(t.Context(), &domain.Invite{
			ID: uuid.NewString(), Email: email, Code: hashToken(raw),
			Status: domain.InvitePending, CreatedBy: f.admin.UserID,
			CreatedAt: now, ExpiresAt: now.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		svc := NewInviteService(
			users, sessions, invites, &testutil.MockHasher{}, token.New(), nil,
			f.db, cfg, f.s.sessionSvc, nil,
		)
		return func(ctx context.Context) error {
			_, err := svc.CompleteInviteRegistration(ctx, api.CompleteInviteInput{
				Code: raw, Name: "Signup", Password: "Passw0rd!", ConfirmPassword: "Passw0rd!",
			})
			return err
		}
	case "oauth":
		raw, verifier := uuid.NewString(), "verifier"
		now := time.Now().UTC()
		if err := tokens.Create(t.Context(), &domain.VerificationToken{
			ID: uuid.NewString(), TokenHash: hashToken(raw), Type: domain.TokenOAuthState,
			ExpiresAt: now.Add(time.Minute), CodeVerifier: &verifier, CreatedAt: now,
		}); err != nil {
			t.Fatal(err)
		}
		provider := &stubOAuthProvider{
			name: "test", profile: oauthTestProfile("test", email, email),
		}
		svc := NewOAuthService(
			map[string]port.OAuthProvider{"test": provider},
			sqlstore.NewProviderAccountRepository(f.db), users, tokens,
			&testutil.MockHasher{}, token.New(), f.s.sessionSvc, nil, f.db,
			OAuthServiceConfig{EnableOAuth: true, DisableAdminTwoFactor: true, AppPermissions: f.s},
		)
		return func(ctx context.Context) error {
			_, err := svc.Callback(ctx, api.OAuthCallbackInput{
				Provider: "test", Code: "code", State: raw, BrowserState: raw,
			})
			return err
		}
	default:
		t.Fatalf("unknown signup mode %q", mode)
		return nil
	}
}

func TestAppSignupAvoidsGlobalAuthorizationLocks(t *testing.T) {
	for _, mode := range []string{"password", "invite", "oauth"} {
		t.Run(mode, func(t *testing.T) {
			f := newAppFixture(t)
			f.s.users = signupUsersWithoutGlobalGuard{UserRepository: f.users}
			f.s.state = signupStateWithoutExclusiveLock{AppAuthorizationState: f.repo}
			before, err := f.repo.AppStateRevision(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			email := mode + "@signup.example"
			if err := appSignupAction(t, f, mode, email)(t.Context()); err != nil {
				t.Fatal(err)
			}
			user, err := f.users.GetByEmail(t.Context(), email)
			if err != nil || user == nil || user.AppRoleID == nil || user.AppRoleAssignmentRevision != 1 {
				t.Fatalf("committed default assignment: %+v %v", user, err)
			}
			role, err := f.repo.RoleByID(t.Context(), *user.AppRoleID)
			if err != nil || role == nil || role.Slug != "user" {
				t.Fatalf("default role: %+v %v", role, err)
			}
			after, err := f.repo.AppStateRevision(t.Context())
			if err != nil || after != before {
				t.Fatalf("signup changed authorization state: %d -> %d, %v", before, after, err)
			}
		})
	}
}

func TestAppSignupBaselineFailureRollsBack(t *testing.T) {
	for _, mode := range []string{"password", "invite", "oauth"} {
		for _, failure := range []string{"uninitialized", "missing", "disabled", "admin"} {
			t.Run(mode+"/"+failure, func(t *testing.T) {
				f := newAppFixture(t)
				want := domain.ErrAppRoleNotFound
				switch failure {
				case "uninitialized":
					if _, err := f.db.ExecContext(t.Context(), "DELETE FROM app_authorization_state"); err != nil {
						t.Fatal(err)
					}
					want = domain.ErrAppPermissionsNotInitialized
				case "missing":
					f.s.config.DefaultRoleSlug = "missing"
				case "disabled":
					role := f.role(t, "disabled-default")
					role.IsEnabled = false
					if changed, err := f.repo.UpdateAppRole(t.Context(), role, role.Revision); err != nil || !changed {
						t.Fatalf("disable default fixture: %v %v", changed, err)
					}
					f.s.config.DefaultRoleSlug = role.Slug
				case "admin":
					f.s.config.DefaultRoleSlug = "admin"
				}
				email := failure + "@rollback.example"
				if err := appSignupAction(t, f, mode, email)(t.Context()); !errors.Is(err, want) {
					t.Fatalf("expected %v, got %v", want, err)
				}
				user, err := f.users.GetByEmail(t.Context(), email)
				if err != nil || user != nil {
					t.Fatalf("failed signup left account: %+v %v", user, err)
				}
				if mode == "invite" {
					invite, err := sqlstore.NewInviteRepository(f.db).GetByEmail(t.Context(), email)
					if err != nil || invite == nil || invite.Status != domain.InvitePending {
						t.Fatalf("failed signup consumed invitation: %+v %v", invite, err)
					}
				}
				if mode == "oauth" {
					link, err := sqlstore.NewProviderAccountRepository(f.db).GetByProvider(t.Context(), "test", email)
					if err != nil || link != nil {
						t.Fatalf("failed signup left provider link: %+v %v", link, err)
					}
				}
			})
		}
	}
}

type signupStaleInviteReader struct {
	port.InviteRepository
	snapshot domain.Invite
}

func (r signupStaleInviteReader) GetByCode(context.Context, string) (*domain.Invite, error) {
	snapshot := r.snapshot
	return &snapshot, nil
}

func TestAppSignupInviteDuplicatePreservesClaimError(t *testing.T) {
	for _, consumed := range []bool{false, true} {
		name := "email_exists"
		if consumed {
			name = "another_redemption_won"
		}
		t.Run(name, func(t *testing.T) {
			f := newAppFixture(t)
			account := f.account(t)
			user, err := f.users.GetByID(t.Context(), account.UserID)
			if err != nil {
				t.Fatal(err)
			}
			invites := sqlstore.NewInviteRepository(f.db)
			raw := uuid.NewString()
			now := time.Now().UTC()
			snapshot := domain.Invite{
				ID: uuid.NewString(), Email: user.Email, Code: hashToken(raw),
				Status: domain.InvitePending, CreatedBy: f.admin.UserID,
				CreatedAt: now, ExpiresAt: now.Add(time.Hour),
			}
			if err := invites.Create(t.Context(), &snapshot); err != nil {
				t.Fatal(err)
			}
			if consumed {
				if claimed, err := invites.ClaimInvite(t.Context(), snapshot.Code, now); err != nil || !claimed {
					t.Fatalf("winning claim: %v %v", claimed, err)
				}
			}
			cfg := defaultTestConfig()
			cfg.AppPermissions, cfg.DisableAdminTwoFactor = f.s, true
			svc := NewInviteService(
				signupUsersWithoutGlobalGuard{UserRepository: f.users},
				sqlstore.NewSessionRepository(f.db),
				signupStaleInviteReader{InviteRepository: invites, snapshot: snapshot},
				&testutil.MockHasher{}, token.New(), nil, f.db, cfg, f.s.sessionSvc, nil,
			)
			_, err = svc.CompleteInviteRegistration(t.Context(), api.CompleteInviteInput{
				Code: raw, Name: "Signup", Password: "Passw0rd!", ConfirmPassword: "Passw0rd!",
			})
			want := domain.ErrEmailAlreadyExists
			if consumed {
				want = domain.ErrInviteAlreadyUsed
			}
			if !errors.Is(err, want) {
				t.Fatalf("expected %v, got %v", want, err)
			}
			current, err := invites.GetByID(t.Context(), snapshot.ID)
			wantStatus := domain.InvitePending
			if consumed {
				wantStatus = domain.InviteAccepted
			}
			if err != nil || current == nil || current.Status != wantStatus {
				t.Fatalf("losing redemption changed invite: %+v %v", current, err)
			}
		})
	}
}

func TestAppSignupInviteClaimFailureRollsBack(t *testing.T) {
	f := newAppFixture(t)
	invites := sqlstore.NewInviteRepository(f.db)
	raw := uuid.NewString()
	now := time.Now().UTC()
	snapshot := domain.Invite{
		ID: uuid.NewString(), Email: "revoked@signup.example", Code: hashToken(raw),
		Status: domain.InvitePending, CreatedBy: f.admin.UserID,
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := invites.Create(t.Context(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if changed, err := invites.Revoke(t.Context(), snapshot.ID); err != nil || !changed {
		t.Fatalf("invalidate claim: %v %v", changed, err)
	}
	cfg := defaultTestConfig()
	cfg.AppPermissions, cfg.DisableAdminTwoFactor = f.s, true
	svc := NewInviteService(
		signupUsersWithoutGlobalGuard{UserRepository: f.users},
		sqlstore.NewSessionRepository(f.db),
		signupStaleInviteReader{InviteRepository: invites, snapshot: snapshot},
		&testutil.MockHasher{}, token.New(), nil, f.db, cfg, f.s.sessionSvc, nil,
	)
	_, err := svc.CompleteInviteRegistration(t.Context(), api.CompleteInviteInput{
		Code: raw, Name: "Signup", Password: "Passw0rd!", ConfirmPassword: "Passw0rd!",
	})
	if !errors.Is(err, domain.ErrInviteAlreadyUsed) {
		t.Fatalf("invalid claim: %v", err)
	}
	user, err := f.users.GetByEmail(t.Context(), snapshot.Email)
	if err != nil || user != nil {
		t.Fatalf("failed claim left provisional account: %+v %v", user, err)
	}
	current, err := invites.GetByID(t.Context(), snapshot.ID)
	if err != nil || current == nil || current.Status != domain.InviteRevoked {
		t.Fatalf("failed claim changed invitation: %+v %v", current, err)
	}
}

func appSignupSecondPool(t *testing.T, f appFixture) appFixture {
	t.Helper()
	raw := testdb.SecondPool(t, f.db.DB)
	db := sqlstore.NewDB(raw, testdb.Driver(raw))
	users := sqlstore.NewUserRepository(db).WithAppPermissions()
	repo := sqlstore.NewAppPermissionsRepository(db)
	sessions := sqlstore.NewSessionRepository(db)
	sessionSvc := NewSessionService(db, sessions, token.New(), DefaultSessionConfig())
	svc := NewAppPermissionsService(
		db, users, sessions, sessionSvc, repo, repo, repo, repo, f.s.config,
	)
	return appFixture{s: svc, db: db, users: users, repo: repo, admin: f.admin}
}

type signupSharedRoleSignal struct {
	port.AppRoleStore
	reached chan struct{}
}

func (r signupSharedRoleSignal) RoleBySlugForShare(ctx context.Context, slug string) (*domain.AppRole, error) {
	close(r.reached)
	return r.AppRoleStore.RoleBySlugForShare(ctx, slug)
}

func TestPostgres_AppSignupRoleLocksAcrossPools(t *testing.T) {
	if testdb.Selected() != "postgres" {
		t.Skip("requires selected PostgreSQL backend")
	}
	testAppSignupRoleLocksAcrossPools(t)
}

func TestMySQL_AppSignupRoleLocksAcrossPools(t *testing.T) {
	if testdb.Selected() != "mysql" {
		t.Skip("requires selected MySQL backend")
	}
	testAppSignupRoleLocksAcrossPools(t)
}

func testAppSignupRoleLocksAcrossPools(t *testing.T) {
	t.Helper()
	t.Run("management_state_does_not_block_signup", func(t *testing.T) {
		f := newAppFixture(t)
		other := appSignupSecondPool(t, f)
		signup := appSignupAction(t, other, "password", "state-lock@signup.example")
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		if err := f.db.WithTx(ctx, func(txCtx context.Context) error {
			if err := f.repo.LockAppState(txCtx); err != nil {
				return err
			}
			return signup(ctx)
		}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("shared_default_allows_another_signup", func(t *testing.T) {
		f := newAppFixture(t)
		other := appSignupSecondPool(t, f)
		signup := appSignupAction(t, other, "password", "shared-lock@signup.example")
		now := time.Now().UTC()
		first := &domain.User{
			ID: uuid.NewString(), Email: "first@signup.example", Role: domain.RoleUser,
			CreatedAt: now, UpdatedAt: now,
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		if err := f.db.WithTx(ctx, func(txCtx context.Context) error {
			if err := f.users.Create(txCtx, first); err != nil {
				return err
			}
			if err := f.s.AssignBaseline(txCtx, first); err != nil {
				return err
			}
			// An independent writer cannot update/delete the default while this
			// transaction holds it, but another signup must finish successfully.
			lockErr := other.db.WithTx(ctx, func(lockCtx context.Context) error {
				var id string
				return other.db.QueryRowContext(
					lockCtx, "SELECT id FROM app_roles WHERE id=$1 FOR UPDATE NOWAIT", *first.AppRoleID,
				).Scan(&id)
			})
			var pgErr *pgconn.PgError
			var mysqlErr *mysql.MySQLError
			locked := errors.As(lockErr, &pgErr) && pgErr.Code == "55P03"
			locked = locked || (errors.As(lockErr, &mysqlErr) && mysqlErr.Number == 3572)
			if !locked {
				t.Fatalf("default was not share-locked: %v", lockErr)
			}
			return signup(ctx)
		}); err != nil {
			t.Fatal(err)
		}
		user, err := f.users.GetByEmail(ctx, "shared-lock@signup.example")
		if err != nil || user == nil || user.AppRoleID == nil || *user.AppRoleID != *first.AppRoleID {
			t.Fatalf("shared signup assignment: %+v %v", user, err)
		}
	})
	for _, action := range []string{"disable", "delete"} {
		t.Run(action+"_before_shared_read", func(t *testing.T) {
			f := newAppFixture(t)
			role := f.role(t, "custom-default")
			f.s.config.DefaultRoleSlug = role.Slug
			other := appSignupSecondPool(t, f)
			reached := make(chan struct{})
			other.s.roles = signupSharedRoleSignal{AppRoleStore: other.repo, reached: reached}
			email := action + "@signup.example"
			signup := appSignupAction(t, other, "password", email)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			if err := f.db.WithTx(ctx, func(txCtx context.Context) error {
				current, err := f.repo.RoleByID(txCtx, role.ID)
				if err != nil {
					return err
				}
				if action == "delete" {
					if err := f.repo.DeleteAppRole(txCtx, role.ID); err != nil {
						return err
					}
				} else {
					current.IsEnabled = false
					if changed, err := f.repo.UpdateAppRole(txCtx, current, current.Revision); err != nil {
						return err
					} else if !changed {
						return domain.ErrAppAuthorizationConflict
					}
				}
				go func() { done <- signup(ctx) }()
				select {
				case <-reached:
					return nil // release the role writer after signup's state read
				case <-ctx.Done():
					return ctx.Err()
				}
			}); err != nil {
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
				}
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if !errors.Is(err, domain.ErrAppRoleNotFound) {
					t.Fatalf("stale default accepted: %v", err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			user, err := f.users.GetByEmail(t.Context(), email)
			if err != nil || user != nil {
				t.Fatalf("invalid default left account: %+v %v", user, err)
			}
		})
	}
}
