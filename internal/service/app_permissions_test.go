package service

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nazimdjebloun/go-auth/api"
	"github.com/nazimdjebloun/go-auth/audit"
	"github.com/nazimdjebloun/go-auth/domain"
	"github.com/nazimdjebloun/go-auth/internal/sqlstore"
	"github.com/nazimdjebloun/go-auth/internal/testdb"
	"github.com/nazimdjebloun/go-auth/internal/testutil"
	"github.com/nazimdjebloun/go-auth/port"
	"github.com/nazimdjebloun/go-auth/token"
)

type appFixture struct {
	s     *AppPermissionsService
	db    *sqlstore.DB
	users port.UserRepository
	repo  *sqlstore.AppPermissionsRepository
	admin api.AppPermissionActor
}

func TestAppPermissionsOAuthCreationAndMissingDefaultRollback(t *testing.T) {
	f := newAppFixture(t)
	tokens := sqlstore.NewTokenRepository(f.db)
	links := sqlstore.NewProviderAccountRepository(f.db)
	sessions := NewSessionService(f.db, sqlstore.NewSessionRepository(f.db), token.New(), DefaultSessionConfig())
	provider := &stubOAuthProvider{name: "test", profile: oauthTestProfile("test", "first", "oauth-app@example.com")}
	s := NewOAuthService(map[string]port.OAuthProvider{"test": provider}, links, f.users, tokens, &testutil.MockHasher{}, token.New(), sessions, nil, f.db, OAuthServiceConfig{EnableOAuth: true, DisableAdminTwoFactor: true, AppPermissions: f.s})
	callback := func(raw string) (*api.OAuthCallbackResult, error) {
		t.Helper()
		verifier := "verifier"
		now := time.Now().UTC()
		if err := tokens.Create(t.Context(), &domain.VerificationToken{ID: uuid.NewString(), TokenHash: hashToken(raw), Type: domain.TokenOAuthState, ExpiresAt: now.Add(time.Minute), CodeVerifier: &verifier, CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		return s.Callback(t.Context(), api.OAuthCallbackInput{Provider: "test", Code: "code", State: raw, BrowserState: raw})
	}
	result, err := callback("first-state")
	if err != nil || !result.IsNewUser || result.SessionToken == "" {
		t.Fatalf("OAuth creation: %+v %v", result, err)
	}
	user, err := f.users.GetByEmail(t.Context(), provider.profile.Email)
	if err != nil || user == nil || user.AppRoleID == nil || user.AppRoleAssignmentRevision != 1 {
		t.Fatalf("OAuth assignment: %+v %v", user, err)
	}
	baseline, err := f.repo.RoleBySlug(t.Context(), "user")
	if err != nil || *user.AppRoleID != baseline.ID {
		t.Fatalf("OAuth baseline: %+v %v", baseline, err)
	}
	f.s.config.DefaultRoleSlug = "missing-default"
	provider.profile = oauthTestProfile("test", "second", "failed-oauth-app@example.com")
	if _, err := callback("second-state"); !errors.Is(err, domain.ErrAppRoleNotFound) {
		t.Fatalf("missing default: %v", err)
	}
	if u, err := f.users.GetByEmail(t.Context(), provider.profile.Email); err != nil || u != nil {
		t.Fatalf("failed OAuth left account: %+v %v", u, err)
	}
	if link, err := links.GetByProvider(t.Context(), "test", "second"); err != nil || link != nil {
		t.Fatalf("failed OAuth left provider link: %+v %v", link, err)
	}
}

func TestAppPermissionsInviteCreationAndMissingDefaultRollback(t *testing.T) {
	f := newAppFixture(t)
	invites := sqlstore.NewInviteRepository(f.db)
	sessionRepo := sqlstore.NewSessionRepository(f.db)
	sessions := NewSessionService(f.db, sessionRepo, token.New(), DefaultSessionConfig())
	cfg := defaultTestConfig()
	cfg.EnableInvite, cfg.AppPermissions = true, f.s
	s := NewInviteService(f.users, sessionRepo, invites, &testutil.MockHasher{}, token.New(), nil, f.db, cfg, sessions, nil)
	complete := func(raw, email string) (*api.CompleteInviteResult, string, error) {
		t.Helper()
		now := time.Now().UTC()
		id := uuid.NewString()
		if err := invites.Create(t.Context(), &domain.Invite{ID: id, Email: email, Code: hashToken(raw), Status: domain.InvitePending, CreatedBy: f.admin.UserID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		result, err := s.CompleteInviteRegistration(t.Context(), api.CompleteInviteInput{Code: raw, Name: "Invited", Password: "Passw0rd!", ConfirmPassword: "Passw0rd!"})
		return result, id, err
	}
	result, _, err := complete("invite-first", "invite-app@example.com")
	if err != nil || result.User.AppRoleID == nil || result.User.AppRoleAssignmentRevision != 1 || result.SessionToken == "" {
		t.Fatalf("invite assignment: %+v %v", result, err)
	}
	f.s.config.DefaultRoleSlug = "missing-default"
	_, id, err := complete("invite-second", "failed-invite-app@example.com")
	if !errors.Is(err, domain.ErrAppRoleNotFound) {
		t.Fatalf("missing default: %v", err)
	}
	invite, err := invites.GetByID(t.Context(), id)
	if err != nil || invite == nil || invite.Status != domain.InvitePending {
		t.Fatalf("failed assignment consumed invite: %+v %v", invite, err)
	}
	if u, err := f.users.GetByEmail(t.Context(), "failed-invite-app@example.com"); err != nil || u != nil {
		t.Fatalf("failed invite left account: %+v %v", u, err)
	}
}

func TestAppPermissionsOrganizationOversightUsesProtectedIdentity(t *testing.T) {
	f := newAppFixture(t)
	owner := f.account(t)
	s := NewOrgService(sqlstore.NewOrgRepository(f.db), f.users, sqlstore.NewSessionRepository(f.db), f.db, OrgServiceConfig{AppPermissions: f.s})
	org, err := s.CreateOrg(t.Context(), api.CreateOrgInput{OwnerID: owner.UserID, Name: "Owned", Slug: "owned"})
	if err != nil {
		t.Fatal(err)
	}
	// Neither org ownership nor a stale legacy admin column grants platform access.
	if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET role='admin' WHERE id=$1", owner.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdminListOrgs(t.Context(), api.AdminListOrgsInput{ActorID: owner.UserID}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("legacy admin bypassed platform oversight: %v", err)
	}
	if err := s.AdminDeleteOrg(t.Context(), api.AdminOrgActionInput{ActorID: owner.UserID, OrgID: org.ID}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("owner bypassed protected mutation: %v", err)
	}
	if _, err := f.db.ExecContext(t.Context(), "UPDATE users SET role='user' WHERE id=$1", f.admin.UserID); err != nil {
		t.Fatal(err)
	}
	if err := s.AdminDeleteOrg(t.Context(), api.AdminOrgActionInput{ActorID: f.admin.UserID, OrgID: org.ID}); err != nil {
		t.Fatal("protected admin could not delete organization", err)
	}
}

func newAppFixture(t *testing.T) appFixture {
	t.Helper()
	raw := testdb.OpenSelected(t)
	testdb.Apply(t, raw)
	db := sqlstore.NewDB(raw, testdb.Driver(raw))
	users := sqlstore.NewUserRepository(db).WithAppPermissions()
	repo := sqlstore.NewAppPermissionsRepository(db)
	sessions := sqlstore.NewSessionRepository(db)
	sessionSvc := NewSessionService(db, sessions, token.New(), DefaultSessionConfig())
	s := NewAppPermissionsService(db, users, sessions, sessionSvc, repo, repo, repo, repo, AppPermissionsServiceConfig{})
	now := time.Now().UTC()
	id := uuid.NewString()
	if err := users.Create(t.Context(), &domain.User{ID: id, Email: id + "@example.com", Role: domain.RoleAdmin, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.Initialize(t.Context(), api.InitializeAppPermissionsInput{AdministratorUserID: id}); err != nil {
		t.Fatal(err)
	}
	return appFixture{s: s, db: db, users: users, repo: repo, admin: api.AppPermissionActor{UserID: id}}
}

func (f appFixture) account(t *testing.T) api.AppPermissionActor {
	t.Helper()
	now := time.Now().UTC()
	id := uuid.NewString()
	u := &domain.User{ID: id, Email: id + "@example.com", Role: domain.RoleUser, CreatedAt: now, UpdatedAt: now}
	if err := f.db.WithTx(t.Context(), func(ctx context.Context) error {
		if err := f.users.Create(ctx, u); err != nil {
			return err
		}
		return f.s.AssignBaseline(ctx, u)
	}); err != nil {
		t.Fatal(err)
	}
	return api.AppPermissionActor{UserID: id}
}

func (f appFixture) install(t *testing.T, keys ...string) {
	t.Helper()
	if _, err := f.s.UpdateLibraryPermissions(t.Context(), api.UpdateAppLibraryPermissionsInput{Actor: f.admin, Create: keys}); err != nil {
		t.Fatal(err)
	}
}

func (f appFixture) role(t *testing.T, slug string, keys ...string) *domain.AppRole {
	t.Helper()
	r, err := f.s.CreateRole(t.Context(), api.CreateAppRoleInput{Actor: f.admin, Slug: slug, Name: slug, PermissionKeys: keys})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f appFixture) assign(t *testing.T, actor api.AppPermissionActor, role *domain.AppRole) {
	t.Helper()
	u, err := f.users.GetByID(t.Context(), actor.UserID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.SetUserRole(t.Context(), api.SetAppUserRoleInput{Actor: f.admin, UserID: actor.UserID, RoleID: role.ID, ExpectedRoleRevision: role.Revision, ExpectedAssignmentRevision: u.AppRoleAssignmentRevision}); err != nil {
		t.Fatal(err)
	}
}

func (f appFixture) allowed(t *testing.T, actor api.AppPermissionActor, key string, want bool) {
	t.Helper()
	d, err := f.s.CheckPermission(t.Context(), api.CheckAppPermissionInput{Actor: actor, PermissionKey: key})
	if err != nil {
		t.Fatal(err)
	}
	if d.Allowed != want {
		t.Fatalf("%s allowed=%v, want %v", key, d.Allowed, want)
	}
}

func TestAppLibraryInstallationRevocationAndRetry(t *testing.T) {
	f := newAppFixture(t)
	ctx := t.Context()
	actor := f.account(t)
	key := "goauth.app.sessions.revoke"
	installed, err := f.repo.ListAppPermissions(ctx, 100, 0)
	if err != nil || len(installed) != 0 {
		t.Fatalf("implicit seeding: %v %v", installed, err)
	}
	f.allowed(t, f.admin, key, true)
	f.allowed(t, actor, key, false)
	f.allowed(t, f.admin, "goauth.app.sessions.unknown", false)
	f.install(t, key)
	role := f.role(t, "revoker", key)
	f.assign(t, actor, role)
	f.allowed(t, actor, key, true)
	before, err := f.repo.AppStateRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.s.UpdateLibraryPermissions(ctx, api.UpdateAppLibraryPermissionsInput{Actor: f.admin, Create: []string{key}})
	if err != nil || !slices.Equal(result.Unchanged, []string{key}) {
		t.Fatalf("retry: %+v %v", result, err)
	}
	after, _ := f.repo.AppStateRevision(ctx)
	if before != after {
		t.Fatal("no-op seed changed revision")
	}
	f.allowed(t, actor, key, true)
	if _, err := f.s.UpdateLibraryPermissions(ctx, api.UpdateAppLibraryPermissionsInput{Actor: f.admin, Delete: []string{key}, Create: []string{"goauth.app.sessions.read"}}); err != nil {
		t.Fatal(err)
	}
	f.allowed(t, actor, key, false)
	f.allowed(t, f.admin, key, true)
	updated, err := f.repo.RoleByID(ctx, role.ID)
	if err != nil || updated.Revision != role.Revision+1 {
		t.Fatalf("cleanup revision: %+v %v", updated, err)
	}
	f.install(t, key)
	f.allowed(t, actor, key, false)
	if err := f.s.Initialize(ctx, api.InitializeAppPermissionsInput{AdministratorUserID: f.admin.UserID}); !errors.Is(err, domain.ErrAppPermissionsInitialized) {
		t.Fatalf("repeat initialization: %v", err)
	}
}

type appBlockingAudit struct{}

func (appBlockingAudit) Record(context.Context, audit.Event) error {
	return errors.New("durable record blocked")
}

func TestAppLibraryBatchRollbackAndOwnership(t *testing.T) {
	f := newAppFixture(t)
	ctx := t.Context()
	old := "goauth.app.sessions.revoke"
	newKey := "goauth.app.sessions.read"
	f.install(t, old)
	role := f.role(t, "revoker", old)
	f.s.config.Audit = appBlockingAudit{}
	if _, err := f.s.UpdateLibraryPermissions(ctx, api.UpdateAppLibraryPermissionsInput{Actor: f.admin, Create: []string{newKey}, Delete: []string{old}}); err == nil {
		t.Fatal("audit failure did not abort batch")
	}
	f.s.config.Audit = nil
	p, err := f.repo.PermissionByKey(ctx, newKey)
	if err != nil || p != nil {
		t.Fatalf("partial create survived: %+v %v", p, err)
	}
	p, err = f.repo.PermissionByKey(ctx, old)
	if err != nil || p == nil {
		t.Fatal("partial deletion survived")
	}
	keys, err := f.repo.RoleGrantKeys(ctx, role.ID)
	if err != nil || !slices.Equal(keys, []string{old}) {
		t.Fatalf("cleanup survived rollback: %v %v", keys, err)
	}
	for _, input := range []api.UpdateAppLibraryPermissionsInput{
		{Actor: f.admin, Create: []string{newKey, "goauth.app.unknown.action"}},
		{Actor: f.admin, Create: []string{newKey}, Delete: []string{newKey}},
		{Actor: f.admin, Create: []string{"app.posts.delete"}},
	} {
		if _, err := f.s.UpdateLibraryPermissions(ctx, input); err == nil {
			t.Fatal("invalid batch accepted")
		}
	}
	if _, err := f.s.UpdatePermission(ctx, api.UpdateAppPermissionInput{Actor: f.admin, PermissionID: p.ID, ExpectedRevision: p.Revision, Name: new(string)}); !errors.Is(err, domain.ErrProtectedAppPermission) {
		t.Fatalf("system metadata edit: %v", err)
	}
}

func TestAppRoleDelegationAndSingleAssignment(t *testing.T) {
	f := newAppFixture(t)
	ctx := t.Context()
	f.install(t, "goauth.app.roles.create", "goauth.app.roles.update", "goauth.app.roles.assign", "goauth.app.sessions.revoke")
	manager := f.account(t)
	role := f.role(t, "manager", "goauth.app.roles.create", "goauth.app.roles.update", "goauth.app.roles.assign")
	f.assign(t, manager, role)
	if _, err := f.s.CreateRole(ctx, api.CreateAppRoleInput{Actor: manager, Slug: "escalated", Name: "Escalated", PermissionKeys: []string{"goauth.app.sessions.revoke"}}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("overgrant accepted: %v", err)
	}
	if _, err := f.s.SetRolePermissions(ctx, api.SetAppRolePermissionsInput{Actor: manager, RoleID: role.ID, ExpectedRevision: role.Revision}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("self edit accepted: %v", err)
	}
	if _, err := f.s.UpdateLibraryPermissions(ctx, api.UpdateAppLibraryPermissionsInput{Actor: manager, Delete: []string{"goauth.app.roles.create"}}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("delegated provisioning accepted: %v", err)
	}
	actor := f.account(t)
	revoker := f.role(t, "revoker", "goauth.app.sessions.revoke")
	f.assign(t, actor, revoker)
	f.allowed(t, actor, "goauth.app.sessions.revoke", true)
	base, err := f.repo.RoleBySlug(ctx, "user")
	if err != nil {
		t.Fatal(err)
	}
	f.assign(t, actor, base)
	f.allowed(t, actor, "goauth.app.sessions.revoke", false)
	if _, err := f.s.SetUserRole(ctx, api.SetAppUserRoleInput{Actor: f.admin, UserID: actor.UserID, RoleID: revoker.ID, ExpectedRoleRevision: revoker.Revision, ExpectedAssignmentRevision: 1}); !errors.Is(err, domain.ErrAppAuthorizationConflict) {
		t.Fatalf("stale assignment accepted: %v", err)
	}
	root, _ := f.users.GetByID(ctx, f.admin.UserID)
	if _, err := f.s.SetUserRole(ctx, api.SetAppUserRoleInput{Actor: f.admin, UserID: root.ID, RoleID: base.ID, ExpectedRoleRevision: base.Revision, ExpectedAssignmentRevision: root.AppRoleAssignmentRevision}); !errors.Is(err, domain.ErrCannotDeleteLastAdmin) {
		t.Fatalf("last admin demoted: %v", err)
	}
}

func TestAppBusinessDeletionDeniesAndGrantCleanupRestricts(t *testing.T) {
	f := newAppFixture(t)
	ctx := t.Context()
	p, err := f.s.CreatePermission(ctx, api.CreateAppPermissionInput{Actor: f.admin, Key: "app.posts.delete", Name: "Delete posts"})
	if err != nil {
		t.Fatal(err)
	}
	f.allowed(t, f.admin, p.Key, true)
	role := f.role(t, "editor", p.Key)
	if err := f.s.DeletePermission(ctx, api.DeleteAppPermissionInput{Actor: f.admin, PermissionID: p.ID, ExpectedRevision: p.Revision}); !errors.Is(err, domain.ErrAppPermissionInUse) {
		t.Fatalf("referenced definition deleted: %v", err)
	}
	if _, err := f.s.SetRolePermissions(ctx, api.SetAppRolePermissionsInput{Actor: f.admin, RoleID: role.ID, ExpectedRevision: role.Revision}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.DeletePermission(ctx, api.DeleteAppPermissionInput{Actor: f.admin, PermissionID: p.ID, ExpectedRevision: p.Revision}); err != nil {
		t.Fatal(err)
	}
	f.allowed(t, f.admin, p.Key, false)
}

func TestAppConcurrentRoleReplacementHasOneWinner(t *testing.T) {
	f := newAppFixture(t)
	other := appSecondPool(t, f)
	actor := f.account(t)
	r := f.role(t, "operator")
	u, _ := f.users.GetByID(t.Context(), actor.UserID)
	input := api.SetAppUserRoleInput{Actor: f.admin, UserID: actor.UserID, RoleID: r.ID, ExpectedRoleRevision: r.Revision, ExpectedAssignmentRevision: u.AppRoleAssignmentRevision}
	results := make(chan error, 2)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, service := range []*AppPermissionsService{f.s, other.s} {
		wg.Add(1)
		go func() { defer wg.Done(); <-start; _, err := service.SetUserRole(t.Context(), input); results <- err }()
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, domain.ErrAppAuthorizationConflict) {
			t.Fatalf("replacement failed without a revision conflict: %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("got %d successful stale replacements", winners)
	}
}

func TestAppBusinessDisableCannotBeReenabledByDelegate(t *testing.T) {
	f := newAppFixture(t)
	ctx := t.Context()
	f.install(t, "goauth.app.permissions.update")
	p, err := f.s.CreatePermission(ctx, api.CreateAppPermissionInput{Actor: f.admin, Key: "app.posts.delete", Name: "Delete posts"})
	if err != nil {
		t.Fatal(err)
	}
	r := f.role(t, "editor", p.Key, "goauth.app.permissions.update")
	actor := f.account(t)
	f.assign(t, actor, r)
	disabled := false
	p, err = f.s.UpdatePermission(ctx, api.UpdateAppPermissionInput{Actor: f.admin, PermissionID: p.ID, ExpectedRevision: p.Revision, IsEnabled: &disabled})
	if err != nil {
		t.Fatal(err)
	}
	f.allowed(t, actor, p.Key, false)
	f.allowed(t, f.admin, p.Key, false)
	enabled := true
	if _, err := f.s.UpdatePermission(ctx, api.UpdateAppPermissionInput{Actor: actor, PermissionID: p.ID, ExpectedRevision: p.Revision, IsEnabled: &enabled}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("delegate regained disabled access: %v", err)
	}
	if _, err := f.s.UpdatePermission(ctx, api.UpdateAppPermissionInput{Actor: f.admin, PermissionID: p.ID, ExpectedRevision: p.Revision, IsEnabled: &enabled}); err != nil {
		t.Fatal(err)
	}
	f.allowed(t, actor, p.Key, true)
}

func TestAppProtectedRolesAndDefaultCannotBeChanged(t *testing.T) {
	f := newAppFixture(t)
	ctx := t.Context()
	disabled := false
	for _, slug := range []string{"user", "admin"} {
		t.Run(slug, func(t *testing.T) {
			r, err := f.repo.RoleBySlug(ctx, slug)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.s.UpdateRole(ctx, api.UpdateAppRoleInput{Actor: f.admin, RoleID: r.ID, ExpectedRevision: r.Revision, IsEnabled: &disabled}); !errors.Is(err, domain.ErrProtectedAppRole) {
				t.Fatalf("protected role updated: %v", err)
			}
			if _, err := f.s.SetRolePermissions(ctx, api.SetAppRolePermissionsInput{Actor: f.admin, RoleID: r.ID, ExpectedRevision: r.Revision}); !errors.Is(err, domain.ErrProtectedAppRole) {
				t.Fatalf("protected grants updated: %v", err)
			}
			if err := f.s.DeleteRole(ctx, api.DeleteAppRoleInput{Actor: f.admin, RoleID: r.ID, ExpectedRevision: r.Revision}); !errors.Is(err, domain.ErrProtectedAppRole) {
				t.Fatalf("protected role deleted: %v", err)
			}
		})
	}
	r := f.role(t, "default")
	f.s.config.DefaultRoleSlug = r.Slug
	if _, err := f.s.UpdateRole(ctx, api.UpdateAppRoleInput{Actor: f.admin, RoleID: r.ID, ExpectedRevision: r.Revision, IsEnabled: &disabled}); !errors.Is(err, domain.ErrAppRoleInUse) {
		t.Fatalf("default disabled: %v", err)
	}
	if err := f.s.DeleteRole(ctx, api.DeleteAppRoleInput{Actor: f.admin, RoleID: r.ID, ExpectedRevision: r.Revision}); !errors.Is(err, domain.ErrAppRoleInUse) {
		t.Fatalf("default deleted: %v", err)
	}
}

func TestAppConcurrentGrantReplacementAndDeletionCannotRestoreAccess(t *testing.T) {
	f := newAppFixture(t)
	other := appSecondPool(t, f)
	ctx := t.Context()
	key := "goauth.app.sessions.revoke"
	f.install(t, key)
	r := f.role(t, "operator", key)
	actor := f.account(t)
	f.assign(t, actor, r)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, err := f.s.SetRolePermissions(ctx, api.SetAppRolePermissionsInput{Actor: f.admin, RoleID: r.ID, ExpectedRevision: r.Revision, PermissionKeys: []string{key}})
		results <- err
	}()
	go func() {
		defer wg.Done()
		<-start
		_, err := other.s.UpdateLibraryPermissions(ctx, api.UpdateAppLibraryPermissionsInput{Actor: f.admin, Delete: []string{key}})
		results <- err
	}()
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil && !errors.Is(err, domain.ErrAppAuthorizationConflict) && !errors.Is(err, domain.ErrAppPermissionNotFound) {
			t.Fatal(err)
		}
	}
	f.allowed(t, actor, key, false)
	keys, err := f.repo.RoleGrantKeys(ctx, r.ID)
	if err != nil || len(keys) != 0 {
		t.Fatalf("stale grants survived: %v %v", keys, err)
	}
}
