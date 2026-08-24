package integration_test

import (
	"context"
	"testing"
	"time"

	goauth "github.com/nazimdjebloun/go-auth"
	"github.com/nazimdjebloun/go-auth/service"
)

func TestAdmin_ListUsers_DormancyFilters(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()

	admin, err := a.Register(ctx, goauth.RegisterInput{Email: "admin@example.com", Password: "Passw0rd!", Name: "Admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE users SET role = 'admin' WHERE id = ?", admin.User.ID); err != nil {
		t.Fatal(err)
	}

	dormant, err := a.Register(ctx, goauth.RegisterInput{Email: "dormant@example.com", Password: "Passw0rd!", Name: "Dormant"})
	if err != nil {
		t.Fatal(err)
	}
	active, err := a.Register(ctx, goauth.RegisterInput{Email: "active@example.com", Password: "Passw0rd!", Name: "Active"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Register(ctx, goauth.RegisterInput{Email: "never@example.com", Password: "Passw0rd!", Name: "Never"}); err != nil {
		t.Fatal(err)
	}

	cutoff := time.Now().UTC()
	dormantSince := cutoff.Add(-30 * 24 * time.Hour)
	stillActive := cutoff.Add(1 * time.Hour)
	if _, err := db.ExecContext(ctx, "UPDATE users SET last_login_at = ? WHERE id = ?", dormantSince, dormant.User.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE users SET last_login_at = ? WHERE id = ?", stillActive, active.User.ID); err != nil {
		t.Fatal(err)
	}

	// NeverLoggedIn: only "never" (dormant/active both have a last_login_at).
	yes := true
	neverResult, err := a.Services.Admin.ListUsers(ctx, service.AdminListUsersInput{
		ActorID: admin.User.ID, Limit: 10, NeverLoggedIn: &yes,
	})
	if err != nil {
		t.Fatal(err)
	}
	// "never" plus the admin actor itself — neither has ever logged in.
	if neverResult.Total != 2 {
		t.Fatalf("expected 2 never-logged-in users, got %d", neverResult.Total)
	}

	// LastLoginBefore cutoff: only "dormant" (logged in before cutoff) — not
	// "active" (logged in after), not "never" (LastLoginBefore excludes NULLs).
	dormantResult, err := a.Services.Admin.ListUsers(ctx, service.AdminListUsersInput{
		ActorID: admin.User.ID, Limit: 10, LastLoginBefore: &cutoff,
	})
	if err != nil {
		t.Fatal(err)
	}
	if dormantResult.Total != 1 || dormantResult.Users[0].ID != dormant.User.ID {
		t.Fatalf("expected only dormant user, got %+v", dormantResult.Users)
	}
}

func TestAdmin_GetRegistrationTrend(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()

	admin, err := a.Register(ctx, goauth.RegisterInput{Email: "admin2@example.com", Password: "Passw0rd!", Name: "Admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE users SET role = 'admin' WHERE id = ?", admin.User.ID); err != nil {
		t.Fatal(err)
	}

	today := time.Now().UTC()
	twoDaysAgo := today.Add(-48 * time.Hour)
	if _, err := a.Register(ctx, goauth.RegisterInput{Email: "regtrend1@example.com", Password: "Passw0rd!", Name: "One"}); err != nil {
		t.Fatal(err)
	}
	u2, err := a.Register(ctx, goauth.RegisterInput{Email: "regtrend2@example.com", Password: "Passw0rd!", Name: "Two"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE users SET created_at = ? WHERE id = ?", twoDaysAgo, u2.User.ID); err != nil {
		t.Fatal(err)
	}

	counts, err := a.Services.Admin.GetRegistrationTrend(ctx, service.StatsRangeInput{
		ActorID: admin.User.ID,
		From:    twoDaysAgo.Add(-time.Hour),
		To:      today.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != 2 {
		t.Fatalf("expected 2 day buckets (today + two days ago), got %d: %+v", len(counts), counts)
	}
	var total int
	for _, c := range counts {
		total += c.Count
	}
	// admin + u1 + u2 = 3 registrations across the two buckets.
	if total != 3 {
		t.Fatalf("expected 3 total registrations, got %d: %+v", total, counts)
	}
}

func TestAdmin_GetLoginActivity(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()

	admin, err := a.Register(ctx, goauth.RegisterInput{Email: "admin3@example.com", Password: "Passw0rd!", Name: "Admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE users SET role = 'admin' WHERE id = ?", admin.User.ID); err != nil {
		t.Fatal(err)
	}
	u1, err := a.Register(ctx, goauth.RegisterInput{Email: "loginuser@example.com", Password: "Passw0rd!", Name: "LoginUser"})
	if err != nil {
		t.Fatal(err)
	}

	// Register itself only emits user.registered, not login.success — log in
	// explicitly to produce the event this test checks for.
	if _, err := a.Login(ctx, goauth.LoginInput{Email: "loginuser@example.com", Password: "Passw0rd!"}); err != nil {
		t.Fatal(err)
	}
	// Audit events are published asynchronously (AuditServiceConfig's default
	// FlushInterval is 100ms) — wait for the batch to land before querying.
	time.Sleep(200 * time.Millisecond)

	now := time.Now().UTC()
	perUser, err := a.Services.Admin.GetLoginActivity(ctx, service.LoginActivityInput{
		ActorID: admin.User.ID,
		UserID:  &u1.User.ID,
		From:    now.Add(-time.Hour),
		To:      now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	var perUserTotal int
	for _, c := range perUser {
		perUserTotal += c.Count
	}
	if perUserTotal != 1 {
		t.Fatalf("expected 1 login for u1, got %d: %+v", perUserTotal, perUser)
	}

	global, err := a.Services.Admin.GetLoginActivity(ctx, service.LoginActivityInput{
		ActorID: admin.User.ID,
		From:    now.Add(-time.Hour),
		To:      now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	var globalTotal int
	for _, c := range global {
		globalTotal += c.Count
	}
	if globalTotal != 1 {
		t.Fatalf("expected 1 global login, got %d: %+v", globalTotal, global)
	}
}

func TestAdmin_ListSessions_FilterByIP(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()

	admin, err := a.Register(ctx, goauth.RegisterInput{Email: "admin4@example.com", Password: "Passw0rd!", Name: "Admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE users SET role = 'admin' WHERE id = ?", admin.User.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := a.Register(ctx, goauth.RegisterInput{Email: "sessionuser1@example.com", Password: "Passw0rd!", Name: "One"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Register(ctx, goauth.RegisterInput{Email: "sessionuser2@example.com", Password: "Passw0rd!", Name: "Two"}); err != nil {
		t.Fatal(err)
	}

	if _, err := a.Login(ctx, goauth.LoginInput{Email: "sessionuser1@example.com", Password: "Passw0rd!", IP: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Login(ctx, goauth.LoginInput{Email: "sessionuser2@example.com", Password: "Passw0rd!", IP: "10.0.0.2"}); err != nil {
		t.Fatal(err)
	}

	ip := "10.0.0.1"
	result, err := a.Services.Admin.ListSessions(ctx, service.AdminListSessionsInput{
		ActorID: admin.User.ID, IP: &ip,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 || result.Sessions[0].IP != "10.0.0.1" {
		t.Fatalf("expected exactly 1 session from 10.0.0.1, got %+v", result.Sessions)
	}

	// Search substring-matches IP too, same as the IP filter but fuzzy.
	search := "10.0.0.2"
	searched, err := a.Services.Admin.ListSessions(ctx, service.AdminListSessionsInput{
		ActorID: admin.User.ID, Search: &search,
	})
	if err != nil {
		t.Fatal(err)
	}
	if searched.Total != 1 || searched.Sessions[0].IP != "10.0.0.2" {
		t.Fatalf("expected exactly 1 session matching search 10.0.0.2, got %+v", searched.Sessions)
	}
}

func TestAdmin_BulkBanUsers(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()

	admin, err := a.Register(ctx, goauth.RegisterInput{Email: "admin5@example.com", Password: "Passw0rd!", Name: "Admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE users SET role = 'admin' WHERE id = ?", admin.User.ID); err != nil {
		t.Fatal(err)
	}

	u1, err := a.Register(ctx, goauth.RegisterInput{Email: "bulk1@example.com", Password: "Passw0rd!", Name: "One"})
	if err != nil {
		t.Fatal(err)
	}
	u2, err := a.Register(ctx, goauth.RegisterInput{Email: "bulk2@example.com", Password: "Passw0rd!", Name: "Two"})
	if err != nil {
		t.Fatal(err)
	}

	result, err := a.Services.Admin.BulkBanUsers(ctx, service.BulkUserActionInput{
		UserIDs: []string{u1.User.ID, u2.User.ID, "nonexistent"}, ActorID: admin.User.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Succeeded) != 2 {
		t.Fatalf("expected 2 succeeded, got %+v", result.Succeeded)
	}
	if len(result.Failed) != 1 || result.Failed[0].UserID != "nonexistent" {
		t.Fatalf("expected 1 failure for nonexistent, got %+v", result.Failed)
	}

	var isBanned bool
	if err := db.QueryRowContext(ctx, "SELECT is_banned FROM users WHERE id = ?", u1.User.ID).Scan(&isBanned); err != nil {
		t.Fatal(err)
	}
	if !isBanned {
		t.Error("expected u1 to be banned in the database")
	}
}

func TestAdmin_ListAuditLogs_DeviceTypeAndMultiEventType(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()

	admin, err := a.Register(ctx, goauth.RegisterInput{Email: "admin6@example.com", Password: "Passw0rd!", Name: "Admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE users SET role = 'admin' WHERE id = ?", admin.User.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := a.Register(ctx, goauth.RegisterInput{Email: "mobileuser@example.com", Password: "Passw0rd!", Name: "Mobile"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Register(ctx, goauth.RegisterInput{Email: "deskuser@example.com", Password: "Passw0rd!", Name: "Desk"}); err != nil {
		t.Fatal(err)
	}

	mobileUA := "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
	desktopUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	if _, err := a.Login(ctx, goauth.LoginInput{Email: "mobileuser@example.com", Password: "Passw0rd!", UserAgent: mobileUA}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Login(ctx, goauth.LoginInput{Email: "deskuser@example.com", Password: "Passw0rd!", UserAgent: desktopUA}); err != nil {
		t.Fatal(err)
	}
	// Audit events flush asynchronously (AuditServiceConfig's default
	// FlushInterval is 100ms).
	time.Sleep(200 * time.Millisecond)

	deviceType := "mobile"
	result, err := a.Services.Admin.ListAuditLogs(ctx, service.AdminListAuditLogsInput{
		ActorID: admin.User.ID, EventTypes: []string{"login.success"}, DeviceType: &deviceType,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Total != 1 {
		t.Fatalf("expected 1 mobile login.success event, got %d: %+v", result.Total, result.Events)
	}

	// Multi-value event type: registrations (3) + logins (2) in one call,
	// nothing else.
	multi, err := a.Services.Admin.ListAuditLogs(ctx, service.AdminListAuditLogsInput{
		ActorID: admin.User.ID, EventTypes: []string{"user.registered", "login.success"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if multi.Total != 5 {
		t.Fatalf("expected 5 events (3 registrations + 2 logins), got %d: %+v", multi.Total, multi.Events)
	}
}

func TestAdmin_ListAuditLogs_ResolvesActorAndTargetEmails(t *testing.T) {
	db, closeDB := newSQLiteDB(t)
	defer closeDB()
	a := openAuth(t, db, &testMailer{})
	defer a.Close()
	ctx := context.Background()

	admin, err := a.Register(ctx, goauth.RegisterInput{Email: "admin7@example.com", Password: "Passw0rd!", Name: "Admin"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, "UPDATE users SET role = 'admin' WHERE id = ?", admin.User.ID); err != nil {
		t.Fatal(err)
	}
	target, err := a.Register(ctx, goauth.RegisterInput{Email: "bantarget@example.com", Password: "Passw0rd!", Name: "Target"})
	if err != nil {
		t.Fatal(err)
	}

	if err := a.Services.Admin.BanUser(ctx, service.BanUserInput{UserID: target.User.ID, ActorID: admin.User.ID}); err != nil {
		t.Fatal(err)
	}
	// Audit events flush asynchronously (AuditServiceConfig's default
	// FlushInterval is 100ms).
	time.Sleep(200 * time.Millisecond)

	bannedType := "admin.user.banned"
	result, err := a.Services.Admin.ListAuditLogs(ctx, service.AdminListAuditLogsInput{
		ActorID: admin.User.ID, EventTypes: []string{bannedType},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 admin.user.banned event, got %d: %+v", len(result.Events), result.Events)
	}
	if result.Events[0].TargetEmail == nil || *result.Events[0].TargetEmail != "bantarget@example.com" {
		t.Fatalf("expected TargetEmail bantarget@example.com, got %+v", result.Events[0].TargetEmail)
	}
}
