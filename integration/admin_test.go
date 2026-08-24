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
